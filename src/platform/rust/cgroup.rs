// SPDX-License-Identifier: LGPL-2.1-or-later

use std::env;
use std::fs;
use std::io::{self, Write};
use std::os::fd::RawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};

/// Bitmask of supported cgroup controllers.
pub type CGroupMask = u64;

/// Supported cgroup v2 controllers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CgroupController {
    Cpu = 0,
    Cpuset = 1,
    Io = 2,
    Memory = 3,
    Pids = 4,
    Rdma = 5,
    Freezer = 6,
}

impl CgroupController {
    /// Maximum number of controller slots.
    pub const MAX: usize = 7;

    /// Return the filesystem controller name.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Cpu => "cpu",
            Self::Cpuset => "cpuset",
            Self::Io => "io",
            Self::Memory => "memory",
            Self::Pids => "pids",
            Self::Rdma => "rdma",
            Self::Freezer => "freezer",
        }
    }

    /// Bitmask for this controller.
    pub const fn mask(self) -> CGroupMask {
        1u64 << (self as u64)
    }

    /// Convert an index to a controller slot.
    pub const fn from_index(index: usize) -> Option<Self> {
        match index {
            0 => Some(Self::Cpu),
            1 => Some(Self::Cpuset),
            2 => Some(Self::Io),
            3 => Some(Self::Memory),
            4 => Some(Self::Pids),
            5 => Some(Self::Rdma),
            6 => Some(Self::Freezer),
            _ => None,
        }
    }

    /// Convert a controller name to an enum variant.
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "cpu" => Some(Self::Cpu),
            "cpuset" => Some(Self::Cpuset),
            "io" => Some(Self::Io),
            "memory" => Some(Self::Memory),
            "pids" => Some(Self::Pids),
            "rdma" => Some(Self::Rdma),
            "freezer" => Some(Self::Freezer),
            _ => None,
        }
    }
}

const DEFAULT_CGROUP_ROOT: &str = "/sys/fs/cgroup";
const SYSTEMD_CGROUP_ROOT: &str = "SYSTEMD_CGROUP_ROOT";

const CGROUP_V2_MASK: CGroupMask = CgroupController::Cpu.mask()
    | CgroupController::Cpuset.mask()
    | CgroupController::Io.mask()
    | CgroupController::Memory.mask()
    | CgroupController::Pids.mask()
    | CgroupController::Rdma.mask();

const CGROUP_CONTROLLERS: [CgroupController; 7] = [
    CgroupController::Cpu,
    CgroupController::Cpuset,
    CgroupController::Io,
    CgroupController::Memory,
    CgroupController::Pids,
    CgroupController::Rdma,
    CgroupController::Freezer,
];

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct CGroupFlags: u32 {
        const IGNORE_SELF = 1 << 0;
        const REMOVE = 1 << 1;
    }
}

pub const UID_INVALID: u32 = u32::MAX;
pub const GID_INVALID: u32 = u32::MAX;

fn invalid_input(msg: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, msg)
}

fn invalid_data(msg: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

fn cgroup_root() -> io::Result<PathBuf> {
    let root = env::var_os(SYSTEMD_CGROUP_ROOT)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_CGROUP_ROOT));

    fs::canonicalize(root)
}

fn normalize_components(path: &str) -> io::Result<Vec<String>> {
    if path.contains('\0') {
        return Err(invalid_input("path contains NUL"));
    }

    let mut components = Vec::new();

    for component in Path::new(path).components() {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::ParentDir => return Err(invalid_input("path may not contain ..")),
            Component::Normal(part) => {
                let part = part
                    .to_str()
                    .ok_or_else(|| invalid_data("path is not valid UTF-8"))?;
                if part.is_empty() {
                    continue;
                }
                if part == "." || part == ".." {
                    return Err(invalid_input("path may not contain traversal segments"));
                }
                components.push(part.to_owned());
            }
            _ => return Err(invalid_input("unsupported path component")),
        }
    }

    Ok(components)
}

fn normalize_cgroup_path(path: &str) -> io::Result<String> {
    let components = normalize_components(path)?;
    if components.is_empty() {
        return Ok("/".to_string());
    }

    Ok(format!("/{}", components.join("/")))
}

fn build_cgroup_path(path: &str, suffix: Option<&str>) -> io::Result<PathBuf> {
    let mut full = cgroup_root()?;

    for component in normalize_components(path)? {
        full.push(component);
    }

    if let Some(suffix) = suffix
        && !suffix.is_empty()
    {
        for component in normalize_components(suffix)? {
            full.push(component);
        }
    }

    Ok(full)
}

fn parse_proc_cgroup(content: &str) -> io::Result<String> {
    for line in content.lines() {
        if line.is_empty() {
            continue;
        }

        let Some(path) = line.strip_prefix("0::") else {
            continue;
        };

        let path = path.strip_suffix(" (deleted)").unwrap_or(path);
        return normalize_cgroup_path(path);
    }

    Err(invalid_data("no unified cgroup entry found"))
}

fn parse_cgroup_controllers(content: &str) -> CGroupMask {
    let mut mask = 0;

    for name in content.split_whitespace() {
        if let Some(controller) = CgroupController::from_name(name) {
            mask |= controller.mask();
        }
    }

    mask & CGROUP_V2_MASK
}

fn cg_enable_actions(supported: CGroupMask, mask: CGroupMask) -> (Vec<String>, CGroupMask) {
    let mut actions = Vec::new();
    let mut result_mask = 0;

    for controller in CGROUP_CONTROLLERS {
        let bit = controller.mask();
        if bit & CGROUP_V2_MASK == 0 || bit & supported == 0 {
            continue;
        }

        let enabled = mask & bit != 0;
        let prefix = if enabled { '+' } else { '-' };
        actions.push(format!("{prefix}{}", controller.as_str()));

        if enabled {
            result_mask |= bit;
        }
    }

    (actions, result_mask)
}

fn chown_path(path: &Path, uid: u32, gid: u32) -> io::Result<()> {
    if uid == UID_INVALID && gid == GID_INVALID {
        return Ok(());
    }

    let c_path = std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| invalid_input("path contains interior NUL"))?;
    let uid_t = if uid == UID_INVALID {
        !0 as libc::uid_t
    } else {
        uid as libc::uid_t
    };
    let gid_t = if gid == GID_INVALID {
        !0 as libc::gid_t
    } else {
        gid as libc::gid_t
    };

    // SAFETY: c_path is a valid, NUL-terminated C string.
    let rc = unsafe { libc::chown(c_path.as_ptr(), uid_t, gid_t) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn chmod_path(path: &Path, mode: u32) -> io::Result<()> {
    let mut perms = fs::metadata(path)?.permissions();
    perms.set_mode(mode);
    fs::set_permissions(path, perms)
}

fn apply_access(path: &Path, uid: u32, gid: u32) -> io::Result<()> {
    chown_path(path, uid, gid)?;
    if path.is_dir() {
        chmod_path(path, 0o755)?;
    } else {
        chmod_path(path, 0o644)?;
    }
    Ok(())
}

fn trim_inner(path: &Path) -> io::Result<()> {
    let Ok(entries) = fs::read_dir(path) else {
        return Ok(());
    };

    for entry in entries.flatten() {
        let child = entry.path();
        if child.is_dir() {
            let _ = trim_inner(&child);
            let _ = fs::remove_dir(&child);
        }
    }

    Ok(())
}

/// Read the cgroup path for a given process from `/proc/{pid}/cgroup`.
///
/// Returns the unified-hierarchy path (for example `/user.slice`).
pub fn cg_pid_get_path(pid: i32) -> io::Result<String> {
    if pid <= 0 {
        return Err(invalid_input("pid must be positive"));
    }

    let path = Path::new("/proc").join(pid.to_string()).join("cgroup");
    let content = fs::read_to_string(path)?;
    parse_proc_cgroup(&content)
}

/// Backward-compatible wrapper that returns the path without a leading slash.
pub fn cgroup_path(pid: i32) -> io::Result<String> {
    cg_pid_get_path(pid).map(|path| path.trim_start_matches('/').to_string())
}

/// Resolve a cgroup path relative to the configured cgroup root.
pub fn cg_get_path(path: &str, suffix: Option<&str>) -> io::Result<PathBuf> {
    build_cgroup_path(path, suffix)
}

/// Create a cgroup directory.
///
/// Returns `true` if the directory was newly created.
pub fn cg_create(path: &str) -> io::Result<bool> {
    let dir = cg_get_path(path, None)?;
    let existed = dir.exists();
    fs::create_dir_all(&dir)?;
    Ok(!existed)
}

/// Attach a PID to the cgroup's `cgroup.procs`.
pub fn cg_attach(path: &str, pid: i32) -> io::Result<()> {
    let pid = if pid == 0 {
        std::process::id() as i32
    } else if pid > 0 {
        pid
    } else {
        return Err(invalid_input("pid must not be negative"));
    };

    let file = cg_get_path(path, Some("cgroup.procs"))?;
    let mut file = fs::OpenOptions::new().append(true).open(file)?;
    file.write_all(format!("{pid}\n").as_bytes())
}

/// Create a cgroup and then attach a PID to it.
///
/// Returns `true` if the cgroup was newly created.
pub fn cg_create_and_attach(path: &str, pid: i32) -> io::Result<bool> {
    let created = cg_create(path)?;
    cg_attach(path, pid)?;
    Ok(created)
}

/// Parse supported controllers from `cgroup.controllers`.
pub fn cg_mask_supported_subtree(path: &str) -> io::Result<CGroupMask> {
    let controllers = fs::read_to_string(cg_get_path(path, Some("cgroup.controllers"))?)?;
    Ok(parse_cgroup_controllers(&controllers))
}

/// Return the supported controller mask for the cgroup root.
pub fn cg_mask_supported() -> io::Result<CGroupMask> {
    cg_mask_supported_subtree("/")
}

/// Enable the requested controllers in `cgroup.subtree_control`.
///
/// Returns the mask of controllers that were selected for enabling.
pub fn cg_enable(supported: CGroupMask, mask: CGroupMask, path: &str) -> io::Result<CGroupMask> {
    if supported == 0 {
        return Ok(0);
    }

    let (actions, result_mask) = cg_enable_actions(supported, mask);
    if actions.is_empty() {
        return Ok(0);
    }

    let file = cg_get_path(path, Some("cgroup.subtree_control"))?;
    let mut payload = actions.join("\n");
    payload.push('\n');
    fs::write(file, payload)?;

    Ok(result_mask)
}

/// Set owner and basic mode for a delegated cgroup path and key control files.
pub fn cg_set_access(path: &str, uid: u32, gid: u32) -> io::Result<()> {
    let root = cg_get_path(path, None)?;
    apply_access(&root, uid, gid)?;

    for key in [
        "cgroup.procs",
        "cgroup.subtree_control",
        "cgroup.threads",
        "memory.oom.group",
        "memory.reclaim",
    ] {
        let file = root.join(key);
        if file.exists() {
            apply_access(&file, uid, gid)?;
        }
    }

    Ok(())
}

/// Recursively set ownership/mode for all files and directories below a cgroup path.
pub fn cg_set_access_recursive(path: &str, uid: u32, gid: u32) -> io::Result<()> {
    fn recurse(path: &Path, uid: u32, gid: u32) -> io::Result<()> {
        apply_access(path, uid, gid)?;
        if path.is_dir() {
            for entry in fs::read_dir(path)? {
                recurse(&entry?.path(), uid, gid)?;
            }
        }
        Ok(())
    }

    let root = cg_get_path(path, None)?;
    recurse(&root, uid, gid)
}

/// Heuristic check whether a cgroup appears delegated to a non-root owner.
pub fn cg_is_delegated(path: &str) -> io::Result<bool> {
    let root = cg_get_path(path, None)?;
    let md = fs::metadata(&root)?;
    let uid = md.uid();
    if uid == 0 {
        return Ok(false);
    }

    for key in ["cgroup.procs", "cgroup.subtree_control"] {
        let file = root.join(key);
        if let Ok(md) = fs::metadata(file)
            && md.uid() != uid
        {
            return Ok(false);
        }
    }

    Ok(true)
}

/// Heuristic check whether an opened cgroup directory fd appears delegated.
pub fn cg_is_delegated_fd(fd: RawFd) -> io::Result<bool> {
    let mut st = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: st points to valid uninitialized memory and fstat initializes it on success.
    let rc = unsafe { libc::fstat(fd, st.as_mut_ptr()) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fstat succeeded and initialized st.
    let st = unsafe { st.assume_init() };
    Ok(st.st_uid != 0)
}

/// Check coredump receive knob on a cgroup when present.
pub fn cg_has_coredump_receive(path: &str) -> io::Result<bool> {
    let knob = cg_get_path(path, Some("coredump.receive"))?;
    if !knob.exists() {
        return Ok(false);
    }
    let value = fs::read_to_string(knob)?;
    Ok(matches!(value.trim(), "1" | "yes" | "true" | "on"))
}

/// Move processes from one cgroup to another.
///
/// Returns `true` when at least one process is migrated.
pub fn cg_migrate(from: &str, to: &str, flags: CGroupFlags) -> io::Result<bool> {
    let from_file = cg_get_path(from, Some("cgroup.procs"))?;
    let data = fs::read_to_string(from_file)?;
    let self_pid = std::process::id() as i32;
    let mut migrated = false;

    for line in data.lines() {
        let Ok(pid) = line.trim().parse::<i32>() else {
            continue;
        };
        if flags.contains(CGroupFlags::IGNORE_SELF) && pid == self_pid {
            continue;
        }
        cg_attach(to, pid)?;
        migrated = true;
    }

    if migrated && flags.contains(CGroupFlags::REMOVE) {
        let _ = cg_trim(from, true);
    }

    Ok(migrated)
}

/// Trim subcgroups recursively. When `delete_root` is true, attempt to remove root too.
pub fn cg_trim(path: &str, delete_root: bool) -> io::Result<()> {
    let root = cg_get_path(path, None)?;
    trim_inner(&root)?;
    if delete_root {
        let _ = fs::remove_dir(&root);
    }
    Ok(())
}

/// Backward-compatible wrapper for writing cgroup files.
///
/// Only cgroup v2 unified hierarchy writes are supported.
pub fn cgroup_write(controller: &str, cgroup: &str, key: &str, value: &str) -> io::Result<()> {
    if !controller.is_empty() {
        return Err(invalid_input("cgroup v1 controllers are unsupported"));
    }
    if key.is_empty() {
        return Err(invalid_input("key must not be empty"));
    }

    let path = cg_get_path(cgroup, Some(key))?;
    fs::write(path, value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Mutex, OnceLock};

    struct TempRoot {
        path: PathBuf,
    }

    impl TempRoot {
        fn new() -> Self {
            static NEXT_ID: AtomicU64 = AtomicU64::new(0);
            let root = env::temp_dir().join(format!(
                "systemd-cgroup-rs-{}-{}",
                std::process::id(),
                NEXT_ID.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(&root).unwrap();
            Self { path: root }
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TempRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    struct EnvGuard {
        key: &'static str,
        previous: Option<OsString>,
    }

    impl EnvGuard {
        // SAFETY: callers must exclude concurrent process-environment access
        // until the returned guard is dropped.
        unsafe fn set(key: &'static str, value: &Path) -> Self {
            let previous = env::var_os(key);
            // SAFETY: with_temp_cgroup_root holds the test module's environment
            // lock for this guard's complete lifetime.
            unsafe { env::set_var(key, value) };
            Self { key, previous }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            if let Some(previous) = self.previous.take() {
                // SAFETY: the environment lock is still held while this guard
                // restores the value it changed.
                unsafe { env::set_var(self.key, previous) };
            } else {
                // SAFETY: the environment lock is still held while this guard
                // restores the value it changed.
                unsafe { env::remove_var(self.key) };
            }
        }
    }

    /// # Safety
    ///
    /// The caller must ensure that no other thread reads or mutates the process
    /// environment until the callback returns.
    unsafe fn with_temp_cgroup_root<T>(f: impl FnOnce(&Path) -> T) -> T {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        let _guard = match LOCK.get_or_init(|| Mutex::new(())).lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let root = TempRoot::new();
        // SAFETY: this function's caller upholds the environment contract for
        // the complete lifetime of the guard.
        let _env = unsafe { EnvGuard::set(SYSTEMD_CGROUP_ROOT, root.path()) };
        f(root.path())
    }

    #[test]
    fn test_cgroup_controller_mask_and_name() {
        assert_eq!(CgroupController::Cpu.mask(), 1u64 << 0);
        assert_eq!(CgroupController::Cpuset.mask(), 1u64 << 1);
        assert_eq!(CgroupController::Rdma.mask(), 1u64 << 5);
        assert_eq!(CgroupController::Cpu.as_str(), "cpu");
        assert_eq!(CgroupController::Cpuset.as_str(), "cpuset");
        assert_eq!(CgroupController::Rdma.as_str(), "rdma");
    }

    #[test]
    fn test_cgroup_controller_lookup() {
        assert_eq!(CgroupController::from_index(0), Some(CgroupController::Cpu));
        assert_eq!(
            CgroupController::from_index(5),
            Some(CgroupController::Rdma)
        );
        assert_eq!(CgroupController::from_index(7), None);
        assert_eq!(
            CgroupController::from_name("memory"),
            Some(CgroupController::Memory)
        );
        assert_eq!(CgroupController::from_name("bogus"), None);
    }

    #[test]
    fn test_cg_get_path_normalizes_and_joins_root() {
        // SAFETY: this environment-dependent test target runs with --test-threads=1
        // and does not spawn threads that access the process environment.
        unsafe {
            with_temp_cgroup_root(|root| {
                let root = fs::canonicalize(root).unwrap();
                let path = cg_get_path("/foo/./bar//", Some("cgroup.procs")).unwrap();
                assert_eq!(path, root.join("foo/bar/cgroup.procs"));
            })
        };
    }

    #[test]
    fn test_cg_get_path_rejects_parent_and_nul() {
        // SAFETY: this environment-dependent test target runs with --test-threads=1
        // and does not spawn threads that access the process environment.
        unsafe {
            with_temp_cgroup_root(|_| {
                assert_eq!(
                    cg_get_path("/foo/../bar", None).unwrap_err().kind(),
                    io::ErrorKind::InvalidInput
                );
                assert_eq!(
                    cg_get_path("foo\0bar", None).unwrap_err().kind(),
                    io::ErrorKind::InvalidInput
                );
            })
        };
    }

    #[test]
    fn test_parse_proc_cgroup_prefers_v2() {
        let content = "11:cpu:/legacy\n0::/user.slice/user-1000.slice/session-2.scope\n";
        assert_eq!(
            parse_proc_cgroup(content).unwrap(),
            "/user.slice/user-1000.slice/session-2.scope"
        );
    }

    #[test]
    fn test_parse_proc_cgroup_rejects_traversal() {
        let content = "0::/../escape\n";
        assert_eq!(
            parse_proc_cgroup(content).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[test]
    fn test_cg_mask_supported_parses_known_controllers() {
        // SAFETY: this environment-dependent test target runs with --test-threads=1
        // and does not spawn threads that access the process environment.
        unsafe {
            with_temp_cgroup_root(|root| {
                fs::write(
                    root.join("cgroup.controllers"),
                    "cpu memory rdma freezer bogus\n",
                )
                .unwrap();

                let mask = cg_mask_supported().unwrap();
                assert!(mask & CgroupController::Cpu.mask() != 0);
                assert!(mask & CgroupController::Memory.mask() != 0);
                assert!(mask & CgroupController::Rdma.mask() != 0);
                assert!(mask & CgroupController::Freezer.mask() == 0);
            })
        };
    }

    #[test]
    fn test_cg_enable_writes_expected_actions() {
        // SAFETY: this environment-dependent test target runs with --test-threads=1
        // and does not spawn threads that access the process environment.
        unsafe {
            with_temp_cgroup_root(|root| {
                fs::create_dir_all(root.join("demo")).unwrap();
                fs::write(root.join("demo/cgroup.controllers"), "cpu memory rdma\n").unwrap();

                let supported = cg_mask_supported_subtree("demo").unwrap();
                let result = cg_enable(supported, CgroupController::Cpu.mask(), "demo").unwrap();

                assert_eq!(result, CgroupController::Cpu.mask());
                let contents =
                    fs::read_to_string(root.join("demo/cgroup.subtree_control")).unwrap();
                assert_eq!(contents, "+cpu\n-memory\n-rdma\n");
            })
        };
    }

    #[test]
    fn test_cgroup_write_rejects_controller_name() {
        // SAFETY: this environment-dependent test target runs with --test-threads=1
        // and does not spawn threads that access the process environment.
        unsafe {
            with_temp_cgroup_root(|root| {
                fs::create_dir_all(root.join("demo")).unwrap();
                let err = cgroup_write("cpu", "demo", "cgroup.procs", "1");
                assert_eq!(err.unwrap_err().kind(), io::ErrorKind::InvalidInput);
            })
        };
    }

    #[test]
    fn test_cg_create_and_attach_writes_pid() {
        // SAFETY: this environment-dependent test target runs with --test-threads=1
        // and does not spawn threads that access the process environment.
        unsafe {
            with_temp_cgroup_root(|root| {
                fs::create_dir_all(root.join("demo")).unwrap();
                fs::File::create(root.join("demo/cgroup.procs")).unwrap();
                cg_attach("demo", 42).unwrap();
                let data = fs::read_to_string(root.join("demo/cgroup.procs")).unwrap();
                assert_eq!(data, "42\n");
            })
        };
    }

    #[test]
    fn test_cg_migrate_moves_pids() {
        // SAFETY: this environment-dependent test target runs with --test-threads=1
        // and does not spawn threads that access the process environment.
        unsafe {
            with_temp_cgroup_root(|root| {
                fs::create_dir_all(root.join("from")).unwrap();
                fs::create_dir_all(root.join("to")).unwrap();
                fs::write(root.join("from/cgroup.procs"), "11\n12\n").unwrap();
                fs::File::create(root.join("to/cgroup.procs")).unwrap();

                let changed = cg_migrate("from", "to", CGroupFlags::empty()).unwrap();
                assert!(changed);
                let data = fs::read_to_string(root.join("to/cgroup.procs")).unwrap();
                assert_eq!(data, "11\n12\n");
            })
        };
    }

    #[test]
    fn test_cg_trim_removes_empty_subdirs() {
        // SAFETY: this environment-dependent test target runs with --test-threads=1
        // and does not spawn threads that access the process environment.
        unsafe {
            with_temp_cgroup_root(|root| {
                fs::create_dir_all(root.join("parent/child/grandchild")).unwrap();
                fs::write(root.join("parent/leaf.txt"), "x").unwrap();
                cg_trim("parent", false).unwrap();
                assert!(!root.join("parent/child/grandchild").exists());
                assert!(root.join("parent").exists());
            })
        };
    }
}
