// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/udev/udev-rules.c, src/udev/udev-node.c, src/udev/udev-worker.c

use crate::udev_builtin::builtin_by_name;
use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::path::{Component, Path, PathBuf};

#[cfg(target_os = "linux")]
use std::ffi::{CStr, CString, OsStr};
#[cfg(test)]
use std::fs;
#[cfg(target_os = "linux")]
use std::mem::MaybeUninit;
#[cfg(target_os = "linux")]
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
#[cfg(target_os = "linux")]
use std::os::unix::ffi::OsStrExt;
#[cfg(target_os = "linux")]
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DeviceEvent {
    pub action: String,
    pub devpath: String,
    pub kernel: String,
    pub subsystem: String,
    pub env: BTreeMap<String, String>,
    pub tags: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MatchToken {
    Action(String),
    Devpath(String),
    Kernel(String),
    Subsystem(String),
    Env { key: String, value: String },
    Tag(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AssignToken {
    Name(String),
    Symlink(String),
    Owner(String),
    Group(String),
    Mode(u32),
    Env { key: String, value: String },
    Tag(String),
    Run(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Rule {
    pub matches: Vec<MatchToken>,
    pub assigns: Vec<AssignToken>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RuleAssignment {
    pub name: Option<String>,
    pub symlinks: BTreeSet<String>,
    pub owner: Option<String>,
    pub group: Option<String>,
    pub mode: Option<u32>,
    pub env: BTreeMap<String, String>,
    pub tags: BTreeSet<String>,
    pub run: Vec<String>,
}

fn wildcard_match(pattern: &str, text: &str) -> bool {
    let p = pattern.as_bytes();
    let t = text.as_bytes();
    let mut dp = vec![vec![false; t.len() + 1]; p.len() + 1];
    dp[0][0] = true;

    for i in 1..=p.len() {
        if p[i - 1] == b'*' {
            dp[i][0] = dp[i - 1][0];
        }
    }

    for i in 1..=p.len() {
        for j in 1..=t.len() {
            dp[i][j] = match p[i - 1] {
                b'*' => dp[i - 1][j] || dp[i][j - 1],
                b'?' => dp[i - 1][j - 1],
                c => dp[i - 1][j - 1] && c == t[j - 1],
            };
        }
    }

    dp[p.len()][t.len()]
}

fn token_matches(event: &DeviceEvent, token: &MatchToken) -> bool {
    match token {
        MatchToken::Action(v) => wildcard_match(v, &event.action),
        MatchToken::Devpath(v) => wildcard_match(v, &event.devpath),
        MatchToken::Kernel(v) => wildcard_match(v, &event.kernel),
        MatchToken::Subsystem(v) => wildcard_match(v, &event.subsystem),
        MatchToken::Env { key, value } => event
            .env
            .get(key)
            .map(|v| wildcard_match(value, v))
            .unwrap_or(false),
        MatchToken::Tag(tag) => event.tags.iter().any(|t| wildcard_match(tag, t)),
    }
}

pub fn apply_rules(event: &DeviceEvent, rules: &[Rule]) -> RuleAssignment {
    let mut context = event.clone();
    let mut assignment = RuleAssignment::default();

    for rule in rules {
        if !rule
            .matches
            .iter()
            .all(|token| token_matches(&context, token))
        {
            continue;
        }

        for assign in &rule.assigns {
            match assign {
                AssignToken::Name(name) => assignment.name = Some(name.clone()),
                AssignToken::Symlink(link) => {
                    assignment.symlinks.insert(link.clone());
                }
                AssignToken::Owner(owner) => assignment.owner = Some(owner.clone()),
                AssignToken::Group(group) => assignment.group = Some(group.clone()),
                AssignToken::Mode(mode) => assignment.mode = Some(*mode),
                AssignToken::Env { key, value } => {
                    assignment.env.insert(key.clone(), value.clone());
                    context.env.insert(key.clone(), value.clone());
                }
                AssignToken::Tag(tag) => {
                    assignment.tags.insert(tag.clone());
                    context.tags.insert(tag.clone());
                }
                AssignToken::Run(cmd) => assignment.run.push(cmd.clone()),
            }
        }
    }

    assignment
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceNodeKind {
    Block,
    Char,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceNodeSpec {
    /// Root directory that contains both the device node and rule-created
    /// symlinks. This is `/dev` in production and may be a temporary directory
    /// in tests.
    pub dev_root: PathBuf,
    pub path: PathBuf,
    pub kind: DeviceNodeKind,
    pub major: u32,
    pub minor: u32,
    pub mode: u32,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeApplyError {
    Io(i32),
    InvalidPath,
}

impl From<io::Error> for NodeApplyError {
    fn from(value: io::Error) -> Self {
        Self::Io(-value.raw_os_error().unwrap_or(libc::EIO))
    }
}

/// Return whether `path` is a non-empty relative path made solely of normal
/// path components. Device event data and rule values must never be allowed to
/// select an absolute path or escape the device directory with `.` or `..`.
pub fn is_safe_device_relative_path(path: &str) -> bool {
    !path.is_empty()
        && !path.as_bytes().contains(&0)
        && Path::new(path)
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
}

#[cfg(target_os = "linux")]
struct ResolvedPath {
    parent: OwnedFd,
    name: CString,
}

#[cfg(target_os = "linux")]
fn c_string(value: &OsStr) -> Result<CString, NodeApplyError> {
    CString::new(value.as_bytes()).map_err(|_| NodeApplyError::InvalidPath)
}

#[cfg(target_os = "linux")]
fn owned_fd(raw: libc::c_int) -> Result<OwnedFd, NodeApplyError> {
    if raw < 0 {
        return Err(NodeApplyError::from(io::Error::last_os_error()));
    }

    // SAFETY: `raw` was just returned by an fd-producing libc call and has
    // not been wrapped or closed. Ownership is transferred exactly once.
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}

#[cfg(target_os = "linux")]
fn open_device_root(path: &Path) -> Result<OwnedFd, NodeApplyError> {
    let path = c_string(path.as_os_str())?;
    // SAFETY: `path` is NUL-terminated and lives through the call. O_PATH
    // avoids granting data access; O_NOFOLLOW rejects a symlink as the root
    // itself, and the returned descriptor is uniquely owned.
    owned_fd(unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    })
}

#[cfg(target_os = "linux")]
fn duplicate_fd(fd: RawFd) -> Result<OwnedFd, NodeApplyError> {
    // SAFETY: `fd` is borrowed for the duration of fcntl. F_DUPFD_CLOEXEC
    // returns a new descriptor with independent ownership.
    owned_fd(unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) })
}

#[cfg(target_os = "linux")]
fn open_child_directory(parent: RawFd, name: &CStr) -> Result<OwnedFd, NodeApplyError> {
    // SAFETY: `parent` is a live directory descriptor and `name` is a
    // NUL-terminated single path component. O_NOFOLLOW|O_DIRECTORY prevents
    // a pre-existing or concurrently substituted symlink from being followed.
    owned_fd(unsafe {
        libc::openat(
            parent,
            name.as_ptr(),
            libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    })
}

#[cfg(target_os = "linux")]
fn resolve_parent(root: &OwnedFd, relative: &Path) -> Result<ResolvedPath, NodeApplyError> {
    let name = relative
        .file_name()
        .ok_or(NodeApplyError::InvalidPath)
        .and_then(c_string)?;
    let mut current = duplicate_fd(root.as_raw_fd())?;

    if let Some(parent) = relative.parent() {
        for component in parent.components() {
            let Component::Normal(component) = component else {
                return Err(NodeApplyError::InvalidPath);
            };
            let component = c_string(component)?;

            // SAFETY: both arguments are valid, and `component` is a single
            // validated path component relative to `current`.
            if unsafe { libc::mkdirat(current.as_raw_fd(), component.as_ptr(), 0o755) } < 0 {
                let error = io::Error::last_os_error();
                if error.raw_os_error() != Some(libc::EEXIST) {
                    return Err(NodeApplyError::from(error));
                }
            }

            current = open_child_directory(current.as_raw_fd(), &component)?;
        }
    }

    Ok(ResolvedPath {
        parent: current,
        name,
    })
}

#[cfg(target_os = "linux")]
fn fstat_fd(fd: RawFd) -> Result<libc::stat, NodeApplyError> {
    let mut stat = MaybeUninit::<libc::stat>::uninit();
    // SAFETY: `fd` is live and `stat` points to writable storage large enough
    // for libc::stat. The value is initialized only after fstat succeeds.
    if unsafe { libc::fstat(fd, stat.as_mut_ptr()) } < 0 {
        return Err(NodeApplyError::from(io::Error::last_os_error()));
    }
    // SAFETY: successful fstat initialized the complete structure.
    Ok(unsafe { stat.assume_init() })
}

#[cfg(target_os = "linux")]
fn chmod_opath(fd: RawFd, mode: libc::mode_t) -> Result<(), NodeApplyError> {
    static EMPTY: &[u8] = b"\0";

    // SAFETY: `fd` is live, EMPTY is a valid empty C string, and
    // AT_EMPTY_PATH directs libc/the kernel to the already pinned inode.
    if unsafe {
        libc::fchmodat(
            fd,
            EMPTY.as_ptr().cast(),
            mode & 0o7777,
            libc::AT_EMPTY_PATH,
        )
    } >= 0
    {
        return Ok(());
    }

    let error = io::Error::last_os_error();
    let errno = error.raw_os_error();
    if errno != Some(libc::EINVAL)
        && errno != Some(libc::ENOSYS)
        && errno != Some(libc::EPERM)
        && errno != Some(libc::ENOTSUP)
    {
        return Err(NodeApplyError::from(error));
    }

    // Older libc/kernel combinations cannot apply fchmodat2(AT_EMPTY_PATH).
    // This procfs path is derived solely from our still-owned descriptor, not
    // from event data, so following this magic link still targets the pinned
    // inode and cannot escape through a raced device path.
    let proc_path =
        CString::new(format!("/proc/self/fd/{fd}")).map_err(|_| NodeApplyError::InvalidPath)?;
    // SAFETY: `proc_path` is a valid C string and the mode is permission bits.
    if unsafe { libc::chmod(proc_path.as_ptr(), mode & 0o7777) } < 0 {
        return Err(NodeApplyError::from(io::Error::last_os_error()));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn apply_node_permissions(
    node: &OwnedFd,
    mode: u32,
    uid: Option<u32>,
    gid: Option<u32>,
) -> Result<(), NodeApplyError> {
    let stat = fstat_fd(node.as_raw_fd())?;
    let current_mode = stat.st_mode & 0o7777;
    let desired_mode = mode as libc::mode_t & 0o7777;
    let ownership_changes = uid.is_some_and(|value| value != stat.st_uid)
        || gid.is_some_and(|value| value != stat.st_gid);

    if ownership_changes {
        let minimal_mode = current_mode & desired_mode;
        if minimal_mode != current_mode {
            chmod_opath(node.as_raw_fd(), minimal_mode)?;
        }

        static EMPTY: &[u8] = b"\0";
        // SAFETY: the empty path plus AT_EMPTY_PATH selects the pinned inode.
        // u32::MAX is Linux's documented "leave unchanged" uid/gid sentinel.
        if unsafe {
            libc::fchownat(
                node.as_raw_fd(),
                EMPTY.as_ptr().cast(),
                uid.unwrap_or(u32::MAX),
                gid.unwrap_or(u32::MAX),
                libc::AT_EMPTY_PATH,
            )
        } < 0
        {
            return Err(NodeApplyError::from(io::Error::last_os_error()));
        }
    }

    if ownership_changes || current_mode != desired_mode {
        chmod_opath(node.as_raw_fd(), desired_mode)?;
    }

    Ok(())
}

#[cfg(target_os = "linux")]
fn create_or_open_device_node(
    path: &ResolvedPath,
    kind: DeviceNodeKind,
    major: u32,
    minor: u32,
    mode: u32,
) -> Result<OwnedFd, NodeApplyError> {
    let kind_bits: libc::mode_t = match kind {
        DeviceNodeKind::Block => libc::S_IFBLK,
        DeviceNodeKind::Char => libc::S_IFCHR,
    };
    // `makedev` is a pure libc encoding operation.
    let device = libc::makedev(major as _, minor as _);

    // SAFETY: the parent descriptor is live, the name is a single
    // NUL-terminated component, and mknodat cannot traverse through it.
    if unsafe {
        libc::mknodat(
            path.parent.as_raw_fd(),
            path.name.as_ptr(),
            kind_bits | (mode as libc::mode_t & 0o7777),
            device,
        )
    } < 0
    {
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::EEXIST) {
            return Err(NodeApplyError::from(error));
        }
    }

    // O_PATH|O_NOFOLLOW pins the directory entry without opening the device
    // itself (which could otherwise have driver-visible side effects).
    // SAFETY: the descriptor and C string remain valid for the call.
    let node = owned_fd(unsafe {
        libc::openat(
            path.parent.as_raw_fd(),
            path.name.as_ptr(),
            libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    })?;
    let stat = fstat_fd(node.as_raw_fd())?;
    if stat.st_mode & libc::S_IFMT != kind_bits || stat.st_rdev != device {
        return Err(NodeApplyError::Io(-libc::EEXIST));
    }

    Ok(node)
}

#[cfg(target_os = "linux")]
fn relative_symlink_target(node: &Path, link: &Path) -> Result<CString, NodeApplyError> {
    let mut target = PathBuf::new();
    if let Some(parent) = link.parent() {
        for component in parent.components() {
            if !matches!(component, Component::Normal(_)) {
                return Err(NodeApplyError::InvalidPath);
            }
            target.push("..");
        }
    }
    target.push(node);
    c_string(target.as_os_str())
}

#[cfg(target_os = "linux")]
fn fstatat_nofollow(path: &ResolvedPath) -> Result<Option<libc::stat>, NodeApplyError> {
    let mut stat = MaybeUninit::<libc::stat>::uninit();
    // SAFETY: all pointers and descriptors remain valid for the call.
    if unsafe {
        libc::fstatat(
            path.parent.as_raw_fd(),
            path.name.as_ptr(),
            stat.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } >= 0
    {
        // SAFETY: successful fstatat initialized the complete structure.
        return Ok(Some(unsafe { stat.assume_init() }));
    }

    let error = io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::ENOENT) {
        Ok(None)
    } else {
        Err(NodeApplyError::from(error))
    }
}

#[cfg(target_os = "linux")]
fn replace_symlink_atomic(path: &ResolvedPath, target: &CStr) -> Result<(), NodeApplyError> {
    if let Some(stat) = fstatat_nofollow(path)?
        && stat.st_mode & libc::S_IFMT != libc::S_IFLNK
    {
        return Err(NodeApplyError::Io(-libc::EEXIST));
    }

    static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);
    let parent = path.parent.as_raw_fd();
    for _ in 0..64 {
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let temporary = CString::new(format!(".udev-rs-tmp-{}-{sequence}", std::process::id()))
            .map_err(|_| NodeApplyError::InvalidPath)?;

        // SAFETY: the target and temporary name are valid C strings and the
        // latter is a single internally generated component.
        if unsafe { libc::symlinkat(target.as_ptr(), parent, temporary.as_ptr()) } < 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EEXIST) {
                continue;
            }
            return Err(NodeApplyError::from(error));
        }

        // renameat atomically replaces an existing symlink, matching
        // symlinkat_atomic_full() in the canonical C implementation.
        // SAFETY: both names are valid and relative to the same live dirfd.
        if unsafe { libc::renameat(parent, temporary.as_ptr(), parent, path.name.as_ptr()) } >= 0 {
            return Ok(());
        }

        let error = io::Error::last_os_error();
        // SAFETY: cleanup is confined to the internal temporary name.
        unsafe {
            libc::unlinkat(parent, temporary.as_ptr(), 0);
        }
        return Err(NodeApplyError::from(error));
    }

    Err(NodeApplyError::Io(-libc::EEXIST))
}

#[cfg(target_os = "linux")]
fn apply_node_and_symlinks_linux(
    spec: &DeviceNodeSpec,
    relative_node: &Path,
    symlinks: &BTreeSet<String>,
) -> Result<(), NodeApplyError> {
    let root = open_device_root(&spec.dev_root)?;

    // Resolve and hold every parent before creating the node. Parent
    // components are opened one at a time with O_NOFOLLOW, so neither
    // pre-existing symlinks nor rename/symlink substitution races can redirect
    // later filesystem operations through an event-derived path.
    let node_path = resolve_parent(&root, relative_node)?;
    let mut resolved_links = Vec::with_capacity(symlinks.len());
    for link in symlinks {
        let relative_link = Path::new(link);
        resolved_links.push((
            resolve_parent(&root, relative_link)?,
            relative_symlink_target(relative_node, relative_link)?,
        ));
    }

    let node =
        create_or_open_device_node(&node_path, spec.kind, spec.major, spec.minor, spec.mode)?;
    apply_node_permissions(&node, spec.mode, spec.uid, spec.gid)?;

    for (link, target) in resolved_links {
        replace_symlink_atomic(&link, &target)?;
    }

    Ok(())
}

pub fn apply_node_and_symlinks(
    spec: &DeviceNodeSpec,
    symlinks: &BTreeSet<String>,
) -> Result<PathBuf, NodeApplyError> {
    let relative_node = spec
        .path
        .strip_prefix(&spec.dev_root)
        .map_err(|_| NodeApplyError::InvalidPath)?;

    // Validate every event-derived path before touching the node. This keeps
    // an invalid rule value from producing a partial device update and
    // prevents lexical escapes from the configured device directory.
    if !is_safe_device_relative_path(relative_node.to_str().ok_or(NodeApplyError::InvalidPath)?)
        || symlinks
            .iter()
            .any(|link| !is_safe_device_relative_path(link))
    {
        return Err(NodeApplyError::InvalidPath);
    }

    #[cfg(target_os = "linux")]
    apply_node_and_symlinks_linux(spec, relative_node, symlinks)?;

    #[cfg(not(target_os = "linux"))]
    return Err(NodeApplyError::Io(-libc::ENOTSUP));

    Ok(spec.path.clone())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunResult {
    BuiltinUnsupported(String),
    BuiltinMissing(String),
    ExternalUnsupported(String),
    Skipped(String),
}

fn parse_builtin_command(command: &str) -> Option<&str> {
    if let Some(name) = command.strip_prefix("builtin:") {
        let trimmed = name.trim();
        if !trimmed.is_empty() {
            return Some(trimmed);
        }
        return None;
    }

    if let Some(rest) = command.strip_prefix("builtin ") {
        let mut parts = rest.split_whitespace();
        return parts.next();
    }

    None
}

pub fn execute_run_commands(commands: &[String], execute_external: bool) -> Vec<RunResult> {
    let mut out = Vec::with_capacity(commands.len());

    for cmd in commands {
        if let Some(name) = parse_builtin_command(cmd) {
            if builtin_by_name(name).is_some() {
                // The registry currently contains metadata only. Reporting
                // success here would silently skip the requested device
                // mutation.
                out.push(RunResult::BuiltinUnsupported(name.to_string()));
            } else {
                out.push(RunResult::BuiltinMissing(name.to_string()));
            }
            continue;
        }

        if !execute_external {
            out.push(RunResult::Skipped(cmd.clone()));
            continue;
        }

        // Canonical udev tokenizes the command without a shell, resolves it
        // below UDEVLIBEXECDIR, pins the executable, supplies device
        // properties, and enforces an event deadline. Until that machinery is
        // ported, fail explicitly instead of introducing shell expansion and
        // falsely claiming parity.
        out.push(RunResult::ExternalUnsupported(cmd.clone()));
    }

    out
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EngineOutput {
    pub assignment: RuleAssignment,
    pub node_path: Option<PathBuf>,
    pub run_results: Vec<RunResult>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EngineError {
    Node(NodeApplyError),
}

pub fn process_device_event(
    event: &DeviceEvent,
    rules: &[Rule],
    node_spec: Option<&DeviceNodeSpec>,
    execute_external_run: bool,
) -> Result<EngineOutput, EngineError> {
    let assignment = apply_rules(event, rules);
    let node_path = match node_spec {
        Some(spec) => {
            Some(apply_node_and_symlinks(spec, &assignment.symlinks).map_err(EngineError::Node)?)
        }
        None => None,
    };
    let run_results = execute_run_commands(&assignment.run, execute_external_run);

    Ok(EngineOutput {
        assignment,
        node_path,
        run_results,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_event() -> DeviceEvent {
        let mut env = BTreeMap::new();
        env.insert("ID_VENDOR".to_string(), "Acme".to_string());
        DeviceEvent {
            action: "add".to_string(),
            devpath: "/devices/pci0000:00/mock0".to_string(),
            kernel: "mock0".to_string(),
            subsystem: "block".to_string(),
            env,
            tags: BTreeSet::new(),
        }
    }

    #[test]
    fn match_and_assignment_phases_are_applied() {
        let rules = vec![Rule {
            matches: vec![
                MatchToken::Action("add".to_string()),
                MatchToken::Subsystem("block".to_string()),
                MatchToken::Env {
                    key: "ID_VENDOR".to_string(),
                    value: "A*".to_string(),
                },
            ],
            assigns: vec![
                AssignToken::Name("sda".to_string()),
                AssignToken::Symlink("disk/by-id/acme-disk".to_string()),
                AssignToken::Mode(0o660),
                AssignToken::Tag("systemd".to_string()),
            ],
        }];

        let out = apply_rules(&sample_event(), &rules);
        assert_eq!(out.name, Some("sda".to_string()));
        assert!(out.symlinks.contains("disk/by-id/acme-disk"));
        assert_eq!(out.mode, Some(0o660));
        assert!(out.tags.contains("systemd"));
    }

    #[test]
    fn env_assignment_can_feed_later_match() {
        let rules = vec![
            Rule {
                matches: vec![MatchToken::Action("add".to_string())],
                assigns: vec![AssignToken::Env {
                    key: "MATCH_ME".to_string(),
                    value: "yes".to_string(),
                }],
            },
            Rule {
                matches: vec![MatchToken::Env {
                    key: "MATCH_ME".to_string(),
                    value: "yes".to_string(),
                }],
                assigns: vec![AssignToken::Tag("second".to_string())],
            },
        ];

        let out = apply_rules(&sample_event(), &rules);
        assert!(out.tags.contains("second"));
    }

    #[test]
    fn node_and_symlink_creation_works() {
        let root = std::env::temp_dir().join(format!("udev-node-engine-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();

        let spec = DeviceNodeSpec {
            dev_root: root.clone(),
            path: root.join("sda"),
            kind: DeviceNodeKind::Block,
            major: 8,
            minor: 0,
            mode: 0o660,
            uid: None,
            gid: None,
        };

        let mut links = BTreeSet::new();
        links.insert("disk/by-id/mock-disk".to_string());
        apply_node_and_symlinks(&spec, &links).unwrap();

        assert!(spec.path.exists());
        assert!(root.join("disk/by-id/mock-disk").exists());

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn nested_node_keeps_symlinks_at_device_root() {
        let root =
            std::env::temp_dir().join(format!("udev-node-engine-nested-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();

        let spec = DeviceNodeSpec {
            dev_root: root.clone(),
            path: root.join("input/event0"),
            kind: DeviceNodeKind::Char,
            major: 13,
            minor: 64,
            mode: 0o660,
            uid: None,
            gid: None,
        };
        let links = BTreeSet::from(["input/by-id/mock-event".to_string()]);

        apply_node_and_symlinks(&spec, &links).unwrap();
        assert!(root.join("input/by-id/mock-event").exists());
        assert!(!root.join("input/input/by-id/mock-event").exists());

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn unsafe_symlink_paths_are_rejected_before_node_creation() {
        let root =
            std::env::temp_dir().join(format!("udev-node-engine-invalid-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);

        let spec = DeviceNodeSpec {
            dev_root: root.clone(),
            path: root.join("sda"),
            kind: DeviceNodeKind::Block,
            major: 8,
            minor: 0,
            mode: 0o660,
            uid: None,
            gid: None,
        };
        let mut links = BTreeSet::new();
        links.insert("../outside".to_string());

        assert_eq!(
            apply_node_and_symlinks(&spec, &links),
            Err(NodeApplyError::InvalidPath)
        );
        assert!(!spec.path.exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn symlinked_node_parent_is_rejected_without_escaping_device_root() {
        use std::os::unix::fs::symlink;

        let base = std::env::temp_dir().join(format!(
            "udev-node-engine-raced-parent-{}",
            std::process::id()
        ));
        let root = base.join("dev");
        let outside = base.join("outside");
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&root).unwrap();
        fs::create_dir_all(&outside).unwrap();
        symlink(&outside, root.join("raced")).unwrap();

        let spec = DeviceNodeSpec {
            dev_root: root.clone(),
            path: root.join("raced/sda"),
            kind: DeviceNodeKind::Block,
            major: 8,
            minor: 0,
            mode: 0o660,
            uid: None,
            gid: None,
        };

        assert!(matches!(
            apply_node_and_symlinks(&spec, &BTreeSet::new()),
            Err(NodeApplyError::Io(_))
        ));
        assert!(!outside.join("sda").exists());

        let _ = fs::remove_dir_all(&base);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn symlinked_link_parent_is_rejected_before_node_creation() {
        use std::os::unix::fs::symlink;

        let base = std::env::temp_dir().join(format!(
            "udev-node-engine-raced-link-{}",
            std::process::id()
        ));
        let root = base.join("dev");
        let outside = base.join("outside");
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&root).unwrap();
        fs::create_dir_all(&outside).unwrap();
        symlink(&outside, root.join("disk")).unwrap();

        let spec = DeviceNodeSpec {
            dev_root: root.clone(),
            path: root.join("sda"),
            kind: DeviceNodeKind::Block,
            major: 8,
            minor: 0,
            mode: 0o660,
            uid: None,
            gid: None,
        };
        let links = BTreeSet::from(["disk/by-id/mock-disk".to_string()]);

        assert!(matches!(
            apply_node_and_symlinks(&spec, &links),
            Err(NodeApplyError::Io(_))
        ));
        assert!(!spec.path.exists());
        assert!(!outside.join("by-id").exists());

        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn safe_device_relative_paths_reject_escaping_components() {
        assert!(is_safe_device_relative_path("disk/by-id/mock-disk"));
        for invalid in ["", "/etc/passwd", "../outside", "disk/../outside", "./disk"] {
            assert!(
                !is_safe_device_relative_path(invalid),
                "{invalid} must be rejected"
            );
        }
    }

    #[test]
    fn run_execution_supports_builtin_and_external_commands() {
        let results = execute_run_commands(
            &[
                "builtin:kmod".to_string(),
                "builtin kmod".to_string(),
                "builtin:missing-builtin".to_string(),
                "true".to_string(),
            ],
            true,
        );

        assert!(matches!(results[0], RunResult::BuiltinUnsupported(_)));
        assert!(matches!(results[1], RunResult::BuiltinUnsupported(_)));
        assert!(matches!(results[2], RunResult::BuiltinMissing(_)));
        assert!(matches!(results[3], RunResult::ExternalUnsupported(_)));
    }

    #[test]
    fn tag_match_uses_wildcards() {
        let mut event = sample_event();
        event.tags.insert("seat-lab".to_string());

        let rules = vec![Rule {
            matches: vec![MatchToken::Tag("seat-*".to_string())],
            assigns: vec![AssignToken::Tag("matched".to_string())],
        }];

        let out = apply_rules(&event, &rules);
        assert!(out.tags.contains("matched"));
    }
}
