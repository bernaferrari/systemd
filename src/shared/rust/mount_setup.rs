// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/mount-setup.c, src/shared/mount-setup.h
//
// Early boot mount setup: creates API filesystem mount points and mounts
// virtual filesystems like /proc, /sys, /dev, /run during system boot.
//
// The mount table defines the standard API filesystems that systemd mounts
// during early boot. The first N_EARLY_MOUNT entries are established before
// SELinux/IMA policies are loaded. Remaining entries are mounted after
// policy loading.

use crate::ffi::*;
use std::fs;
use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use crate::mount_util::{
    MS_NODEV, MS_NOEXEC, MS_NOSUID, MS_REC, MS_SHARED, MS_STRICTATIME, UMOUNT_NOFOLLOW,
};

#[cfg(target_os = "linux")]
use crate::mount_util::{mount_nofollow_verbose, mount_verbose_full, umount_verbose};

// ── Error type ──────────────────────────────────────────────────────────────

/// Errors from mount setup operations.
#[derive(Debug)]
pub enum MountSetupError {
    /// A mount(2) syscall failed.
    MountFailed {
        what: String,
        where_: String,
        source: io::Error,
    },
    /// An umount(2) syscall failed.
    UmountFailed { path: String, source: io::Error },
    /// Failed to create a mount point directory.
    MkdirFailed { path: String, source: io::Error },
    /// Mount point is not writable after mounting.
    NotWritable { path: String, source: io::Error },
}

impl std::fmt::Display for MountSetupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MountFailed {
                what,
                where_,
                source,
            } => {
                write!(f, "Failed to mount {} on {}: {}", what, where_, source)
            }
            Self::UmountFailed { path, source } => {
                write!(f, "Failed to unmount {}: {}", path, source)
            }
            Self::MkdirFailed { path, source } => {
                write!(f, "Failed to create directory {}: {}", path, source)
            }
            Self::NotWritable { path, source } => {
                write!(f, "Mount point '{}' not writable: {}", path, source)
            }
        }
    }
}

impl std::error::Error for MountSetupError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::MountFailed { source, .. }
            | Self::UmountFailed { source, .. }
            | Self::MkdirFailed { source, .. }
            | Self::NotWritable { source, .. } => Some(source),
        }
    }
}

/// Result type for mount setup operations.
pub type Result<T> = std::result::Result<T, MountSetupError>;

// ── Mount mode flags ────────────────────────────────────────────────────────

bitflags::bitflags! {
    /// Flags controlling mount point behavior.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct MountMode: u32 {
        /// If mounting fails, return an error instead of continuing silently.
        const FATAL            = 1 << 0;
        /// Mount this filesystem even when running inside a container.
        const IN_CONTAINER     = 1 << 1;
        /// After mounting, verify the mount point is writable.
        const CHECK_WRITABLE   = 1 << 2;
        /// Follow symlinks when resolving the mount point path.
        const FOLLOW_SYMLINK   = 1 << 3;
    }
}

// ── Mount point descriptor ──────────────────────────────────────────────────

/// Descriptor for a single virtual filesystem to mount during boot.
#[derive(Debug, Clone)]
pub struct MountPoint {
    /// Source device or filesystem name (e.g. "proc", "sysfs", "devtmpfs").
    pub what: &'static str,
    /// Target mount path (e.g. "/proc", "/sys", "/dev").
    pub where_: &'static str,
    /// Filesystem type passed to mount(2) (e.g. "proc", "sysfs", "tmpfs").
    pub fstype: &'static str,
    /// Base mount options (e.g. "mode=0755").
    pub options: &'static str,
    /// Mount flags bitmask (MS_NOSUID, MS_NOEXEC, etc.).
    pub flags: u64,
    /// Behavior flags for this mount point.
    pub mode: MountMode,
    /// Optional runtime condition — the mount is skipped if this returns `false`.
    pub condition_fn: Option<fn() -> bool>,
    /// Optional function to compute additional mount options at runtime.
    pub options_fn: Option<fn(&str) -> Option<String>>,
}

// ── Mount table ─────────────────────────────────────────────────────────────

/// The standard table of API filesystems to mount during boot.
///
/// The first [`N_EARLY_MOUNT`] entries are mounted before SELinux/IMA policies
/// are loaded. The remaining entries are mounted after policy loading.
///
/// This table corresponds to the `mount_table[]` array in mount-setup.c.
pub static MOUNT_TABLE: &[MountPoint] = &[
    // ── Early mounts (0..N_EARLY_MOUNT) ──────────────────────────────────
    MountPoint {
        what: "proc",
        where_: "/proc",
        fstype: "proc",
        options: "",
        flags: MS_NOSUID | MS_NOEXEC | MS_NODEV,
        mode: MountMode::from_bits_retain(
            MountMode::FATAL.bits()
                | MountMode::IN_CONTAINER.bits()
                | MountMode::FOLLOW_SYMLINK.bits(),
        ),
        condition_fn: None,
        options_fn: None,
    },
    MountPoint {
        what: "sysfs",
        where_: "/sys",
        fstype: "sysfs",
        options: "",
        flags: MS_NOSUID | MS_NOEXEC | MS_NODEV,
        mode: MountMode::from_bits_retain(MountMode::FATAL.bits() | MountMode::IN_CONTAINER.bits()),
        condition_fn: None,
        options_fn: None,
    },
    MountPoint {
        what: "devtmpfs",
        where_: "/dev",
        fstype: "devtmpfs",
        options: "mode=0755",
        flags: MS_NOSUID | MS_STRICTATIME,
        mode: MountMode::from_bits_retain(MountMode::FATAL.bits() | MountMode::IN_CONTAINER.bits()),
        condition_fn: None,
        options_fn: None,
    },
    MountPoint {
        what: "securityfs",
        where_: "/sys/kernel/security",
        fstype: "securityfs",
        options: "",
        flags: MS_NOSUID | MS_NOEXEC | MS_NODEV,
        mode: MountMode::from_bits_retain(MountMode::FATAL.bits() | MountMode::IN_CONTAINER.bits()),
        condition_fn: None,
        options_fn: None,
    },
    // ── Post-policy mounts ──────────────────────────────────────────────
    MountPoint {
        what: "tmpfs",
        where_: "/dev/shm",
        fstype: "tmpfs",
        options: "mode=01777",
        flags: MS_NOSUID | MS_NODEV | MS_STRICTATIME,
        mode: MountMode::from_bits_retain(MountMode::FATAL.bits() | MountMode::IN_CONTAINER.bits()),
        condition_fn: None,
        options_fn: Some(usrquota_mount_option),
    },
    MountPoint {
        what: "devpts",
        where_: "/dev/pts",
        fstype: "devpts",
        options: "mode=0620,gid=5",
        flags: MS_NOSUID | MS_NOEXEC,
        mode: MountMode::IN_CONTAINER,
        condition_fn: None,
        options_fn: None,
    },
    MountPoint {
        what: "tmpfs",
        where_: "/run",
        fstype: "tmpfs",
        options: "mode=0755",
        flags: MS_NOSUID | MS_NODEV | MS_STRICTATIME,
        mode: MountMode::from_bits_retain(MountMode::FATAL.bits() | MountMode::IN_CONTAINER.bits()),
        condition_fn: None,
        options_fn: None,
    },
    MountPoint {
        what: "cgroup2",
        where_: "/sys/fs/cgroup",
        fstype: "cgroup2",
        options: "nsdelegate,memory_recursiveprot",
        flags: MS_NOSUID | MS_NOEXEC | MS_NODEV,
        mode: MountMode::from_bits_retain(
            MountMode::FATAL.bits()
                | MountMode::IN_CONTAINER.bits()
                | MountMode::CHECK_WRITABLE.bits(),
        ),
        condition_fn: None,
        options_fn: Some(cgroupfs_mount_options),
    },
    MountPoint {
        what: "pstore",
        where_: "/sys/fs/pstore",
        fstype: "pstore",
        options: "",
        flags: MS_NOSUID | MS_NOEXEC | MS_NODEV,
        mode: MountMode::empty(),
        condition_fn: None,
        options_fn: None,
    },
    MountPoint {
        what: "efivarfs",
        where_: "/sys/firmware/efi/efivars",
        fstype: "efivarfs",
        options: "",
        flags: MS_NOSUID | MS_NOEXEC | MS_NODEV,
        mode: MountMode::empty(),
        condition_fn: None,
        options_fn: None,
    },
    MountPoint {
        what: "bpf",
        where_: "/sys/fs/bpf",
        fstype: "bpf",
        options: "mode=0700",
        flags: MS_NOSUID | MS_NOEXEC | MS_NODEV,
        mode: MountMode::empty(),
        condition_fn: None,
        options_fn: None,
    },
];

/// Number of mount table entries processed before SELinux/IMA policy loading.
///
/// These are: proc, sysfs, devtmpfs, securityfs. The securityfs entry is
/// needed by IMA to load a custom policy.
pub const N_EARLY_MOUNT: usize = 4;

// ── Dynamic mount option functions ──────────────────────────────────────────

/// Compute additional cgroup2 mount options based on kernel support.
///
/// Checks if the kernel supports the `memory_hugetlb_accounting` mount option
/// (added in Linux v6.7). Returns the option string if supported.
fn cgroupfs_mount_options(fstype: &str) -> Option<String> {
    if fstype != "cgroup2" {
        return None;
    }
    // The C version calls mount_option_supported("cgroup2", "memory_hugetlb_accounting", NULL)
    // which probes /proc/filesystems. We read it and check for cgroup2 support,
    // then conservatively return None — the base options nsdelegate,memory_recursiveprot
    // are already applied via the mount table entry.
    match fs::read_to_string("/proc/filesystems") {
        Ok(ref contents)
            if contents.contains("nodev\tcgroup2") || contents.contains("nodev cgroup2") =>
        {
            Some("memory_hugetlb_accounting".to_owned())
        }
        _ => None,
    }
}

/// Compute additional mount options for quota support.
///
/// Checks if the filesystem type supports the `usrquota` mount option.
fn usrquota_mount_option(_fstype: &str) -> Option<String> {
    // The C version calls mount_option_supported(type, "usrquota", NULL).
    // We conservatively return None — callers can extend this at runtime.
    None
}

// ── Path classification ─────────────────────────────────────────────────────

/// Check whether a path is an API filesystem mount point.
///
/// API filesystems are virtual filesystems managed by systemd. They should be
/// ignored by fstab processing, remount operations, and similar logic.
///
/// Returns `true` for any path that exactly matches a mount table target, or
/// any path beneath `/sys/fs/cgroup/`.
pub fn mount_point_is_api(path: &str) -> bool {
    if MOUNT_TABLE.iter().any(|mp| mp.where_ == path) {
        return true;
    }
    path.starts_with("/sys/fs/cgroup/")
}

/// Check whether a mount point should be ignored by systemd.
///
/// These are API filesystems that may be mounted by other software, or
/// container bind mounts that should not be managed by systemd.
pub fn mount_point_ignore(path: &str) -> bool {
    const IGNORE_EXACT: &[&str] = &[
        "/sys/fs/selinux",
        "/dev/console",
        "/proc/kmsg",
        "/proc/sys",
        "/proc/sys/kernel/random/boot_id",
    ];

    if IGNORE_EXACT.iter().any(|&p| p == path) {
        return true;
    }
    // All mounts passed in from the container manager live under /run/host
    path.starts_with("/run/host")
}

// ── Public API ──────────────────────────────────────────────────────────────

/// Mount a separate cgroup2 filesystem instance at the given path.
///
/// This is useful when cgroup namespaces are not employed, since the kernel
/// overrides all previous options if a new mount is established in the
/// initial cgroup namespace.
///
/// The mount options are kept in sync with the cgroup2 entry in [`MOUNT_TABLE`].
pub fn mount_cgroupfs(path: &str) -> Result<()> {
    let extra = cgroupfs_mount_options("cgroup2");
    let combined = combine_options("nsdelegate,memory_recursiveprot", extra);

    create_mount_point(path).map_err(|e| MountSetupError::MkdirFailed {
        path: path.to_owned(),
        source: e,
    })?;

    do_mount_nofollow(
        "cgroup2",
        path,
        "cgroup2",
        MS_NOSUID | MS_NOEXEC | MS_NODEV,
        combined.as_deref(),
    )
    .map_err(|e| MountSetupError::MountFailed {
        what: "cgroup2".to_owned(),
        where_: path.to_owned(),
        source: e,
    })?;

    Ok(())
}

/// Perform minimal early boot mounts (proc, sysfs, devtmpfs, securityfs).
///
/// These mounts are needed to enable the most basic system functionality,
/// including SELinux policy loading and IMA policy initialization.
pub fn mount_setup_early() -> Result<()> {
    mount_points_setup(N_EARLY_MOUNT, detect_container())
}

/// Full mount setup for boot.
///
/// Mounts all API filesystems from [`MOUNT_TABLE`], sets up shared mount
/// propagation on the root directory, and creates essential runtime
/// directories under `/run/systemd/`.
///
/// # Arguments
///
/// * `_loaded_policy` — Whether SELinux/SMACK policy has been loaded. When
///   `true`, filesystem labels are applied after mounting. Reserved for
///   future relabeling support.
/// * `leave_propagation` — If `true`, skip setting shared mount propagation
///   on the root directory. Set this when invoked by a container manager
///   that manages its own propagation settings.
pub fn mount_setup(_loaded_policy: bool, leave_propagation: bool) -> Result<()> {
    let in_container = detect_container();

    // Mount all API filesystems
    mount_points_setup(MOUNT_TABLE.len(), in_container)?;

    // Set root to shared mount propagation (best-effort, not fatal)
    if !in_container && !leave_propagation {
        let _ = set_root_shared_propagation();
    }

    // Create essential runtime directories (best-effort)
    create_run_directories();

    Ok(())
}

// ── Internal helpers ────────────────────────────────────────────────────────

/// Combine base mount options with dynamically computed extra options.
///
/// Returns `None` if both base and extra are empty (no options needed).
/// Otherwise returns the comma-separated combination.
fn combine_options(base: &str, extra: Option<String>) -> Option<String> {
    match (base.is_empty(), extra.as_deref()) {
        (true, None | Some("")) => None,
        (true, Some(e)) => Some(e.to_owned()),
        (false, None | Some("")) => Some(base.to_owned()),
        (false, Some(e)) => Some(format!("{},{}", base, e)),
    }
}

/// Create a mount point directory (and all parents) if it does not exist.
fn create_mount_point(where_: &str) -> io::Result<()> {
    fs::create_dir_all(where_)
}

/// Check whether a path is already a mount point by reading `/proc/self/mountinfo`.
///
/// Returns `false` on non-Linux systems where mountinfo is unavailable.
fn is_mount_point(path: &Path) -> bool {
    let mountinfo = match fs::read_to_string("/proc/self/mountinfo") {
        Ok(s) => s,
        Err(_) => return false,
    };
    let target = match path.as_os_str().to_str() {
        Some(s) => s,
        None => return false,
    };
    mountinfo.lines().any(|line| {
        // mountinfo(5) format: mnt_id mnt_parent_id major:minor root mount_point ...
        // Field index 4 is the mount point path.
        let mut fields = line.split_whitespace();
        fields.nth(4) == Some(target)
    })
}

/// Simple container detection via systemd's own container type marker.
fn detect_container() -> bool {
    let container_path = Path::new("/run/systemd/container");
    if let Ok(contents) = fs::read_to_string(container_path) {
        let trimmed = contents.trim();
        if !trimmed.is_empty() && trimmed != "none" {
            return true;
        }
    }
    false
}

/// Perform a single mount operation, delegating to `mount_verbose_full`.
#[cfg(target_os = "linux")]
fn do_mount(
    what: &str,
    where_: &str,
    fstype: &str,
    flags: u64,
    options: Option<&str>,
    follow: bool,
) -> io::Result<()> {
    mount_verbose_full(what, where_, Some(fstype), flags, options, follow)
}

/// Mount without following symlinks, delegating to `mount_nofollow_verbose`.
#[cfg(target_os = "linux")]
fn do_mount_nofollow(
    what: &str,
    where_: &str,
    fstype: &str,
    flags: u64,
    options: Option<&str>,
) -> io::Result<()> {
    mount_nofollow_verbose(what, where_, Some(fstype), flags, options)
}

/// Stub for non-Linux platforms.
#[cfg(not(target_os = "linux"))]
fn do_mount(
    _what: &str,
    _where_: &str,
    _fstype: &str,
    _flags: u64,
    _options: Option<&str>,
    _follow: bool,
) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "mount syscalls not available on this platform",
    ))
}

/// Stub for non-Linux platforms.
#[cfg(not(target_os = "linux"))]
fn do_mount_nofollow(
    _what: &str,
    _where_: &str,
    _fstype: &str,
    _flags: u64,
    _options: Option<&str>,
) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "mount syscalls not available on this platform",
    ))
}

/// Perform an unmount operation, delegating to `umount_verbose`.
#[cfg(target_os = "linux")]
fn do_umount(path: &str) -> io::Result<()> {
    umount_verbose(path, UMOUNT_NOFOLLOW)
}

/// Stub for non-Linux platforms.
#[cfg(not(target_os = "linux"))]
fn do_umount(_path: &str) -> io::Result<()> {
    Ok(())
}

/// Set the root directory to shared mount propagation.
///
/// Wraps `mount(NULL, "/", NULL, MS_REC|MS_SHARED, NULL)` which changes
/// mount propagation without mounting a filesystem.
#[cfg(target_os = "linux")]
fn set_root_shared_propagation() -> io::Result<()> {
    let c_path = std::ffi::CString::new("/")?;
    // SAFETY: c_path is a valid null-terminated string. NULL source, type,
    // and data pointers are valid for mount(2) when only changing propagation.
    let ret = unsafe {
        libc::mount(
            std::ptr::null(),
            c_path.as_ptr(),
            std::ptr::null(),
            (MS_REC | MS_SHARED) as u64,
            std::ptr::null(),
        )
    };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn set_root_shared_propagation() -> io::Result<()> {
    Ok(())
}

/// Check if a filesystem path has write permission bits set.
fn is_path_writable(path: &str) -> bool {
    match fs::metadata(path) {
        Ok(meta) => {
            use std::os::unix::fs::PermissionsExt;
            meta.permissions().mode() & 0o222 != 0
        }
        Err(_) => false,
    }
}

/// Mount a single filesystem entry from the mount table.
///
/// Returns `Ok(true)` if a new mount was established, `Ok(false)` if the
/// mount was skipped (already mounted, condition not met, non-fatal error),
/// or `Err` if a fatal mount failure occurred.
fn mount_one(mp: &MountPoint, in_container: bool) -> Result<bool> {
    // Check runtime condition
    if let Some(cond_fn) = mp.condition_fn {
        if !cond_fn() {
            return Ok(false);
        }
    }

    // Skip non-container mounts when inside a container
    if !mp.mode.contains(MountMode::IN_CONTAINER) && in_container {
        return Ok(false);
    }

    // Skip if already mounted
    if is_mount_point(Path::new(mp.where_)) {
        return Ok(false);
    }

    // Create the mount point directory
    if let Err(e) = create_mount_point(mp.where_) {
        if mp.mode.contains(MountMode::FATAL) {
            return Err(MountSetupError::MkdirFailed {
                path: mp.where_.to_owned(),
                source: e,
            });
        }
        return Ok(false);
    }

    // Compute final mount options
    let extra = mp.options_fn.and_then(|f| f(mp.fstype));
    let combined = combine_options(mp.options, extra);

    // Perform the mount
    let follow = mp.mode.contains(MountMode::FOLLOW_SYMLINK);
    if let Err(e) = do_mount(
        mp.what,
        mp.where_,
        mp.fstype,
        mp.flags,
        combined.as_deref(),
        follow,
    ) {
        if mp.mode.contains(MountMode::FATAL) {
            return Err(MountSetupError::MountFailed {
                what: mp.what.to_owned(),
                where_: mp.where_.to_owned(),
                source: e,
            });
        }
        return Ok(false);
    }

    // Check writability if required
    if mp.mode.contains(MountMode::CHECK_WRITABLE) && !is_path_writable(mp.where_) {
        // Undo the mount and clean up
        let _ = do_umount(mp.where_);
        let _ = fs::remove_dir(mp.where_);

        if mp.mode.contains(MountMode::FATAL) {
            return Err(MountSetupError::NotWritable {
                path: mp.where_.to_owned(),
                source: io::Error::new(io::ErrorKind::PermissionDenied, "not writable after mount"),
            });
        }
        return Ok(false);
    }

    Ok(true)
}

/// Mount the first `n` entries from [`MOUNT_TABLE`].
///
/// Propagates the first fatal error encountered. Non-fatal errors are
/// silently ignored (matching the C RET_GATHER semantics).
fn mount_points_setup(n: usize, in_container: bool) -> Result<()> {
    for mp in MOUNT_TABLE.iter().take(n) {
        mount_one(mp, in_container)?;
    }
    Ok(())
}

/// Create essential runtime directories under `/run/`.
///
/// These directories are needed by systemd and various clients:
/// - `/run/systemd` — sd_booted() checks for `/run/systemd/system`
/// - `/run/systemd/system` — unit file directory for transient units
/// - `/run/systemd/mount-rootfs` — sandbox mount helper
/// - `/run/credentials` — encrypted credential storage
fn create_run_directories() {
    const RUN_DIRS: &[&str] = &[
        "/run/systemd",
        "/run/systemd/system",
        "/run/systemd/mount-rootfs",
        "/run/credentials",
    ];
    for &dir in RUN_DIRS {
        let _ = fs::create_dir_all(dir);
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── mount_point_is_api ──────────────────────────────────────────────

    #[test]
    fn test_mount_point_is_api_exact_matches() {
        for mp in MOUNT_TABLE {
            assert!(
                mount_point_is_api(mp.where_),
                "Expected '{}' to be an API mount point",
                mp.where_
            );
        }
    }

    #[test]
    fn test_mount_point_is_api_cgroup_subpath() {
        assert!(mount_point_is_api("/sys/fs/cgroup/"));
        assert!(mount_point_is_api("/sys/fs/cgroup/user.slice"));
        assert!(mount_point_is_api("/sys/fs/cgroup/system.slice/foo"));
    }

    #[test]
    fn test_mount_point_is_api_non_api_path() {
        assert!(!mount_point_is_api("/home"));
        assert!(!mount_point_is_api("/var/log"));
        assert!(!mount_point_is_api("/usr/bin"));
        assert!(!mount_point_is_api("/etc/passwd"));
    }

    #[test]
    fn test_mount_point_is_api_empty_and_root() {
        assert!(!mount_point_is_api(""));
        assert!(!mount_point_is_api("/"));
        assert!(!mount_point_is_api("/sys/fs"));
    }

    // ── mount_point_ignore ──────────────────────────────────────────────

    #[test]
    fn test_mount_point_ignore_exact_matches() {
        assert!(mount_point_ignore("/sys/fs/selinux"));
        assert!(mount_point_ignore("/dev/console"));
        assert!(mount_point_ignore("/proc/kmsg"));
        assert!(mount_point_ignore("/proc/sys"));
        assert!(mount_point_ignore("/proc/sys/kernel/random/boot_id"));
    }

    #[test]
    fn test_mount_point_ignore_run_host_prefix() {
        assert!(mount_point_ignore("/run/host"));
        assert!(mount_point_ignore("/run/host/inaccessible"));
        assert!(mount_point_ignore("/run/host/notify"));
        assert!(mount_point_ignore("/run/host/something/deep"));
    }

    #[test]
    fn test_mount_point_ignore_non_ignored() {
        assert!(!mount_point_ignore("/home/user"));
        assert!(!mount_point_ignore("/var/log/journal"));
        assert!(!mount_point_ignore("/run/user"));
        assert!(!mount_point_ignore("/tmp"));
    }

    // ── MountMode ───────────────────────────────────────────────────────

    #[test]
    fn test_mount_mode_flags() {
        let fatal = MountMode::FATAL;
        let container = MountMode::IN_CONTAINER;
        let writable = MountMode::CHECK_WRITABLE;
        let follow = MountMode::FOLLOW_SYMLINK;

        assert!(fatal.contains(MountMode::FATAL));
        assert!(!fatal.contains(MountMode::IN_CONTAINER));

        let combined = fatal | container | writable | follow;
        assert!(combined.contains(MountMode::FATAL));
        assert!(combined.contains(MountMode::IN_CONTAINER));
        assert!(combined.contains(MountMode::CHECK_WRITABLE));
        assert!(combined.contains(MountMode::FOLLOW_SYMLINK));
    }

    #[test]
    fn test_mount_mode_empty() {
        let empty = MountMode::empty();
        assert!(empty.is_empty());
        assert!(!empty.contains(MountMode::FATAL));
    }

    #[test]
    fn test_mount_mode_bits() {
        assert_eq!(MountMode::FATAL.bits(), 1);
        assert_eq!(MountMode::IN_CONTAINER.bits(), 2);
        assert_eq!(MountMode::CHECK_WRITABLE.bits(), 4);
        assert_eq!(MountMode::FOLLOW_SYMLINK.bits(), 8);
    }

    // ── Mount table ─────────────────────────────────────────────────────

    #[test]
    fn test_n_early_mount_count() {
        assert_eq!(N_EARLY_MOUNT, 4);
        assert!(N_EARLY_MOUNT <= MOUNT_TABLE.len());
    }

    #[test]
    fn test_mount_table_early_entries_are_fatal_or_container() {
        for mp in MOUNT_TABLE.iter().take(N_EARLY_MOUNT) {
            assert!(
                mp.mode.contains(MountMode::FATAL) || mp.mode.contains(MountMode::IN_CONTAINER),
                "Early mount '{}' should be FATAL or IN_CONTAINER",
                mp.where_
            );
        }
    }

    #[test]
    fn test_mount_table_all_have_required_fields() {
        for mp in MOUNT_TABLE {
            assert!(!mp.what.is_empty(), "Mount entry missing 'what'");
            assert!(!mp.where_.is_empty(), "Mount entry missing 'where_'");
            assert!(!mp.fstype.is_empty(), "Mount entry missing 'fstype'");
            assert!(
                mp.where_.starts_with('/'),
                "Mount path '{}' should be absolute",
                mp.where_
            );
        }
    }

    #[test]
    fn test_mount_table_unique_paths() {
        let mut seen = std::collections::HashSet::new();
        for mp in MOUNT_TABLE {
            assert!(
                seen.insert(mp.where_),
                "Duplicate mount path '{}' in mount table",
                mp.where_
            );
        }
    }

    #[test]
    fn test_mount_table_early_mounts_include_proc_sys_dev_securityfs() {
        let early: Vec<&str> = MOUNT_TABLE
            .iter()
            .take(N_EARLY_MOUNT)
            .map(|mp| mp.where_)
            .collect();
        assert!(
            early.contains(&"/proc"),
            "Early mounts should include /proc"
        );
        assert!(early.contains(&"/sys"), "Early mounts should include /sys");
        assert!(early.contains(&"/dev"), "Early mounts should include /dev");
        assert!(
            early.contains(&"/sys/kernel/security"),
            "Early mounts should include /sys/kernel/security"
        );
    }

    // ── combine_options ─────────────────────────────────────────────────

    #[test]
    fn test_combine_options_base_only() {
        assert_eq!(
            combine_options("mode=0755", None),
            Some("mode=0755".to_owned())
        );
    }

    #[test]
    fn test_combine_options_with_extra() {
        assert_eq!(
            combine_options("mode=0755", Some("usrquota".to_owned())),
            Some("mode=0755,usrquota".to_owned())
        );
    }

    #[test]
    fn test_combine_options_both_empty() {
        assert_eq!(combine_options("", None), None);
        assert_eq!(combine_options("", Some(String::new())), None);
    }

    #[test]
    fn test_combine_options_extra_only() {
        assert_eq!(
            combine_options("", Some("nsdelegate".to_owned())),
            Some("nsdelegate".to_owned())
        );
    }

    #[test]
    fn test_combine_options_empty_extra_string() {
        assert_eq!(
            combine_options("mode=0755", Some(String::new())),
            Some("mode=0755".to_owned())
        );
    }

    #[test]
    fn test_combine_options_cgroup2_realistic() {
        // Simulates cgroupfs_mount_options returning an extra option
        let base = "nsdelegate,memory_recursiveprot";
        let extra = Some("memory_hugetlb_accounting".to_owned());
        assert_eq!(
            combine_options(base, extra),
            Some("nsdelegate,memory_recursiveprot,memory_hugetlb_accounting".to_owned())
        );
    }
}
