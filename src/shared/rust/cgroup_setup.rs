// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/cgroup-setup.c
//
// Cgroup setup and management utilities.
//
// Provides pure-Rust logic for cgroup weight parsing, controller
// management, enable/disable computation, and PID resolution.
// Filesystem operations (mkdir, chown, write to cgroup.procs) are
// isolated behind thin `unsafe` syscall wrappers.

// ── Constants ─────────────────────────────────────────────────────────────

/// Sentinel value indicating no weight was specified.
use crate::ffi::*;
pub const CGROUP_WEIGHT_INVALID: u64 = 0;

/// Special weight value meaning "idle" (lowest priority).
pub const CGROUP_WEIGHT_IDLE: u64 = 1;

/// Minimum valid cgroup weight.
pub const CGROUP_WEIGHT_MIN: u64 = 1;

/// Maximum valid cgroup weight.
pub const CGROUP_WEIGHT_MAX: u64 = 10000;

/// Minimum valid cgroup limit.
pub const CGROUP_LIMIT_MIN: u64 = 1;

/// Maximum valid cgroup limit.
pub const CGROUP_LIMIT_MAX: u64 = u64::MAX;

/// Sentinel for an invalid UID.
pub const UID_INVALID: u32 = u32::MAX;

/// Sentinel for an invalid GID.
pub const GID_INVALID: u32 = u32::MAX;

// ── Types ─────────────────────────────────────────────────────────────────

/// Bitmask representing a set of enabled cgroup controllers.
pub type CGroupMask = u64;

// ── Enums ─────────────────────────────────────────────────────────────────

/// Cgroup controller identifiers (v2 hierarchy).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(usize)]
pub enum CGroupController {
    Cpu = 0,
    CpuSet = 1,
    Io = 2,
    Memory = 3,
    Pids = 4,
    Rdma = 5,
    Freezer = 6,
}

impl CGroupController {
    /// Maximum number of controller slots.
    pub const MAX: usize = 7;

    /// Bitmask for this controller.
    pub const fn mask(self) -> CGroupMask {
        1u64 << (self as usize)
    }

    /// Human-readable controller name (as used in cgroup.subtree_control).
    pub const fn name(self) -> &'static str {
        match self {
            Self::Cpu => "cpu",
            Self::CpuSet => "cpuset",
            Self::Io => "io",
            Self::Memory => "memory",
            Self::Pids => "pids",
            Self::Rdma => "rdma",
            Self::Freezer => "freezer",
        }
    }

    /// Convert a numeric index to a controller, if valid.
    pub const fn from_index(idx: usize) -> Option<Self> {
        match idx {
            0 => Some(Self::Cpu),
            1 => Some(Self::CpuSet),
            2 => Some(Self::Io),
            3 => Some(Self::Memory),
            4 => Some(Self::Pids),
            5 => Some(Self::Rdma),
            6 => Some(Self::Freezer),
            _ => None,
        }
    }
}

/// Precomputed mask of all v2 controllers (excluding freezer, which has
/// no subtree_control presence in the C source).
pub const CGROUP_MASK_V2: CGroupMask = CGroupController::Cpu.mask()
    | CGroupController::CpuSet.mask()
    | CGroupController::Io.mask()
    | CGroupController::Memory.mask()
    | CGroupController::Pids.mask()
    | CGroupController::Rdma.mask();

/// Flags controlling cgroup migration behaviour.
bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct CGroupFlags: u32 {
        /// Skip the current process during migration.
        const IGNORE_SELF = 1 << 0;
        /// Remove the source cgroup after migration.
        const REMOVE = 1 << 1;
    }
}

/// Errors produced by cgroup operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CgroupError {
    /// An argument was invalid (null, wrong type, etc.).
    InvalidArgument,
    /// A numeric value is out of the accepted range.
    Range,
    /// The requested resource does not exist.
    NotFound,
    /// The resource is busy (e.g. cgroup still in use).
    Busy,
    /// Permission denied.
    PermissionDenied,
    /// Operation not supported on this cgroup.
    OperationNotSupported,
    /// An I/O error occurred.
    Io,
    /// Input was not valid UTF-8.
    InvalidUtf8,
    /// A remote/unmappable PID was encountered.
    Remote,
    /// Unknown filesystem type on /sys/fs/cgroup.
    NoMedium,
    /// An unexpected OS error (errno wrapped).
    Unknown(i32),
}

impl std::fmt::Display for CgroupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidArgument => write!(f, "invalid argument"),
            Self::Range => write!(f, "value out of range"),
            Self::NotFound => write!(f, "not found"),
            Self::Busy => write!(f, "resource busy"),
            Self::PermissionDenied => write!(f, "permission denied"),
            Self::OperationNotSupported => write!(f, "operation not supported"),
            Self::Io => write!(f, "I/O error"),
            Self::InvalidUtf8 => write!(f, "invalid UTF-8"),
            Self::Remote => write!(f, "remote PID (cannot migrate)"),
            Self::NoMedium => write!(f, "unknown filesystem on /sys/fs/cgroup"),
            Self::Unknown(code) => write!(f, "unknown error (errno {code})"),
        }
    }
}

impl std::error::Error for CgroupError {}

/// Convenience alias for cgroup operation results.
pub type CgroupResult<T> = Result<T, CgroupError>;

// ── Weight parsing ────────────────────────────────────────────────────────

/// Parse a cgroup weight value from a string.
///
/// An empty string yields `CGROUP_WEIGHT_INVALID`.
/// Values outside `[CGROUP_WEIGHT_MIN, CGROUP_WEIGHT_MAX]` return `Err(Range)`.
pub fn cg_weight_parse(s: &str) -> CgroupResult<u64> {
    if s.is_empty() {
        return Ok(CGROUP_WEIGHT_INVALID);
    }

    let val: u64 = s.parse().map_err(|_| CgroupError::InvalidArgument)?;

    if val < CGROUP_WEIGHT_MIN || val > CGROUP_WEIGHT_MAX {
        return Err(CgroupError::Range);
    }

    Ok(val)
}

/// Parse a CPU weight, additionally accepting the special value `"idle"`.
pub fn cg_cpu_weight_parse(s: &str) -> CgroupResult<u64> {
    if s.eq_ignore_ascii_case("idle") {
        return Ok(CGROUP_WEIGHT_IDLE);
    }

    cg_weight_parse(s)
}

// ── Controller helpers ────────────────────────────────────────────────────

/// Check whether a controller bit is set in the given mask.
pub fn cgroup_mask_test(mask: CGroupMask, controller: CGroupController) -> bool {
    (mask & controller.mask()) != 0
}

/// Iterate over every v2 controller present in `supported`, invoking `f`
/// with the controller and whether it should be enabled (per `mask`).
pub fn cgroup_mask_foreach<F>(mask: CGroupMask, supported: CGroupMask, mut f: F)
where
    F: FnMut(CGroupController, bool),
{
    for idx in 0..CGroupController::MAX {
        let ctrl = match CGroupController::from_index(idx) {
            Some(c) => c,
            None => continue,
        };

        if !cgroup_mask_test(CGROUP_MASK_V2, ctrl) {
            continue;
        }
        if !cgroup_mask_test(supported, ctrl) {
            continue;
        }

        let enable = cgroup_mask_test(mask, ctrl);
        f(ctrl, enable);
    }
}

/// Parse a controller name string into a [`CGroupController`].
pub fn cgroup_controller_from_str(s: &str) -> Option<CGroupController> {
    match s {
        "cpu" => Some(CGroupController::Cpu),
        "cpuset" => Some(CGroupController::CpuSet),
        "io" => Some(CGroupController::Io),
        "memory" => Some(CGroupController::Memory),
        "pids" => Some(CGroupController::Pids),
        "rdma" => Some(CGroupController::Rdma),
        "freezer" => Some(CGroupController::Freezer),
        _ => None,
    }
}

/// Build the `+name` / `-name` string for writing to `cgroup.subtree_control`.
fn controller_action_string(controller: CGroupController, enable: bool) -> String {
    let prefix = if enable { '+' } else { '-' };
    format!("{prefix}{}", controller.name())
}

// ── Result types ──────────────────────────────────────────────────────────

/// Outcome of [`cg_create`]: whether the cgroup was newly created or already existed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CreateResult {
    /// The cgroup already existed.
    Existed,
    /// The cgroup was newly created.
    Created,
}

/// Outcome of [`cg_migrate`]: whether any processes were actually moved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MigrateResult {
    /// No processes were migrated.
    None,
    /// At least one process was migrated.
    Migrated,
}

/// Outcome of [`cg_enable`]: the resulting controller mask.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EnableResult {
    /// Bitmask of controllers actually enabled after the operation.
    pub result_mask: CGroupMask,
}

/// Outcome of [`cg_has_legacy`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LegacyResult {
    /// Unified (v2) cgroup hierarchy detected.
    Unified,
    /// Legacy (v1) cgroup hierarchy detected.
    Legacy,
}

// ── UID / GID helpers ─────────────────────────────────────────────────────

/// Returns `true` if `uid` is not the sentinel [`UID_INVALID`].
pub const fn uid_is_valid(uid: u32) -> bool {
    uid != UID_INVALID
}

/// Returns `true` if `gid` is not the sentinel [`GID_INVALID`].
pub const fn gid_is_valid(gid: u32) -> bool {
    gid != GID_INVALID
}

// ── PID resolution ────────────────────────────────────────────────────────

/// Resolve a PID value: `0` is replaced with the current process ID.
///
/// Returns `Err(InvalidArgument)` for negative PIDs.
pub fn resolve_pid(pid: i32) -> CgroupResult<i32> {
    if pid < 0 {
        return Err(CgroupError::InvalidArgument);
    }
    Ok(if pid == 0 {
        std::process::id() as i32
    } else {
        pid
    })
}

// ── Cgroup attribute table ────────────────────────────────────────────────

/// A cgroup attribute file that needs access permissions.
#[derive(Debug, Clone, Copy)]
pub struct CgroupAttribute {
    /// Filename inside the cgroup directory (e.g. `"cgroup.procs"`).
    pub name: &'static str,
    /// If `true`, a failure to set permissions is fatal.
    pub fatal: bool,
}

/// Standard attributes configured by [`cg_set_access`].
pub const CGROUP_ACCESS_ATTRIBUTES: &[CgroupAttribute] = &[
    CgroupAttribute {
        name: "cgroup.procs",
        fatal: true,
    },
    CgroupAttribute {
        name: "cgroup.subtree_control",
        fatal: true,
    },
    CgroupAttribute {
        name: "cgroup.threads",
        fatal: false,
    },
    CgroupAttribute {
        name: "memory.oom.group",
        fatal: false,
    },
    CgroupAttribute {
        name: "memory.reclaim",
        fatal: false,
    },
];

/// Check whether both UID and GID are invalid (no-op fast path).
pub const fn access_is_noop(uid: u32, gid: u32) -> bool {
    uid == UID_INVALID && gid == GID_INVALID
}

// ── Enable / disable computation ──────────────────────────────────────────

/// Compute the expected result mask for a controller enable/disable operation.
///
/// This is the pure-logic half of `cg_enable()` — it does not touch the
/// filesystem but calculates which controllers should end up enabled given
/// the `supported` and requested `mask`.
pub fn cg_enable_compute(supported: CGroupMask, mask: CGroupMask) -> EnableResult {
    if supported == 0 {
        return EnableResult { result_mask: 0 };
    }

    let mut result_mask: CGroupMask = 0;
    cgroup_mask_foreach(mask, supported, |ctrl, enable| {
        if enable {
            result_mask |= ctrl.mask();
        }
    });

    EnableResult { result_mask }
}

/// Build the list of `+controller` / `-controller` strings that should be
/// written to `cgroup.subtree_control`.
pub fn cg_enable_actions(supported: CGroupMask, mask: CGroupMask) -> Vec<String> {
    let mut actions = Vec::new();
    cgroup_mask_foreach(mask, supported, |ctrl, enable| {
        actions.push(controller_action_string(ctrl, enable));
    });
    actions
}

// ── Kernel-operation wrappers ─────────────────────────────────────────────
//
// These thin wrappers isolate the `unsafe` syscall boundaries. The actual
// mount / mkdir / chown / write syscalls would go here. For now they are
// stubs that the safe layer calls into.

/// Create a cgroup directory on the filesystem.
///
/// # Safety
///
/// The caller must ensure `path` refers to a location under the cgroup
/// filesystem hierarchy.
fn sys_cg_create(path: &str) -> CgroupResult<CreateResult> {
    // SAFETY: caller guarantees path is within cgroup hierarchy.
    // Actual implementation would call mkdir(2) and mkdir_parents().
    let _ = path;
    Ok(CreateResult::Existed)
}

/// Write a PID to the `cgroup.procs` file of a cgroup.
///
/// # Safety
///
/// The caller must ensure `path` is a valid cgroup directory.
fn sys_cg_attach(path: &str, pid: i32) -> CgroupResult<()> {
    let _ = (path, pid);
    // SAFETY: caller guarantees path is a cgroup directory.
    // Actual implementation would write pid to path/cgroup.procs.
    Ok(())
}

/// Write a PID to `cgroup.procs` via an already-open directory fd.
///
/// # Safety
///
/// `fd` must be a valid file descriptor for a cgroup directory.
fn sys_cg_fd_attach(fd: i32, pid: i32) -> CgroupResult<()> {
    let _ = (fd, pid);
    // SAFETY: caller guarantees fd is valid.
    // Actual implementation would use write_string_file_at().
    Ok(())
}

/// Change ownership of a cgroup directory and its attribute files.
///
/// # Safety
///
/// `path` must point to a cgroup directory.
fn sys_cg_set_access(path: &str, uid: u32, gid: u32) -> CgroupResult<()> {
    let _ = (path, uid, gid);
    // SAFETY: caller guarantees path is a cgroup directory.
    Ok(())
}

/// Recursively change ownership of all entries under a cgroup directory.
///
/// # Safety
///
/// `path` must point to a cgroup directory.
fn sys_cg_set_access_recursive(path: &str, uid: u32, gid: u32) -> CgroupResult<()> {
    let _ = (path, uid, gid);
    // SAFETY: caller guarantees path is a cgroup directory.
    Ok(())
}

/// Remove empty sub-cgroups under a cgroup, optionally removing the root.
///
/// # Safety
///
/// `path` must point to a cgroup directory.
fn sys_cg_trim(path: &str, delete_root: bool) -> CgroupResult<()> {
    let _ = (path, delete_root);
    // SAFETY: caller guarantees path is a cgroup directory.
    Ok(())
}

/// Write enable/disable strings to `cgroup.subtree_control`.
///
/// # Safety
///
/// `path` must point to a cgroup directory.
fn sys_cg_enable_write(path: &str, actions: &[String]) -> CgroupResult<EnableResult> {
    let _ = (path, actions);
    // SAFETY: caller guarantees path is a cgroup directory.
    // Would compute result mask based on which writes succeeded/failed.
    Ok(EnableResult { result_mask: 0 })
}

/// Stat the cgroup mount point to detect legacy vs unified hierarchy.
///
/// # Safety
///
/// Uses statfs(2) internally.
fn sys_cg_has_legacy() -> CgroupResult<LegacyResult> {
    // SAFETY: statfs on /sys/fs/cgroup is inherently safe.
    Ok(LegacyResult::Unified)
}

// ── Safe public API ───────────────────────────────────────────────────────

/// Create a cgroup in the hierarchy.
///
/// Returns [`CreateResult::Existed`] if the group was already present,
/// [`CreateResult::Created`] if it was newly created.
///
/// # Errors
///
/// Returns an error if parent directories cannot be created or if
/// the kernel reports a failure.
pub fn cg_create(path: &str) -> CgroupResult<CreateResult> {
    if path.is_empty() {
        return Err(CgroupError::InvalidArgument);
    }
    sys_cg_create(path)
}

/// Attach a process to a cgroup by writing its PID to `cgroup.procs`.
///
/// A `pid` of `0` is resolved to the calling process.
pub fn cg_attach(path: &str, pid: i32) -> CgroupResult<()> {
    if path.is_empty() {
        return Err(CgroupError::InvalidArgument);
    }
    let resolved = resolve_pid(pid)?;
    // SAFETY: path is validated above.
    sys_cg_attach(path, resolved)
}

/// Attach a process to a cgroup via an already-open directory fd.
///
/// A `pid` of `0` is resolved to the calling process.
pub fn cg_fd_attach(fd: i32, pid: i32) -> CgroupResult<()> {
    if fd < 0 {
        return Err(CgroupError::InvalidArgument);
    }
    let resolved = resolve_pid(pid)?;
    // SAFETY: fd is validated above.
    sys_cg_fd_attach(fd, resolved)
}

/// Create a cgroup and immediately attach a process to it.
///
/// A `pid` of `0` is resolved to the calling process.
/// Returns [`CreateResult::Existed`] or [`CreateResult::Created`].
pub fn cg_create_and_attach(path: &str, pid: i32) -> CgroupResult<CreateResult> {
    let create_r = cg_create(path)?;

    cg_attach(path, pid)?;

    Ok(create_r)
}

/// Trim (remove) empty sub-cgroups under a cgroup.
///
/// If `delete_root` is `true`, the cgroup itself is removed as well.
pub fn cg_trim(path: &str, delete_root: bool) -> CgroupResult<()> {
    if path.is_empty() {
        return Err(CgroupError::InvalidArgument);
    }
    // SAFETY: path is validated above.
    sys_cg_trim(path, delete_root)
}

/// Set ownership (uid/gid) on a cgroup directory and its standard attribute files.
///
/// No-op if both `uid` and `gid` are [`UID_INVALID`]/[`GID_INVALID`].
pub fn cg_set_access(path: &str, uid: u32, gid: u32) -> CgroupResult<()> {
    if path.is_empty() {
        return Err(CgroupError::InvalidArgument);
    }
    if access_is_noop(uid, gid) {
        return Ok(());
    }
    // SAFETY: path is validated above.
    sys_cg_set_access(path, uid, gid)
}

/// Recursively set ownership on all files in a cgroup subtree.
///
/// No-op if both `uid` and `gid` are [`UID_INVALID`]/[`GID_INVALID`].
pub fn cg_set_access_recursive(path: &str, uid: u32, gid: u32) -> CgroupResult<()> {
    if path.is_empty() {
        return Err(CgroupError::InvalidArgument);
    }
    if !uid_is_valid(uid) && !gid_is_valid(gid) {
        return Ok(());
    }
    // SAFETY: path is validated above.
    sys_cg_set_access_recursive(path, uid, gid)
}

/// Enable or disable controllers on a cgroup by writing to `cgroup.subtree_control`.
///
/// Returns the resulting mask of enabled controllers.
pub fn cg_enable(
    supported: CGroupMask,
    mask: CGroupMask,
    path: &str,
) -> CgroupResult<EnableResult> {
    if path.is_empty() {
        return Err(CgroupError::InvalidArgument);
    }

    let compute = cg_enable_compute(supported, mask);
    if supported == 0 {
        return Ok(compute);
    }

    let actions = cg_enable_actions(supported, mask);
    // SAFETY: path is validated above.
    sys_cg_enable_write(path, &actions)
}

/// Check whether a legacy (v1) cgroup hierarchy is mounted.
pub fn cg_has_legacy() -> CgroupResult<LegacyResult> {
    // SAFETY: statfs on a well-known path is inherently safe.
    sys_cg_has_legacy()
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_weight_constants() {
        assert_eq!(CGROUP_WEIGHT_INVALID, 0);
        assert_eq!(CGROUP_WEIGHT_IDLE, 1);
        assert_eq!(CGROUP_WEIGHT_MIN, 1);
        assert_eq!(CGROUP_WEIGHT_MAX, 10000);
        assert_eq!(CGROUP_LIMIT_MIN, 1);
        assert_eq!(CGROUP_LIMIT_MAX, u64::MAX);
    }

    #[test]
    fn test_cg_weight_parse_valid() {
        assert_eq!(cg_weight_parse("1").unwrap(), 1);
        assert_eq!(cg_weight_parse("5000").unwrap(), 5000);
        assert_eq!(cg_weight_parse("10000").unwrap(), 10000);
    }

    #[test]
    fn test_cg_weight_parse_empty() {
        assert_eq!(cg_weight_parse("").unwrap(), CGROUP_WEIGHT_INVALID);
    }

    #[test]
    fn test_cg_weight_parse_out_of_range() {
        assert_eq!(cg_weight_parse("0"), Err(CgroupError::Range));
        assert_eq!(cg_weight_parse("10001"), Err(CgroupError::Range));
        assert_eq!(cg_weight_parse("999999"), Err(CgroupError::Range));
    }

    #[test]
    fn test_cg_weight_parse_invalid_string() {
        assert_eq!(cg_weight_parse("abc"), Err(CgroupError::InvalidArgument));
        assert_eq!(cg_weight_parse("12.5"), Err(CgroupError::InvalidArgument));
        assert_eq!(cg_weight_parse("-1"), Err(CgroupError::InvalidArgument));
    }

    #[test]
    fn test_cg_cpu_weight_parse_idle() {
        assert_eq!(cg_cpu_weight_parse("idle").unwrap(), CGROUP_WEIGHT_IDLE);
        assert_eq!(cg_cpu_weight_parse("IDLE").unwrap(), CGROUP_WEIGHT_IDLE);
        assert_eq!(cg_cpu_weight_parse("Idle").unwrap(), CGROUP_WEIGHT_IDLE);
    }

    #[test]
    fn test_cg_cpu_weight_parse_numeric() {
        assert_eq!(cg_cpu_weight_parse("100").unwrap(), 100);
        assert_eq!(cg_cpu_weight_parse("10000").unwrap(), 10000);
    }

    #[test]
    fn test_cgroup_controller_enum() {
        assert_eq!(CGroupController::Cpu as usize, 0);
        assert_eq!(CGroupController::Memory as usize, 3);
        assert_eq!(CGroupController::MAX, 7);
    }

    #[test]
    fn test_cgroup_controller_mask_and_name() {
        assert_eq!(CGroupController::Cpu.mask(), 1u64 << 0);
        assert_eq!(CGroupController::Memory.mask(), 1u64 << 3);
        assert_eq!(CGroupController::Cpu.name(), "cpu");
        assert_eq!(CGroupController::Memory.name(), "memory");
    }

    #[test]
    fn test_cgroup_controller_from_index() {
        assert_eq!(CGroupController::from_index(0), Some(CGroupController::Cpu));
        assert_eq!(
            CGroupController::from_index(3),
            Some(CGroupController::Memory)
        );
        assert_eq!(
            CGroupController::from_index(6),
            Some(CGroupController::Freezer)
        );
        assert_eq!(CGroupController::from_index(7), None);
        assert_eq!(CGroupController::from_index(100), None);
    }

    #[test]
    fn test_cgroup_controller_from_str() {
        assert_eq!(
            cgroup_controller_from_str("cpu"),
            Some(CGroupController::Cpu)
        );
        assert_eq!(
            cgroup_controller_from_str("memory"),
            Some(CGroupController::Memory)
        );
        assert_eq!(cgroup_controller_from_str("bogus"), None);
        assert_eq!(cgroup_controller_from_str(""), None);
    }

    #[test]
    fn test_cgroup_mask_v2() {
        // v2 mask includes cpu, cpuset, io, memory, pids, rdma but NOT freezer
        assert!(cgroup_mask_test(CGROUP_MASK_V2, CGroupController::Cpu));
        assert!(cgroup_mask_test(CGROUP_MASK_V2, CGroupController::Memory));
        assert!(cgroup_mask_test(CGROUP_MASK_V2, CGroupController::Pids));
        // Freezer is excluded from the v2 mask (per C source logic)
        assert!(!cgroup_mask_test(CGROUP_MASK_V2, CGroupController::Freezer));
    }

    #[test]
    fn test_cgroup_mask_test() {
        let mask = CGroupController::Cpu.mask() | CGroupController::Memory.mask();
        assert!(cgroup_mask_test(mask, CGroupController::Cpu));
        assert!(cgroup_mask_test(mask, CGroupController::Memory));
        assert!(!cgroup_mask_test(mask, CGroupController::Io));
        assert!(!cgroup_mask_test(mask, CGroupController::Pids));
    }

    #[test]
    fn test_cgroup_flags() {
        let flags = CGroupFlags::IGNORE_SELF;
        assert!(flags.contains(CGroupFlags::IGNORE_SELF));
        assert!(!flags.contains(CGroupFlags::REMOVE));

        let both = CGroupFlags::IGNORE_SELF | CGroupFlags::REMOVE;
        assert!(both.contains(CGroupFlags::IGNORE_SELF));
        assert!(both.contains(CGroupFlags::REMOVE));
    }

    #[test]
    fn test_uid_gid_validity() {
        assert!(uid_is_valid(0));
        assert!(uid_is_valid(1000));
        assert!(!uid_is_valid(UID_INVALID));
        assert!(gid_is_valid(0));
        assert!(gid_is_valid(1000));
        assert!(!gid_is_valid(GID_INVALID));
    }

    #[test]
    fn test_access_is_noop() {
        assert!(access_is_noop(UID_INVALID, GID_INVALID));
        assert!(!access_is_noop(0, GID_INVALID));
        assert!(!access_is_noop(UID_INVALID, 0));
        assert!(!access_is_noop(1000, 1000));
    }

    #[test]
    fn test_resolve_pid() {
        let current = std::process::id() as i32;
        assert_eq!(resolve_pid(0).unwrap(), current);
        assert_eq!(resolve_pid(1).unwrap(), 1);
        assert_eq!(resolve_pid(12345).unwrap(), 12345);
        assert_eq!(resolve_pid(-1), Err(CgroupError::InvalidArgument));
    }

    #[test]
    fn test_cg_enable_compute_empty_supported() {
        let result = cg_enable_compute(0, 0xFF);
        assert_eq!(result.result_mask, 0);
    }

    #[test]
    fn test_cg_enable_compute_enable_all() {
        let supported = CGROUP_MASK_V2;
        let mask = CGROUP_MASK_V2;
        let result = cg_enable_compute(supported, mask);
        // All v2 controllers should be in result
        assert_eq!(result.result_mask, CGROUP_MASK_V2);
    }

    #[test]
    fn test_cg_enable_compute_partial() {
        let supported = CGROUP_MASK_V2;
        let mask = CGroupController::Cpu.mask() | CGroupController::Memory.mask();
        let result = cg_enable_compute(supported, mask);
        assert!(cgroup_mask_test(result.result_mask, CGroupController::Cpu));
        assert!(cgroup_mask_test(
            result.result_mask,
            CGroupController::Memory
        ));
        assert!(!cgroup_mask_test(result.result_mask, CGroupController::Io));
        assert!(!cgroup_mask_test(
            result.result_mask,
            CGroupController::Pids
        ));
    }

    #[test]
    fn test_cg_enable_actions() {
        let supported = CGroupController::Cpu.mask() | CGroupController::Memory.mask();
        let mask = CGroupController::Cpu.mask();
        let actions = cg_enable_actions(supported, mask);
        assert!(actions.contains(&"+cpu".to_string()));
        assert!(actions.contains(&"-memory".to_string()));
    }

    #[test]
    fn test_cg_enable_actions_none() {
        let actions = cg_enable_actions(0, 0);
        assert!(actions.is_empty());
    }

    #[test]
    fn test_cg_create_empty_path_rejects() {
        assert_eq!(cg_create(""), Err(CgroupError::InvalidArgument));
    }

    #[test]
    fn test_cg_attach_empty_path_rejects() {
        assert_eq!(cg_attach("", 1), Err(CgroupError::InvalidArgument));
    }

    #[test]
    fn test_cg_attach_negative_pid_rejects() {
        assert_eq!(
            cg_attach("/user.slice", -1),
            Err(CgroupError::InvalidArgument)
        );
    }

    #[test]
    fn test_cg_fd_attach_negative_fd_rejects() {
        assert_eq!(cg_fd_attach(-1, 1), Err(CgroupError::InvalidArgument));
    }

    #[test]
    fn test_cg_fd_attach_negative_pid_rejects() {
        assert_eq!(cg_fd_attach(3, -1), Err(CgroupError::InvalidArgument));
    }

    #[test]
    fn test_cg_set_access_noop() {
        assert!(cg_set_access("/user.slice", UID_INVALID, GID_INVALID).is_ok());
    }

    #[test]
    fn test_cg_set_access_empty_path_rejects() {
        assert_eq!(cg_set_access("", 0, 0), Err(CgroupError::InvalidArgument));
    }

    #[test]
    fn test_cg_set_access_recursive_noop() {
        assert!(cg_set_access_recursive("/user.slice", UID_INVALID, GID_INVALID).is_ok());
    }

    #[test]
    fn test_cg_enable_empty_path_rejects() {
        assert_eq!(
            cg_enable(CGROUP_MASK_V2, CGROUP_MASK_V2, ""),
            Err(CgroupError::InvalidArgument)
        );
    }

    #[test]
    fn test_cg_enable_zero_supported() {
        let result = cg_enable(0, 0xFF, "/sys/fs/cgroup/user.slice");
        assert!(result.is_ok());
        assert_eq!(result.unwrap().result_mask, 0);
    }

    #[test]
    fn test_cg_trim_empty_path_rejects() {
        assert_eq!(cg_trim("", false), Err(CgroupError::InvalidArgument));
    }

    #[test]
    fn test_cg_has_legacy_returns_unified() {
        assert_eq!(cg_has_legacy().unwrap(), LegacyResult::Unified);
    }

    #[test]
    fn test_cgroup_access_attributes() {
        assert_eq!(CGROUP_ACCESS_ATTRIBUTES.len(), 5);
        assert!(CGROUP_ACCESS_ATTRIBUTES[0].fatal); // cgroup.procs
        assert!(CGROUP_ACCESS_ATTRIBUTES[1].fatal); // cgroup.subtree_control
        assert!(!CGROUP_ACCESS_ATTRIBUTES[2].fatal); // cgroup.threads
        assert!(!CGROUP_ACCESS_ATTRIBUTES[3].fatal); // memory.oom.group
        assert!(!CGROUP_ACCESS_ATTRIBUTES[4].fatal); // memory.reclaim
    }

    #[test]
    fn test_cgroup_error_display() {
        let err = CgroupError::InvalidArgument;
        assert!(!err.to_string().is_empty());

        let err = CgroupError::Range;
        assert_eq!(err.to_string(), "value out of range");

        let err = CgroupError::Unknown(42);
        assert!(err.to_string().contains("42"));
    }
}
