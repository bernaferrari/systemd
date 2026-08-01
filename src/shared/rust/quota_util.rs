// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/quota-util.c, src/shared/quota-util.h
//
// Disk quota utilities for project quota management via the quotactl
// syscall.  Provides safe Rust wrappers around the kernel's
// `struct dqblk` and the `quotactl(2)` / `quotactl_fd(2)` interfaces,
// with automatic fallback from fd-based to path-based quotactl on
// kernels older than 5.14.

use std::ffi::c_void;

use crate::ffi::Errno;

// ── Error type ───────────────────────────────────────────────────────────

/// Errors that can occur during quota operations.
///
/// Covers the common errno categories returned by the quotactl family of
/// syscalls.  Unknown errno values are preserved in the [`RawErrno`]
/// variant so callers can inspect them if needed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuotaError {
    /// Kernel or filesystem does not support this operation (ENOSYS / EOPNOTSUPP).
    NotSupported,
    /// Insufficient privileges — EPERM or EACCES.
    Permission,
    /// Quota entry not found — ESRCH.
    NotFound,
    /// File descriptor does not back a block device — ENODEV.
    NoBlockDevice,
    /// State is not recoverable — ENOTRECOVERABLE.
    NotRecoverable,
    /// A raw (negative) errno that does not match any specific variant.
    RawErrno(i32),
}

impl std::fmt::Display for QuotaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotSupported => write!(f, "quota operation not supported"),
            Self::Permission => write!(f, "permission denied for quota operation"),
            Self::NotFound => write!(f, "quota entry not found"),
            Self::NoBlockDevice => write!(f, "no block device for file descriptor"),
            Self::NotRecoverable => write!(f, "quota state not recoverable"),
            Self::RawErrno(e) => write!(f, "quota error (errno {e})"),
        }
    }
}

impl std::error::Error for QuotaError {}

impl QuotaError {
    /// Classify a negative errno return value into a [`QuotaError`].
    ///
    /// Matches the same categories used by `ERRNO_IS_NEG_NOT_SUPPORTED()`
    /// and `ERRNO_IS_NEG_PRIVILEGE()` in the C source.
    #[inline]
    pub(crate) fn from_neg_errno(r: i32) -> Self {
        match r {
            e if e == Errno::ENOSYS.to_neg_errno() || e == Errno::EOPNOTSUPP.to_neg_errno() => {
                Self::NotSupported
            }
            e if e == Errno::EPERM.to_neg_errno() || e == Errno::EACCES.to_neg_errno() => {
                Self::Permission
            }
            e if e == Errno::ESRCH.to_neg_errno() => Self::NotFound,
            e if e == Errno::ENODEV.to_neg_errno() => Self::NoBlockDevice,
            e if e == Errno::ENOTRECOVERABLE.to_neg_errno() => Self::NotRecoverable,
            e => Self::RawErrno(e),
        }
    }

    /// Convert back to the conventional negative errno representation used
    /// by the C layer.
    #[inline]
    pub fn to_neg_errno(self) -> i32 {
        match self {
            Self::NotSupported => Errno::ENOSYS.to_neg_errno(),
            Self::Permission => Errno::EPERM.to_neg_errno(),
            Self::NotFound => Errno::ESRCH.to_neg_errno(),
            Self::NoBlockDevice => Errno::ENODEV.to_neg_errno(),
            Self::NotRecoverable => Errno::ENOTRECOVERABLE.to_neg_errno(),
            Self::RawErrno(e) => e,
        }
    }
}

// ── Quota valid-field flags ─────────────────────────────────────────────

bitflags::bitflags! {
    /// Flags indicating which fields in [`Dqblk`] are valid.
    ///
    /// Matches `QIF_*` from `<linux/dqblk_xfs.h>`.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct QuotaInfoFields: u32 {
        const BLIMITS = 1 << 0;
        const SPACE   = 1 << 1;
        const ILIMITS = 1 << 2;
        const INODES  = 1 << 3;
        const BTIME   = 1 << 4;
        const ITIME   = 1 << 5;
    }
}

/// Backward-compatible flag constants.
pub const QIF_BLIMITS: u32 = QuotaInfoFields::BLIMITS.bits();
pub const QIF_SPACE: u32 = QuotaInfoFields::SPACE.bits();
pub const QIF_ILIMITS: u32 = QuotaInfoFields::ILIMITS.bits();
pub const QIF_INODES: u32 = QuotaInfoFields::INODES.bits();
pub const QIF_BTIME: u32 = QuotaInfoFields::BTIME.bits();
pub const QIF_ITIME: u32 = QuotaInfoFields::ITIME.bits();

/// Bitmask of all six quota-info fields, used by [`Dqblk::is_populated`].
pub const QIF_ALL: u32 = QuotaInfoFields::all().bits();

// ── Quota type ──────────────────────────────────────────────────────────

/// Quota type identifiers, matching `<linux/quota.h>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum QuotaType {
    /// Per-user quota (USRQUOTA).
    User = 0,
    /// Per-group quota (GRPQUOTA).
    Group = 1,
    /// Per-project quota (PRJQUOTA).
    Project = 2,
}

impl QuotaType {
    #[inline]
    pub const fn as_raw(self) -> u32 {
        self as u32
    }

    /// Total number of quota types.
    pub const COUNT: usize = 3;
}

impl std::fmt::Display for QuotaType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::User => write!(f, "usrquota"),
            Self::Group => write!(f, "grpquota"),
            Self::Project => write!(f, "prjquota"),
        }
    }
}

impl std::str::FromStr for QuotaType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "usrquota" | "usr" => Ok(Self::User),
            "grpquota" | "grp" => Ok(Self::Group),
            "prjquota" | "prj" => Ok(Self::Project),
            _ => Err(format!("unknown quota type: {s}")),
        }
    }
}

/// Backward-compatible constant for the project quota type.
pub const PRJQUOTA: u32 = QuotaType::Project as u32;

// ── Dqblk ───────────────────────────────────────────────────────────────

/// Disk quota information block, matching the kernel `struct dqblk`.
///
/// All fields use `u64` for uniformity; the kernel structure mixes
/// `u64` / `__kernel_ulong_t` depending on architecture, but the
/// `#[repr(C)]` layout with all-`u64` members is ABI-compatible on
/// all supported platforms.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[repr(C)]
pub struct Dqblk {
    pub dqb_bhardlimit: u64,
    pub dqb_bsoftlimit: u64,
    pub dqb_curspace: u64,
    pub dqb_ihardlimit: u64,
    pub dqb_isoftlimit: u64,
    pub dqb_curinodes: u64,
    pub dqb_btime: u64,
    pub dqb_itime: u64,
    pub dqb_valid: u32,
}

impl Dqblk {
    /// All six field bits that must be present for a quota to be considered
    /// "populated".  Matches the `QIF_BLIMITS|QIF_SPACE|QIF_ILIMITS|
    /// QIF_INODES|QIF_BTIME|QIF_ITIME` mask from `quota_dqblk_is_populated()`.
    const REQUIRED_FIELDS: QuotaInfoFields = QuotaInfoFields::all();

    /// Returns `true` if *all* required validity flags are set **and** at
    /// least one quota value (limit, usage, or timer) is non-zero.
    ///
    /// This is the Rust equivalent of `quota_dqblk_is_populated()` from the
    /// C source.
    pub fn is_populated(&self) -> bool {
        let fields = QuotaInfoFields::from_bits_truncate(self.dqb_valid);
        fields.contains(Self::REQUIRED_FIELDS)
            && (self.dqb_bhardlimit > 0
                || self.dqb_bsoftlimit > 0
                || self.dqb_ihardlimit > 0
                || self.dqb_isoftlimit > 0
                || self.dqb_curspace > 0
                || self.dqb_curinodes > 0
                || self.dqb_btime > 0
                || self.dqb_itime > 0)
    }

    /// Total disk space consumed, in bytes.
    pub fn space_used(&self) -> u64 {
        self.dqb_curspace
    }

    /// Total number of inodes consumed.
    pub fn inodes_used(&self) -> u64 {
        self.dqb_curinodes
    }

    /// Whether any block-usage limit is configured.
    pub fn has_block_limit(&self) -> bool {
        self.dqb_bhardlimit > 0 || self.dqb_bsoftlimit > 0
    }

    /// Whether any inode-usage limit is configured.
    pub fn has_inode_limit(&self) -> bool {
        self.dqb_ihardlimit > 0 || self.dqb_isoftlimit > 0
    }
}

// ── Command construction ────────────────────────────────────────────────

/// Quota subcommand constants from `<linux/quota.h>`.
pub mod subcmd {
    /// Retrieve quota limits and current usage.
    pub const Q_GETQUOTA: u32 = 0x800007;
    /// Set quota limits.
    pub const Q_SETQUOTA: u32 = 0x800008;
    /// Get next quota ID that has data.
    pub const Q_GETNEXTQUOTA: u32 = 0x800009;
}

/// Build a quotactl command word from *subcmd* and *quota_type*.
///
/// This is the safe Rust equivalent of `QCMD_FIXED()` from
/// `<linux/quota.h>`, avoiding the undefined behaviour that arises
/// when the C macro produces a value larger than `INT_MAX` on 32-bit
/// `int` platforms.
#[inline]
pub fn qcmd_fixed(subcmd: u32, quota_type: QuotaType) -> i32 {
    ((subcmd << 8) | (quota_type.as_raw() & 0x00FF)) as i32
}

// ── Syscall layer (Linux only) ──────────────────────────────────────────

/// Invoke the path-based `quotactl(2)` syscall.
///
/// Returns `Ok(())` on success, or a [`QuotaError`] classified from the
/// current errno on failure.
///
/// # Safety
///
/// * `special` must be a valid, NUL-terminated C string pointer, **or** null
///   (the latter is only meaningful for the fd-based variant).
/// * `addr` must point to a properly aligned, initialised `Dqblk` value.
#[cfg(target_os = "linux")]
unsafe fn quotactl_path_syscall(
    cmd: i32,
    special: *const libc::c_char,
    id: i32,
    addr: *mut c_void,
) -> Result<(), QuotaError> {
    // SAFETY: the caller guarantees both pointers meet quotactl()'s
    // command-specific contract. libc exposes the data argument as a byte
    // pointer, so this is only a representation-preserving pointer cast.
    let r = unsafe_ffi!(libc::quotactl(cmd, special, id, addr.cast()));
    if r < 0 {
        return Err(QuotaError::from_neg_errno(
            -(crate::ffi::get_errno()) as i32,
        ));
    }
    Ok(())
}

/// Invoke the fd-based `quotactl_fd(2)` syscall (Linux ≥ 5.4).
///
/// Returns `Ok(())` on success, or a [`QuotaError`] on failure.
/// If the kernel does not implement this syscall, returns
/// [`QuotaError::NotSupported`] so the caller can fall back.
///
/// # Safety
///
/// `addr` must point to a properly aligned, initialised `Dqblk` value.
#[cfg(target_os = "linux")]
unsafe fn quotactl_fd_syscall(
    fd: i32,
    cmd: i32,
    id: i32,
    addr: *mut c_void,
) -> Result<(), QuotaError> {
    // SAFETY: the caller guarantees addr meets the command-specific quotactl_fd contract.
    let r = unsafe_ffi!(libc::syscall(libc::SYS_quotactl_fd, fd, cmd, id, addr));
    if r < 0 {
        return Err(QuotaError::from_neg_errno(
            -(crate::ffi::get_errno()) as i32,
        ));
    }
    Ok(())
}

/// Retrieve the device number that backs the given file descriptor.
#[cfg(target_os = "linux")]
fn get_block_device_fd(fd: i32) -> Result<libc::dev_t, QuotaError> {
    // SAFETY: `stat` is stack-allocated and its lifetime does not escape
    // this function.  `fstat` return value is checked before `st` is read.
    unsafe_ffi!({
        let mut st: libc::stat = std::mem::zeroed();
        if libc::fstat(fd, &mut st) < 0 {
            return Err(QuotaError::from_neg_errno(
                -(crate::ffi::get_errno()) as i32,
            ));
        }
        Ok(st.st_dev)
    })
}

/// Resolve a block device number to its `/dev` node path.
#[cfg(target_os = "linux")]
fn devname_from_devnum(devno: libc::dev_t) -> Result<std::ffi::CString, QuotaError> {
    // Linux does not provide BSD's devname_r(). Reuse the port's device
    // resolver, which performs the same block-device-number-to-node lookup
    // required by the C fallback before calling path-based quotactl(2).
    let path = crate::device_util::devname_from_devnum(
        crate::device_util::DeviceMode::Block,
        devno as u64,
    )
    .map_err(|_| QuotaError::NoBlockDevice)?;
    std::ffi::CString::new(path).map_err(|_| QuotaError::NoBlockDevice)
}

/// Emulates `quotactl_fd()` on older kernels (< 5.14) that lack it.
///
/// 1. Tries the fd-based syscall first.
/// 2. If the kernel returns `ENOSYS` / `EOPNOTSUPP`, resolves the block
///    device backing `fd` and retries with the path-based `quotactl(2)`.
///
/// This mirrors `quotactl_fd_with_fallback()` from the C source.
#[cfg(target_os = "linux")]
fn quotactl_fd_with_fallback(
    fd: i32,
    cmd: i32,
    id: i32,
    req: &mut Dqblk,
) -> Result<(), QuotaError> {
    let addr = req as *mut Dqblk as *mut c_void;
    // Try the newer fd-based syscall first.
    // SAFETY: `addr` was derived from the live, properly aligned `req` and
    // remains valid throughout this function.
    match unsafe_ffi!(quotactl_fd_syscall(fd, cmd, id, addr)) {
        Ok(()) => return Ok(()),
        Err(QuotaError::NotSupported) => { /* fall through to path-based */ }
        Err(e) => return Err(e),
    }

    // Fallback: resolve block device path from fd.
    let devno = get_block_device_fd(fd)?;
    if devno == 0 {
        return Err(QuotaError::NoBlockDevice);
    }
    let devnode = devname_from_devnum(devno)?;

    // SAFETY: `devnode` is a valid NUL-terminated CString and `addr` still
    // points to the live `req` that meets the command-specific quota ABI.
    unsafe_ffi!(quotactl_path_syscall(cmd, devnode.as_ptr(), id, addr))
}

// ── Safe public API ─────────────────────────────────────────────────────

/// Query project quota for `proj_id` on the filesystem backing `fd`.
///
/// # Returns
///
/// * `Ok(Some(dqblk))` — quota information was retrieved successfully.
/// * `Ok(None)` — the quota is not found, the operation is not supported,
///   or the caller lacks privileges (mirrors the C function's `false` path).
/// * `Err(QuotaError)` — any other failure.
///
/// This is the safe Rust equivalent of `quota_query_proj_id()` from the C
/// source.
#[cfg(target_os = "linux")]
pub fn quota_query_proj_id(fd: i32, proj_id: u32) -> Result<Option<Dqblk>, QuotaError> {
    let cmd = qcmd_fixed(subcmd::Q_GETQUOTA, QuotaType::Project);
    let mut req = Dqblk::default();

    match quotactl_fd_with_fallback(fd, cmd, proj_id as i32, &mut req) {
        Ok(()) => Ok(Some(req)),
        Err(QuotaError::NotFound | QuotaError::NotSupported | QuotaError::Permission) => Ok(None),
        Err(e) => Err(e),
    }
}

/// Verify (and prepare for) setting a project ID recursively.
///
/// When `verify_exclusive` is `true`:
///
/// 1. Queries the quota for `proj_id`.
/// 2. Returns [`Err(QuotaError::NotRecoverable)`] if no inodes are
///    currently associated with the project ID.
/// 3. Returns `Ok(false)` if more than one inode already uses this ID.
/// 4. Returns `Ok(true)` if exactly one inode uses it — safe to proceed.
///
/// When `verify_exclusive` is `false`, immediately returns `Ok(true)`.
///
/// This is the safe Rust equivalent of `quota_proj_id_set_recursive()` from
/// the C source.  The actual recursive `FS_IOC_FSSETXATTR` ioctl calls are
/// left to the caller (or the C layer) since they are filesystem-specific.
#[cfg(target_os = "linux")]
pub fn quota_proj_id_set_recursive(
    fd: i32,
    proj_id: u32,
    verify_exclusive: bool,
) -> Result<bool, QuotaError> {
    if !verify_exclusive {
        return Ok(true);
    }

    let cmd = qcmd_fixed(subcmd::Q_GETQUOTA, QuotaType::Project);
    let mut req = Dqblk::default();

    quotactl_fd_with_fallback(fd, cmd, proj_id as i32, &mut req)?;

    if req.dqb_curinodes == 0 {
        return Err(QuotaError::NotRecoverable);
    }
    if req.dqb_curinodes != 1 {
        return Ok(false);
    }

    Ok(true)
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── QuotaType ────────────────────────────────────────────────────

    #[test]
    fn test_quota_type_display() {
        assert_eq!(QuotaType::User.to_string(), "usrquota");
        assert_eq!(QuotaType::Group.to_string(), "grpquota");
        assert_eq!(QuotaType::Project.to_string(), "prjquota");
    }

    #[test]
    fn test_quota_type_from_str() {
        assert_eq!("usrquota".parse::<QuotaType>().unwrap(), QuotaType::User);
        assert_eq!("usr".parse::<QuotaType>().unwrap(), QuotaType::User);
        assert_eq!("grpquota".parse::<QuotaType>().unwrap(), QuotaType::Group);
        assert_eq!("grp".parse::<QuotaType>().unwrap(), QuotaType::Group);
        assert_eq!("prjquota".parse::<QuotaType>().unwrap(), QuotaType::Project);
        assert_eq!("prj".parse::<QuotaType>().unwrap(), QuotaType::Project);
    }

    #[test]
    fn test_quota_type_from_str_invalid() {
        assert!("invalid".parse::<QuotaType>().is_err());
        assert!("".parse::<QuotaType>().is_err());
        assert!("USRQUOTA".parse::<QuotaType>().is_err());
        assert!("project".parse::<QuotaType>().is_err());
    }

    #[test]
    fn test_quota_type_as_raw() {
        assert_eq!(QuotaType::User.as_raw(), 0);
        assert_eq!(QuotaType::Group.as_raw(), 1);
        assert_eq!(QuotaType::Project.as_raw(), 2);
    }

    #[test]
    fn test_quota_type_equality() {
        assert_eq!(QuotaType::User, QuotaType::User);
        assert_ne!(QuotaType::User, QuotaType::Group);
        assert_ne!(QuotaType::Group, QuotaType::Project);
    }

    // ── QuotaInfoFields ─────────────────────────────────────────────

    #[test]
    fn test_quota_info_fields_bits() {
        assert_eq!(QuotaInfoFields::BLIMITS.bits(), 1);
        assert_eq!(QuotaInfoFields::SPACE.bits(), 2);
        assert_eq!(QuotaInfoFields::ILIMITS.bits(), 4);
        assert_eq!(QuotaInfoFields::INODES.bits(), 8);
        assert_eq!(QuotaInfoFields::BTIME.bits(), 16);
        assert_eq!(QuotaInfoFields::ITIME.bits(), 32);
    }

    #[test]
    fn test_quota_info_fields_combination() {
        let combined = QuotaInfoFields::BLIMITS | QuotaInfoFields::SPACE;
        assert!(combined.contains(QuotaInfoFields::BLIMITS));
        assert!(combined.contains(QuotaInfoFields::SPACE));
        assert!(!combined.contains(QuotaInfoFields::ILIMITS));
    }

    #[test]
    fn test_quota_info_fields_all() {
        let all = QuotaInfoFields::all();
        assert_eq!(all.bits(), 0x3F);
        assert_eq!(all.bits(), QIF_ALL);
        assert!(all.contains(QuotaInfoFields::BLIMITS));
        assert!(all.contains(QuotaInfoFields::ITIME));
    }

    // ── Backward-compatible constants ───────────────────────────────

    #[test]
    fn test_backward_compat_constants() {
        assert_eq!(QIF_BLIMITS, QuotaInfoFields::BLIMITS.bits());
        assert_eq!(QIF_SPACE, QuotaInfoFields::SPACE.bits());
        assert_eq!(QIF_ILIMITS, QuotaInfoFields::ILIMITS.bits());
        assert_eq!(QIF_INODES, QuotaInfoFields::INODES.bits());
        assert_eq!(QIF_BTIME, QuotaInfoFields::BTIME.bits());
        assert_eq!(QIF_ITIME, QuotaInfoFields::ITIME.bits());
        assert_eq!(PRJQUOTA, 2);
    }

    // ── Dqblk ──────────────────────────────────────────────────────

    #[test]
    fn test_dqblk_default_not_populated() {
        let dq = Dqblk::default();
        assert!(!dq.is_populated());
        assert_eq!(dq.space_used(), 0);
        assert_eq!(dq.inodes_used(), 0);
        assert!(!dq.has_block_limit());
        assert!(!dq.has_inode_limit());
    }

    #[test]
    fn test_dqblk_populated_with_bhardlimit() {
        let dq = Dqblk {
            dqb_valid: QuotaInfoFields::all().bits(),
            dqb_bhardlimit: 1024,
            ..Default::default()
        };
        assert!(dq.is_populated());
        assert!(dq.has_block_limit());
    }

    #[test]
    fn test_dqblk_populated_with_bsoftlimit() {
        let dq = Dqblk {
            dqb_valid: QuotaInfoFields::all().bits(),
            dqb_bsoftlimit: 512,
            ..Default::default()
        };
        assert!(dq.is_populated());
        assert!(dq.has_block_limit());
    }

    #[test]
    fn test_dqblk_populated_with_ihardlimit() {
        let dq = Dqblk {
            dqb_valid: QuotaInfoFields::all().bits(),
            dqb_ihardlimit: 100,
            ..Default::default()
        };
        assert!(dq.is_populated());
        assert!(dq.has_inode_limit());
    }

    #[test]
    fn test_dqblk_populated_with_isoftlimit() {
        let dq = Dqblk {
            dqb_valid: QuotaInfoFields::all().bits(),
            dqb_isoftlimit: 50,
            ..Default::default()
        };
        assert!(dq.is_populated());
        assert!(dq.has_inode_limit());
    }

    #[test]
    fn test_dqblk_populated_with_curspace() {
        let dq = Dqblk {
            dqb_valid: QuotaInfoFields::all().bits(),
            dqb_curspace: 4096,
            ..Default::default()
        };
        assert!(dq.is_populated());
        assert_eq!(dq.space_used(), 4096);
    }

    #[test]
    fn test_dqblk_populated_with_curinodes() {
        let dq = Dqblk {
            dqb_valid: QuotaInfoFields::all().bits(),
            dqb_curinodes: 7,
            ..Default::default()
        };
        assert!(dq.is_populated());
        assert_eq!(dq.inodes_used(), 7);
    }

    #[test]
    fn test_dqblk_populated_with_btime() {
        let dq = Dqblk {
            dqb_valid: QuotaInfoFields::all().bits(),
            dqb_btime: 86400,
            ..Default::default()
        };
        assert!(dq.is_populated());
    }

    #[test]
    fn test_dqblk_populated_with_itime() {
        let dq = Dqblk {
            dqb_valid: QuotaInfoFields::all().bits(),
            dqb_itime: 604800,
            ..Default::default()
        };
        assert!(dq.is_populated());
    }

    #[test]
    fn test_dqblk_not_populated_missing_flags() {
        // Only BLIMITS set — missing 5 other required fields.
        let dq = Dqblk {
            dqb_valid: QuotaInfoFields::BLIMITS.bits(),
            dqb_bhardlimit: 9999,
            ..Default::default()
        };
        assert!(!dq.is_populated());
    }

    #[test]
    fn test_dqblk_not_populated_all_flags_zero_values() {
        let dq = Dqblk {
            dqb_valid: QuotaInfoFields::all().bits(),
            ..Default::default()
        };
        // All quota values are zero despite all flags being set.
        assert!(!dq.is_populated());
    }

    #[test]
    fn test_dqblk_populated_per_field_exhaustive() {
        let all_bits = QuotaInfoFields::all().bits();
        type Setter = fn(&mut Dqblk);
        let setters: &[(&str, Setter)] = &[
            ("bhardlimit", |d| d.dqb_bhardlimit = 1),
            ("bsoftlimit", |d| d.dqb_bsoftlimit = 1),
            ("ihardlimit", |d| d.dqb_ihardlimit = 1),
            ("isoftlimit", |d| d.dqb_isoftlimit = 1),
            ("curspace", |d| d.dqb_curspace = 1),
            ("curinodes", |d| d.dqb_curinodes = 1),
            ("btime", |d| d.dqb_btime = 1),
            ("itime", |d| d.dqb_itime = 1),
        ];
        for (name, setter) in setters {
            let mut dq = Dqblk {
                dqb_valid: all_bits,
                ..Default::default()
            };
            setter(&mut dq);
            assert!(dq.is_populated(), "should be populated when {name} > 0");
        }
    }

    #[test]
    fn test_dqblk_equality() {
        let a = Dqblk::default();
        let b = Dqblk::default();
        assert_eq!(a, b);

        let c = Dqblk {
            dqb_bhardlimit: 1,
            ..Default::default()
        };
        assert_ne!(a, c);
    }

    // ── qcmd_fixed ─────────────────────────────────────────────────

    #[test]
    fn test_qcmd_fixed_encodes_type_in_low_byte() {
        for qt in [QuotaType::User, QuotaType::Group, QuotaType::Project] {
            let cmd = qcmd_fixed(subcmd::Q_GETQUOTA, qt);
            assert_eq!(
                (cmd as u32) & 0xFF,
                qt.as_raw(),
                "low byte mismatch for {qt:?}"
            );
        }
    }

    #[test]
    fn test_qcmd_fixed_shifts_subcmd() {
        let cmd = qcmd_fixed(subcmd::Q_GETQUOTA, QuotaType::Project);
        let expected = ((subcmd::Q_GETQUOTA << 8) | QuotaType::Project.as_raw()) as i32;
        assert_eq!(cmd, expected);
    }

    #[test]
    fn test_qcmd_fixed_different_subcmds() {
        let cmd_get = qcmd_fixed(subcmd::Q_GETQUOTA, QuotaType::User);
        let cmd_set = qcmd_fixed(subcmd::Q_SETQUOTA, QuotaType::User);
        assert_ne!(cmd_get, cmd_set);
        // High bytes should differ (subcmd part).
        assert_ne!((cmd_get as u32) >> 8, (cmd_set as u32) >> 8);
        // Low bytes should be identical (type part).
        assert_eq!((cmd_get as u32) & 0xFF, (cmd_set as u32) & 0xFF);
    }

    // ── QuotaError ─────────────────────────────────────────────────

    #[test]
    fn test_quota_error_from_neg_errno_not_supported() {
        assert_eq!(
            QuotaError::from_neg_errno(Errno::ENOSYS.to_neg_errno()),
            QuotaError::NotSupported,
        );
        assert_eq!(
            QuotaError::from_neg_errno(Errno::EOPNOTSUPP.to_neg_errno()),
            QuotaError::NotSupported,
        );
    }

    #[test]
    fn test_quota_error_from_neg_errno_permission() {
        assert_eq!(
            QuotaError::from_neg_errno(Errno::EPERM.to_neg_errno()),
            QuotaError::Permission,
        );
        assert_eq!(
            QuotaError::from_neg_errno(Errno::EACCES.to_neg_errno()),
            QuotaError::Permission,
        );
    }

    #[test]
    fn test_quota_error_from_neg_errno_specific() {
        assert_eq!(
            QuotaError::from_neg_errno(Errno::ESRCH.to_neg_errno()),
            QuotaError::NotFound,
        );
        assert_eq!(
            QuotaError::from_neg_errno(Errno::ENODEV.to_neg_errno()),
            QuotaError::NoBlockDevice,
        );
        assert_eq!(
            QuotaError::from_neg_errno(Errno::ENOTRECOVERABLE.to_neg_errno()),
            QuotaError::NotRecoverable,
        );
    }

    #[test]
    fn test_quota_error_from_neg_errno_raw() {
        let err = QuotaError::from_neg_errno(Errno::EINVAL.to_neg_errno());
        assert_eq!(err, QuotaError::RawErrno(-22));
    }

    #[test]
    fn test_quota_error_to_neg_errno_roundtrip() {
        let cases = [
            QuotaError::NotSupported,
            QuotaError::Permission,
            QuotaError::NotFound,
            QuotaError::NoBlockDevice,
            QuotaError::NotRecoverable,
        ];
        for variant in cases {
            let neg = variant.to_neg_errno();
            assert!(neg < 0, "to_neg_errno should return negative: {neg}");
            assert_eq!(
                QuotaError::from_neg_errno(neg),
                variant,
                "roundtrip failed for {variant:?}"
            );
        }
    }

    #[test]
    fn test_quota_error_raw_roundtrip() {
        let raw = QuotaError::RawErrno(-99);
        assert_eq!(raw.to_neg_errno(), -99);
        assert_eq!(QuotaError::from_neg_errno(-99), QuotaError::RawErrno(-99));
    }

    #[test]
    fn test_quota_error_display() {
        assert!(!QuotaError::NotSupported.to_string().is_empty());
        assert!(!QuotaError::Permission.to_string().is_empty());
        assert!(!QuotaError::NotFound.to_string().is_empty());
        assert!(!QuotaError::NoBlockDevice.to_string().is_empty());
        assert!(!QuotaError::NotRecoverable.to_string().is_empty());
        assert!(!QuotaError::RawErrno(-1).to_string().is_empty());
    }

    #[test]
    fn test_quota_error_is_std_error() {
        let err: Box<dyn std::error::Error> = Box::new(QuotaError::NotSupported);
        assert!(err.to_string().contains("not supported"));
    }

    // ── Subcmd constants ───────────────────────────────────────────

    #[test]
    fn test_subcmd_constants_are_distinct() {
        assert_ne!(subcmd::Q_GETQUOTA, subcmd::Q_SETQUOTA);
        assert_ne!(subcmd::Q_SETQUOTA, subcmd::Q_GETNEXTQUOTA);
        assert_ne!(subcmd::Q_GETQUOTA, subcmd::Q_GETNEXTQUOTA);
    }

    #[test]
    fn test_subcmd_getquota_value() {
        // Matches <linux/quota.h>: #define Q_GETQUOTA  0x800007
        assert_eq!(subcmd::Q_GETQUOTA, 0x800007);
    }

    // ── Edge cases ─────────────────────────────────────────────────

    #[test]
    fn test_dqblk_max_values() {
        let mut dq = Dqblk {
            dqb_bhardlimit: u64::MAX,
            dqb_bsoftlimit: u64::MAX,
            dqb_curspace: u64::MAX,
            dqb_ihardlimit: u64::MAX,
            dqb_isoftlimit: u64::MAX,
            dqb_curinodes: u64::MAX,
            dqb_btime: u64::MAX,
            dqb_itime: u64::MAX,
            dqb_valid: QuotaInfoFields::all().bits(),
        };
        assert!(dq.is_populated());
        assert!(dq.has_block_limit());
        assert!(dq.has_inode_limit());
        assert_eq!(dq.space_used(), u64::MAX);
        assert_eq!(dq.inodes_used(), u64::MAX);
    }

    #[test]
    fn test_dqblk_partial_flags_not_populated() {
        let dq = Dqblk {
            dqb_valid: (QuotaInfoFields::BLIMITS
                | QuotaInfoFields::SPACE
                | QuotaInfoFields::ILIMITS)
                .bits(),
            dqb_bhardlimit: 1,
            ..Default::default()
        };
        // Missing INODES, BTIME, ITIME flags.
        assert!(!dq.is_populated());
    }
}
