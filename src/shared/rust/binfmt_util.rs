// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/binfmt-util.c, src/shared/binfmt-util.h
//
// Binary format (binfmt_misc) utilities.
//
// Provides functions to check whether the binfmt_misc filesystem is mounted
// and writable, whether binary format rules are enabled, and to disable all
// registered binfmt_misc entries (typically during shutdown to release file
// descriptors pinned by rules using the "F" flag).

// ── Constants ─────────────────────────────────────────────────────────────

/// Path to the binfmt_misc filesystem mount point.
pub const BINFMT_MISC_PATH: &str = "/proc/sys/fs/binfmt_misc";

/// Path to the binfmt_misc status control file.
pub const BINFMT_STATUS_PATH: &str = "/proc/sys/fs/binfmt_misc/status";

/// Linux filesystem magic number for binfmt_misc ("BINM").
pub const BINFMTFS_MAGIC: u64 = 0x4249_4E4D;

/// Value written to the status file to disable all binfmt entries.
pub const BINFMT_DISABLE_VALUE: &str = "-1";

// ── Status ────────────────────────────────────────────────────────────────

/// Represents the enabled/disabled state of the binfmt_misc subsystem.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinfmtStatus {
    /// Binary format rules are active.
    Enabled,
    /// Binary format rules have been deactivated.
    Disabled,
}

impl BinfmtStatus {
    /// Parse a binfmt_misc status string as read from the status file.
    ///
    /// Accepts `"enabled"` or `"disabled"` with optional leading/trailing
    /// whitespace. Returns `None` for unrecognised input.
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim() {
            "enabled" => Some(BinfmtStatus::Enabled),
            "disabled" => Some(BinfmtStatus::Disabled),
            _ => None,
        }
    }

    /// Returns `true` if the status is [`Enabled`](BinfmtStatus::Enabled).
    pub fn is_enabled(self) -> bool {
        matches!(self, BinfmtStatus::Enabled)
    }
}

impl std::fmt::Display for BinfmtStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BinfmtStatus::Enabled => f.write_str("enabled"),
            BinfmtStatus::Disabled => f.write_str("disabled"),
        }
    }
}

// ── Errors ────────────────────────────────────────────────────────────────

/// Errors produced by binfmt_misc operations.
#[derive(Debug)]
pub enum BinfmtError {
    /// An I/O error occurred.
    Io(std::io::Error),
    /// The status file contains unrecognised content.
    InvalidStatus(String),
}

impl std::fmt::Display for BinfmtError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BinfmtError::Io(ref e) => write!(f, "I/O error: {e}"),
            BinfmtError::InvalidStatus(ref content) => {
                write!(f, "invalid binfmt_misc status: {content:?}")
            }
        }
    }
}

impl std::error::Error for BinfmtError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            BinfmtError::Io(ref e) => Some(e),
            BinfmtError::InvalidStatus(_) => None,
        }
    }
}

impl From<std::io::Error> for BinfmtError {
    fn from(err: std::io::Error) -> Self {
        BinfmtError::Io(err)
    }
}

// ── Internal helpers ──────────────────────────────────────────────────────

/// Check whether an I/O error represents a refused filesystem write.
///
/// Covers `EROFS` (read-only filesystem), `EACCES` (permission denied),
/// and `EPERM` (operation not permitted).
fn is_fs_write_refused(err: &std::io::Error) -> bool {
    matches!(
        err.raw_os_error(),
        Some(libc::EROFS) | Some(libc::EACCES) | Some(libc::EPERM)
    )
}

/// Check whether opening the binfmt_misc mount point should be treated as the
/// feature being unavailable.
///
/// Under a read-only bind mount of `/proc`, attempting to open an autofs
/// binfmt_misc mount point can fail with `ELOOP`: the kernel cannot trigger
/// the automount. Privilege failures are likewise reported by the C API as
/// "not mounted and writable", rather than as fatal errors.
fn is_binfmt_mount_unavailable(err: &std::io::Error) -> bool {
    matches!(
        err.raw_os_error(),
        Some(libc::ELOOP) | Some(libc::EACCES) | Some(libc::EPERM)
    )
}

/// Determine the filesystem magic number of an open file descriptor.
///
/// Returns the `f_type` field from `statfs(2)`.
#[cfg(target_os = "linux")]
fn fd_fs_type(fd: i32) -> Result<u64, std::io::Error> {
    let mut buf = std::mem::MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: `buf` provides writable storage for fstatfs(2), and `fd` is an
    // open descriptor borrowed from the live File retained by the caller.
    let ret = unsafe { libc::fstatfs(fd, buf.as_mut_ptr()) };
    if ret < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: a successful fstatfs(2) call initialized the complete statfs.
    Ok(unsafe { buf.assume_init() }.f_type as u64)
}

/// Test file-descriptor accessibility using `faccessat` with `AT_EMPTY_PATH`.
#[cfg(target_os = "linux")]
fn access_fd(fd: i32, mode: i32) -> Result<(), std::io::Error> {
    // SAFETY: AT_EMPTY_PATH makes this live empty C string refer to the
    // supplied open descriptor; the call neither retains the descriptor nor
    // writes through the pathname pointer.
    let ret = unsafe {
        libc::faccessat(
            fd,
            b"\0".as_ptr().cast::<libc::c_char>(),
            mode,
            libc::AT_EMPTY_PATH,
        )
    };
    if ret < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

// ── Public API ────────────────────────────────────────────────────────────

/// Check whether the binfmt_misc filesystem is mounted and writable.
///
/// Opens [`BINFMT_MISC_PATH`] with `O_PATH` (to avoid triggering autofs),
/// verifies the filesystem magic is [`BINFMTFS_MAGIC`], and tests writability
/// via `faccessat(W_OK)`.
///
/// # Returns
///
/// - `Ok(true)`  — binfmt_misc is mounted and writable.
/// - `Ok(false)` — not mounted, or mounted read-only / without write permission.
/// - `Err`       — an unexpected error occurred.
#[cfg(target_os = "linux")]
pub fn binfmt_mounted_and_writable() -> Result<bool, BinfmtError> {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::OpenOptionsExt;

    let file = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_PATH)
        .open(BINFMT_MISC_PATH)
    {
        Ok(f) => f,
        Err(e) => {
            return if e.kind() == std::io::ErrorKind::NotFound || is_binfmt_mount_unavailable(&e) {
                Ok(false)
            } else {
                Err(BinfmtError::from(e))
            };
        }
    };

    let fd = file.as_raw_fd();

    // Verify the filesystem is actually binfmt_misc.
    let magic = fd_fs_type(fd)?;
    if magic != BINFMTFS_MAGIC {
        // `fd_is_fs_type()` returns 0 for a different filesystem; C maps
        // that to “not mounted and writable”, not an error.
        return Ok(false);
    }

    // Check writability.
    match access_fd(fd, libc::W_OK) {
        Ok(()) => Ok(true),
        Err(e) if is_fs_write_refused(&e) => Ok(false),
        Err(e) => Err(BinfmtError::from(e)),
    }
}

/// Check whether binfmt_misc is currently enabled.
///
/// Reads and parses the status file at [`BINFMT_STATUS_PATH`].
#[cfg(target_os = "linux")]
pub fn binfmt_is_enabled() -> Result<bool, BinfmtError> {
    let content = std::fs::read_to_string(BINFMT_STATUS_PATH)?;
    match BinfmtStatus::parse(&content) {
        Some(status) => Ok(status.is_enabled()),
        None => Err(BinfmtError::InvalidStatus(content)),
    }
}

/// Disable all registered binfmt_misc entries.
///
/// Writes [`BINFMT_DISABLE_VALUE`] (`"-1"`) to the status file, which
/// unregisters every binary format rule. This is important during shutdown
/// to release file descriptors held by rules using the "F" (preserve fd) flag.
///
/// The function is careful not to trigger autofs mounts: it first checks
/// whether binfmt_misc is mounted and writable without actually opening
/// the status file.
#[cfg(target_os = "linux")]
pub fn disable_binfmt() -> Result<(), BinfmtError> {
    match binfmt_mounted_and_writable() {
        Ok(true) => {}
        Ok(false) => return Ok(()),
        Err(e) => return Err(e),
    }

    std::fs::write(BINFMT_STATUS_PATH, BINFMT_DISABLE_VALUE)?;
    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    // ── Status parsing ─────────────────────────────────────────────────

    #[test]
    fn test_binfmt_status_parse_enabled() {
        assert_eq!(BinfmtStatus::parse("enabled"), Some(BinfmtStatus::Enabled));
    }

    #[test]
    fn test_binfmt_status_parse_disabled() {
        assert_eq!(
            BinfmtStatus::parse("disabled"),
            Some(BinfmtStatus::Disabled)
        );
    }

    #[test]
    fn test_binfmt_status_parse_trims_whitespace() {
        assert_eq!(
            BinfmtStatus::parse("  enabled  "),
            Some(BinfmtStatus::Enabled)
        );
        assert_eq!(
            BinfmtStatus::parse("\tenabled\n"),
            Some(BinfmtStatus::Enabled)
        );
        assert_eq!(
            BinfmtStatus::parse("  disabled  "),
            Some(BinfmtStatus::Disabled)
        );
    }

    #[test]
    fn test_binfmt_status_parse_invalid() {
        assert_eq!(BinfmtStatus::parse("unknown"), None);
        assert_eq!(BinfmtStatus::parse("ENABLED"), None);
        assert_eq!(BinfmtStatus::parse("1"), None);
        assert_eq!(BinfmtStatus::parse(""), None);
    }

    #[test]
    fn test_binfmt_status_is_enabled() {
        assert!(BinfmtStatus::Enabled.is_enabled());
        assert!(!BinfmtStatus::Disabled.is_enabled());
    }

    #[test]
    fn test_binfmt_status_display() {
        assert_eq!(format!("{}", BinfmtStatus::Enabled), "enabled");
        assert_eq!(format!("{}", BinfmtStatus::Disabled), "disabled");
    }

    #[test]
    fn test_binfmt_status_debug() {
        assert!(format!("{:?}", BinfmtStatus::Enabled).contains("Enabled"));
        assert!(format!("{:?}", BinfmtStatus::Disabled).contains("Disabled"));
    }

    #[test]
    fn test_binfmt_status_equality() {
        assert_eq!(BinfmtStatus::Enabled, BinfmtStatus::Enabled);
        assert_eq!(BinfmtStatus::Disabled, BinfmtStatus::Disabled);
        assert_ne!(BinfmtStatus::Enabled, BinfmtStatus::Disabled);
    }

    // ── Constants ──────────────────────────────────────────────────────

    #[test]
    fn test_constants() {
        assert_eq!(BINFMT_MISC_PATH, "/proc/sys/fs/binfmt_misc");
        assert_eq!(BINFMT_STATUS_PATH, "/proc/sys/fs/binfmt_misc/status");
        assert_eq!(BINFMTFS_MAGIC, 0x4249_4E4D);
        assert_eq!(BINFMT_DISABLE_VALUE, "-1");
        assert!(BINFMT_STATUS_PATH.starts_with(BINFMT_MISC_PATH));
    }

    // ── Error types ────────────────────────────────────────────────────

    #[test]
    fn test_binfmt_error_display_io() {
        let err = BinfmtError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "not found",
        ));
        let msg = format!("{err}");
        assert!(msg.contains("not found"));
    }

    #[test]
    #[test]
    fn test_binfmt_error_display_invalid_status() {
        let err = BinfmtError::InvalidStatus("garbage".to_owned());
        let msg = format!("{err}");
        assert!(msg.contains("garbage"));
        assert!(msg.contains("invalid"));
    }

    #[test]
    fn test_binfmt_error_from_io_conversion() {
        let io_err = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied");
        let binfmt_err: BinfmtError = io_err.into();
        assert!(matches!(binfmt_err, BinfmtError::Io(_)));
    }

    #[test]
    fn test_binfmt_error_source_chain() {
        let io_err = std::io::Error::new(std::io::ErrorKind::AlreadyExists, "exists");
        let binfmt_err = BinfmtError::Io(io_err);
        assert!(binfmt_err.source().is_some());

        let no_source = BinfmtError::InvalidStatus(String::new());
        assert!(no_source.source().is_none());
    }

    // ── is_fs_write_refused ────────────────────────────────────────────

    #[test]
    fn test_is_fs_write_refused_eros() {
        let err = std::io::Error::from_raw_os_error(libc::EROFS);
        assert!(is_fs_write_refused(&err));
    }

    #[test]
    fn test_is_fs_write_refused_eacces() {
        let err = std::io::Error::from_raw_os_error(libc::EACCES);
        assert!(is_fs_write_refused(&err));
    }

    #[test]
    fn test_is_fs_write_refused_eperm() {
        let err = std::io::Error::from_raw_os_error(libc::EPERM);
        assert!(is_fs_write_refused(&err));
    }

    #[test]
    fn test_is_fs_write_refused_other_errno() {
        let err = std::io::Error::from_raw_os_error(libc::ENOENT);
        assert!(!is_fs_write_refused(&err));
    }

    #[test]
    fn test_is_fs_write_refused_no_os_error() {
        let err = std::io::Error::new(std::io::ErrorKind::InvalidData, "bad data");
        assert!(!is_fs_write_refused(&err));
    }
}
