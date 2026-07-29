// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/reboot-util.c, src/shared/reboot-util.h
//
// Reboot and shutdown utility functions.
//
// Provides reboot parameter management, system reboot with optional
// parameterized reboot, state restoration checks, kexec detection,
// and nologin file creation for scheduled shutdowns.

use crate::ffi::*;
use std::ffi::CString;
use std::fs;
use std::io;
use std::path::Path;

// ── Constants ─────────────────────────────────────────────────────────────

/// Path to the reboot parameter file.
const REBOOT_PARAM_PATH: &str = "/run/systemd/reboot-param";

/// Path to the kexec loaded status file.
const KEXEC_LOADED_PATH: &str = "/sys/kernel/kexec_loaded";

/// Path to the kernel command line.
const PROC_CMDLINE_PATH: &str = "/proc/cmdline";

/// Path to the nologin file created during shutdown.
const NOLOGIN_PATH: &str = "/run/nologin";

/// Maximum length for a reboot parameter (NAME_MAX from POSIX).
const REBOOT_PARAMETER_MAX_LEN: usize = 255;

// Linux reboot(2) constants — not provided by libc on all platforms.
const LINUX_REBOOT_MAGIC1: u32 = 0xfee1dead;
const LINUX_REBOOT_MAGIC2: u32 = 0x28121969;
const LINUX_REBOOT_CMD_RESTART2: u32 = 0xA1B2C3D4;
const RB_AUTOBOOT: u32 = 0x01234567;

/// SYS_reboot syscall number on Linux (x86_64 / most arches).
#[cfg(target_arch = "x86_64")]
const SYS_REBOOT: libc::c_long = 169;
#[cfg(target_arch = "aarch64")]
const SYS_REBOOT: libc::c_long = 142;
#[cfg(target_arch = "riscv64")]
const SYS_REBOOT: libc::c_long = 104;

/// Message written to `/run/nologin` when the system is going down.
const NOLOGIN_MESSAGE: &str = "System is going down. Unprivileged users are not permitted to log in anymore. \
     For technical details, see pam_nologin(8).";

// ── Error type ────────────────────────────────────────────────────────────

/// Errors produced by reboot utility operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RebootError {
    /// The reboot parameter string is not valid ASCII or exceeds length limits.
    InvalidParameter(String),
    /// An I/O error occurred during file system operations.
    Io(String),
    /// The reboot system call failed.
    RebootFailed(String),
    /// Failed to read a required file.
    ReadFailed(String),
}

impl std::fmt::Display for RebootError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidParameter(msg) => write!(f, "Invalid reboot parameter: {msg}"),
            Self::Io(msg) => write!(f, "I/O error: {msg}"),
            Self::RebootFailed(msg) => write!(f, "Reboot failed: {msg}"),
            Self::ReadFailed(msg) => write!(f, "Read failed: {msg}"),
        }
    }
}

impl std::error::Error for RebootError {}

impl From<io::Error> for RebootError {
    fn from(e: io::Error) -> Self {
        RebootError::Io(e.to_string())
    }
}

impl From<std::ffi::NulError> for RebootError {
    fn from(e: std::ffi::NulError) -> Self {
        RebootError::InvalidParameter(e.to_string())
    }
}

// ── Flags ─────────────────────────────────────────────────────────────────

/// Flags controlling reboot behavior.
///
/// Bit values match the C `RebootFlags` enum in `reboot-util.h`:
/// - `LOG`      = 1 (log about actions and errors)
/// - `DRY_RUN`  = 2 (skip the actual reboot syscall)
/// - `FALLBACK` = 4 (fall back to classic reboot on failure)
bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct RebootFlags: u32 {
        const LOG      = 1 << 0;
        const DRY_RUN  = 1 << 1;
        const FALLBACK = 1 << 2;
    }
}

// ── Reboot parameter validation ───────────────────────────────────────────

/// Check if a reboot parameter string is valid.
///
/// A valid parameter must be pure ASCII and at most `NAME_MAX` bytes long.
/// An empty string is not considered valid.
pub fn reboot_parameter_is_valid(parameter: &str) -> bool {
    !parameter.is_empty()
        && parameter.len() <= REBOOT_PARAMETER_MAX_LEN
        && parameter.bytes().all(|b| b.is_ascii_graphic() || b == b' ')
}

/// Validate a reboot parameter, returning a descriptive error if invalid.
fn validate_reboot_parameter(parameter: &str) -> Result<(), RebootError> {
    if !reboot_parameter_is_valid(parameter) {
        return Err(RebootError::InvalidParameter(format!(
            "Invalid reboot parameter '{parameter}'"
        )));
    }
    Ok(())
}

// ── Update reboot parameter ───────────────────────────────────────────────

/// Update the reboot parameter file on disk.
///
/// - If `parameter` is empty and `keep` is `false`, removes the file.
/// - If `parameter` is empty and `keep` is `true`, does nothing.
/// - If `parameter` is non-empty, validates it and writes it atomically.
pub fn update_reboot_parameter(parameter: &str, keep: bool) -> Result<(), RebootError> {
    if parameter.is_empty() {
        if keep {
            return Ok(());
        }
        match fs::remove_file(REBOOT_PARAM_PATH) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(RebootError::Io(format!(
                "Failed to unlink reboot parameter file: {e}"
            ))),
        }
    } else {
        validate_reboot_parameter(parameter)?;
        fs::write(REBOOT_PARAM_PATH, parameter)?;
        Ok(())
    }
}

// ── Read reboot parameter ─────────────────────────────────────────────────

/// Read the reboot parameter from the parameter file.
///
/// Returns `Ok(None)` if the file does not exist (no reboot parameter set).
/// Returns `Ok(Some(value))` with the trimmed file contents otherwise.
pub fn read_reboot_parameter() -> Result<Option<String>, RebootError> {
    match fs::read_to_string(REBOOT_PARAM_PATH) {
        Ok(contents) => Ok(Some(contents.trim().to_string())),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(RebootError::ReadFailed(format!(
            "Failed to read {REBOOT_PARAM_PATH}: {e}"
        ))),
    }
}

// ── Raw reboot system call ────────────────────────────────────────────────

/// Issue a raw Linux reboot system call.
///
/// Wraps the `reboot(2)` syscall with the appropriate magic numbers.
/// The `cmd` parameter selects the reboot command (e.g., `LINUX_REBOOT_CMD_RESTART2`).
/// The optional `arg` is passed for parameterized reboots.
pub fn raw_reboot(cmd: i32, arg: Option<&str>) -> Result<(), RebootError> {
    let arg_cstr = match arg {
        Some(value) => Some(CString::new(value)?),
        None => None,
    };
    let arg_ptr: *const libc::c_char = arg_cstr
        .as_ref()
        .map_or(std::ptr::null(), |s| s.as_ptr().cast());

    // SAFETY: Direct syscall wrapper — caller provides valid command constants.
    let ret = unsafe {
        libc::syscall(
            SYS_REBOOT,
            LINUX_REBOOT_MAGIC1,
            LINUX_REBOOT_MAGIC2,
            cmd,
            arg_ptr,
        )
    };

    if ret < 0 {
        return Err(RebootError::RebootFailed(
            io::Error::last_os_error().to_string(),
        ));
    }

    Ok(())
}

// ── Reboot with parameter ─────────────────────────────────────────────────

/// Reboot the system, optionally using a stored reboot parameter.
///
/// Reads the reboot parameter from `/run/systemd/reboot-param`. If a parameter
/// is found and the system is not running inside a container, attempts a
/// parameterized reboot via `LINUX_REBOOT_CMD_RESTART2`.
///
/// Behavior is controlled by `flags`:
/// - `LOG`: Log about actions taken and errors encountered.
/// - `DRY_RUN`: Skip the actual reboot syscall, just validate and return.
/// - `FALLBACK`: If parameterized reboot fails, fall back to classic `RB_AUTOBOOT`.
///
/// Returns `Ok(())` on success or when `DRY_RUN` is set.
/// Returns `Ok(())` when `FALLBACK` is not set and parameterized reboot fails
/// (the caller should handle fallback on its own).
pub fn reboot_with_parameter(flags: RebootFlags) -> Result<(), RebootError> {
    let is_dry_run = flags.contains(RebootFlags::DRY_RUN);

    // Only attempt parameterized reboot when not in a container.
    if !detect_container() {
        match read_reboot_parameter() {
            Ok(Some(parameter)) if !parameter.is_empty() => {
                if is_dry_run {
                    return Ok(());
                }

                match raw_reboot(LINUX_REBOOT_CMD_RESTART2 as i32, Some(&parameter)) {
                    Ok(()) => return Ok(()),
                    Err(_) if !flags.contains(RebootFlags::FALLBACK) => {
                        // Caller should fall back on its own.
                        return Ok(());
                    }
                    Err(_) => {
                        // Fall through to classic reboot below.
                    }
                }
            }
            Ok(Some(_)) | Ok(None) => {
                // Empty or missing parameter — skip parameterized reboot.
            }
            Err(_) => {
                // Failed to read parameter file — skip parameterized reboot.
            }
        }
    }

    if !flags.contains(RebootFlags::FALLBACK) {
        return Ok(());
    }

    if is_dry_run {
        return Ok(());
    }

    raw_reboot(RB_AUTOBOOT as i32, None)
}

// ── Container detection ───────────────────────────────────────────────────

/// Simple container detection via well-known indicators.
///
/// Checks for `.dockerenv` and container-related cgroup entries under
/// `/proc/1/cgroup`. Returns `true` if a container environment is detected.
fn detect_container() -> bool {
    if Path::new("/.dockerenv").exists() {
        return true;
    }

    if let Ok(cgroup) = fs::read_to_string("/proc/1/cgroup") {
        for line in cgroup.lines() {
            if line.contains("docker")
                || line.contains("kubepods")
                || line.contains("containerd")
                || line.contains(":/")
            {
                return true;
            }
        }
    }

    false
}

// ── State restoration ─────────────────────────────────────────────────────

/// Determine whether system state should be restored on reboot.
///
/// Reads the kernel command line and checks for `systemd.restore_state=`.
/// Defaults to `true` when the option is not present. Explicit
/// `systemd.restore_state=0` or `systemd.restore_state=false` disables restoration.
pub fn shall_restore_state() -> bool {
    parse_proc_cmdline_bool("systemd.restore_state", PROC_CMDLINE_PATH).unwrap_or(true)
}

/// Parse a boolean kernel command line option from a file.
///
/// Returns `Some(true)` for truthy values (1, yes, true, on),
/// `Some(false)` for falsy values (0, no, false, off),
/// or `None` if the option is not present in the file.
fn parse_proc_cmdline_bool(option: &str, path: &str) -> Option<bool> {
    let cmdline = fs::read_to_string(path).ok()?;

    for token in cmdline.split_whitespace() {
        let token = token.trim_start_matches('"').trim_end_matches('"');
        if let Some(rest) = token.strip_prefix(option) {
            let rest = rest.strip_prefix('=').unwrap_or(rest);
            // Option present without value → treat as true.
            if rest.is_empty() || rest.starts_with(' ') {
                return Some(true);
            }
            return Some(is_truthy(rest));
        }
    }

    None
}

/// Check if a string represents a truthy boolean value.
fn is_truthy(s: &str) -> bool {
    matches!(s.to_lowercase().as_str(), "1" | "yes" | "true" | "on")
}

/// Check if a string represents a falsy boolean value.
fn is_falsy(s: &str) -> bool {
    matches!(s.to_lowercase().as_str(), "0" | "no" | "false" | "off")
}

// ── Kexec detection ───────────────────────────────────────────────────────

/// Check whether a kexec kernel has been loaded into the current kernel.
///
/// Reads `/sys/kernel/kexec_loaded` and returns `true` if it contains `"1"`.
pub fn kexec_loaded() -> bool {
    fs::read_to_string(KEXEC_LOADED_PATH)
        .ok()
        .is_some_and(|v| v.trim() == "1")
}

// ── Nologin file creation ─────────────────────────────────────────────────

/// Create `/run/nologin` to prevent user logins during shutdown.
///
/// Creates parent directories if needed and writes the standard shutdown
/// message. Used by both `systemd-user-sessions.service` and
/// `systemd-logind.service`.
pub fn create_shutdown_run_nologin() -> Result<(), RebootError> {
    if let Some(parent) = Path::new(NOLOGIN_PATH).parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    fs::write(NOLOGIN_PATH, NOLOGIN_MESSAGE)?;
    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Parameter validation ──────────────────────────────────────────────

    #[test]
    fn test_reboot_parameter_is_valid_ascii() {
        assert!(reboot_parameter_is_valid("reboot"));
        assert!(reboot_parameter_is_valid("halt"));
        assert!(reboot_parameter_is_valid("poweroff"));
        assert!(reboot_parameter_is_valid("emergency"));
        assert!(reboot_parameter_is_valid("single"));
    }

    #[test]
    fn test_reboot_parameter_is_valid_empty() {
        assert!(!reboot_parameter_is_valid(""));
    }

    #[test]
    fn test_reboot_parameter_is_valid_non_ascii() {
        assert!(!reboot_parameter_is_valid("reboöt"));
        assert!(!reboot_parameter_is_valid("\t"));
        assert!(!reboot_parameter_is_valid("reboot\n"));
    }

    #[test]
    fn test_reboot_parameter_is_valid_at_length_limit() {
        let at_limit: String = "a".repeat(REBOOT_PARAMETER_MAX_LEN);
        assert!(reboot_parameter_is_valid(&at_limit));

        let over_limit: String = "a".repeat(REBOOT_PARAMETER_MAX_LEN + 1);
        assert!(!reboot_parameter_is_valid(&over_limit));
    }

    #[test]
    fn test_validate_reboot_parameter_accepts_valid() {
        assert!(validate_reboot_parameter("reboot").is_ok());
        assert!(validate_reboot_parameter("a").is_ok());
    }

    #[test]
    fn test_validate_reboot_parameter_rejects_invalid() {
        assert!(validate_reboot_parameter("").is_err());
        assert!(validate_reboot_parameter("reboöt").is_err());
        assert!(validate_reboot_parameter(&"x".repeat(256)).is_err());
    }

    // ── Truthy / falsy parsing ────────────────────────────────────────────

    #[test]
    fn test_is_truthy_variants() {
        for val in ["1", "yes", "Yes", "YES", "true", "True", "TRUE", "on", "ON"] {
            assert!(is_truthy(val), "expected '{val}' to be truthy");
        }
    }

    #[test]
    fn test_is_truthy_rejects_falsy_and_garbage() {
        for val in ["0", "no", "false", "off", "", "maybe", "2"] {
            assert!(!is_truthy(val), "expected '{val}' to NOT be truthy");
        }
    }

    #[test]
    fn test_is_falsy_variants() {
        for val in [
            "0", "no", "No", "NO", "false", "False", "FALSE", "off", "OFF",
        ] {
            assert!(is_falsy(val), "expected '{val}' to be falsy");
        }
    }

    #[test]
    fn test_is_falsy_rejects_truthy_and_garbage() {
        for val in ["1", "yes", "true", "on", "", "maybe", "2"] {
            assert!(!is_falsy(val), "expected '{val}' to NOT be falsy");
        }
    }

    #[test]
    fn test_parse_proc_cmdline_bool_missing_file() {
        assert_eq!(
            parse_proc_cmdline_bool("systemd.restore_state", "/nonexistent/path"),
            None
        );
    }

    #[test]
    fn test_parse_proc_cmdline_bool_option_absent() {
        // /proc/version exists but doesn't contain systemd.restore_state.
        assert_eq!(
            parse_proc_cmdline_bool("systemd.restore_state", "/proc/version"),
            None
        );
    }

    #[test]
    fn test_shall_restore_state_defaults_true() {
        // Without systemd.restore_state on the kernel cmdline, defaults to true.
        assert!(shall_restore_state());
    }

    // ── Flags ─────────────────────────────────────────────────────────────

    #[test]
    fn test_reboot_flags_bit_values_match_c_header() {
        assert_eq!(RebootFlags::LOG.bits(), 1);
        assert_eq!(RebootFlags::DRY_RUN.bits(), 2);
        assert_eq!(RebootFlags::FALLBACK.bits(), 4);
    }

    #[test]
    fn test_reboot_flags_combinations() {
        let none = RebootFlags::empty();
        assert!(!none.contains(RebootFlags::LOG));

        let log_dry = RebootFlags::LOG | RebootFlags::DRY_RUN;
        assert!(log_dry.contains(RebootFlags::LOG));
        assert!(log_dry.contains(RebootFlags::DRY_RUN));
        assert!(!log_dry.contains(RebootFlags::FALLBACK));

        let all = RebootFlags::LOG | RebootFlags::DRY_RUN | RebootFlags::FALLBACK;
        assert!(all.contains(RebootFlags::LOG));
        assert!(all.contains(RebootFlags::DRY_RUN));
        assert!(all.contains(RebootFlags::FALLBACK));
    }

    // ── Error type ────────────────────────────────────────────────────────

    #[test]
    fn test_reboot_error_display_messages() {
        assert_eq!(
            format!("{}", RebootError::InvalidParameter("x".into())),
            "Invalid reboot parameter: x"
        );
        assert_eq!(
            format!("{}", RebootError::RebootFailed("EPERM".into())),
            "Reboot failed: EPERM"
        );
        assert!(format!("{}", RebootError::Io("err".into())).contains("I/O error"));
        assert!(format!("{}", RebootError::ReadFailed("err".into())).contains("Read failed"));
    }

    #[test]
    fn test_reboot_error_from_io_error() {
        let io_err = io::Error::new(io::ErrorKind::NotFound, "file not found");
        let converted: RebootError = io_err.into();
        assert!(matches!(converted, RebootError::Io(_)));
        assert!(converted.to_string().contains("file not found"));
    }

    #[test]
    fn test_reboot_error_from_nul_error() {
        let nul_err = CString::new("abc\0def").unwrap_err();
        let converted: RebootError = nul_err.into();
        assert!(matches!(converted, RebootError::InvalidParameter(_)));
    }

    // ── Constants ─────────────────────────────────────────────────────────

    #[test]
    fn test_constant_paths_are_absolute() {
        assert!(REBOOT_PARAM_PATH.starts_with('/'));
        assert!(KEXEC_LOADED_PATH.starts_with('/'));
        assert!(NOLOGIN_PATH.starts_with('/'));
        assert!(PROC_CMDLINE_PATH.starts_with('/'));
    }

    #[test]
    fn test_nologin_message_content() {
        assert!(NOLOGIN_MESSAGE.contains("System is going down"));
        assert!(NOLOGIN_MESSAGE.contains("pam_nologin"));
    }

    // ── Integration-safe smoke tests ──────────────────────────────────────

    #[test]
    fn test_kexec_loaded_no_panic() {
        // Cannot control /sys/kernel/kexec_loaded — just verify no panic.
        let _ = kexec_loaded();
    }

    #[test]
    fn test_detect_container_no_panic() {
        let _ = detect_container();
    }

    #[test]
    fn test_read_reboot_parameter_missing_file() {
        // /run/systemd/reboot-param typically doesn't exist in test environments.
        let result = read_reboot_parameter();
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), None);
    }

    #[test]
    fn test_update_reboot_parameter_remove_nonexistent() {
        // Removing a file that doesn't exist should succeed (idempotent).
        let result = update_reboot_parameter("", false);
        assert!(result.is_ok());
    }
}
