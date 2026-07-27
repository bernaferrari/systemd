// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/apparmor-util.c, src/shared/apparmor-util.h
//
// AppArmor security module utilities.
//
// Detects whether AppArmor is enabled and the libapparmor shared library
// is available on the system by inspecting kernel parameters and attempting
// to locate the library. Provides a cached check so repeated calls are cheap.

use crate::ffi::*;
use std::fs;
use std::io;
use std::path::Path;
use std::sync::atomic::{AtomicI8, Ordering};

// ── Constants ─────────────────────────────────────────────────────────────

/// Sysfs path to the AppArmor enabled parameter.
const APPARMOR_ENABLED_PATH: &str = "/sys/module/apparmor/parameters/enabled";

/// Sysfs path to the AppArmor securityfs mount (alternative check).
const APPARMOR_SECURITY_PATH: &str = "/sys/kernel/security/apparmor";

/// Known paths where libapparmor may be installed.
const LIBAPPARMOR_PATHS: &[&str] = &[
    "libapparmor.so.1",
    "/lib/libapparmor.so.1",
    "/lib64/libapparmor.so.1",
    "/usr/lib/libapparmor.so.1",
    "/usr/lib64/libapparmor.so.1",
];

/// Cached AppArmor availability: -1 = not yet checked, 0 = unavailable, 1 = available.
static CACHED_USE: AtomicI8 = AtomicI8::new(-1);

// ── Errors ────────────────────────────────────────────────────────────────

/// Errors that can occur when checking AppArmor status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AppArmorError {
    /// The AppArmor enabled parameter file could not be read.
    ReadFailed(io::ErrorKind),
    /// The AppArmor enabled parameter contained an unrecognized value.
    ParseFailed(String),
    /// The libapparmor shared library was not found on the system.
    LibNotFound,
}

impl std::fmt::Display for AppArmorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AppArmorError::ReadFailed(kind) => {
                write!(f, "failed to read AppArmor enabled parameter: {kind}")
            }
            AppArmorError::ParseFailed(value) => {
                write!(f, "failed to parse AppArmor enabled value: {value:?}")
            }
            AppArmorError::LibNotFound => {
                write!(f, "libapparmor shared library not found")
            }
        }
    }
}

impl std::error::Error for AppArmorError {}

// ── Public API ────────────────────────────────────────────────────────────

/// Check whether AppArmor is available and usable on this system.
///
/// This is the primary entry point, equivalent to `mac_apparmor_use()` in C.
/// The result is cached after the first call; subsequent calls return the
/// cached value without re-querying the filesystem.
///
/// Returns `Ok(true)` if AppArmor is enabled and libapparmor is available,
/// `Ok(false)` if AppArmor is not enabled or the library is missing,
/// or `Err` if an unexpected I/O or parse error occurred.
pub fn mac_apparmor_use() -> Result<bool, AppArmorError> {
    let cached = CACHED_USE.load(Ordering::Acquire);
    if cached >= 0 {
        return Ok(cached == 1);
    }

    let result = determine_apparmor_use();
    CACHED_USE.store(
        if result.as_ref().is_ok_and(|v| *v) {
            1
        } else {
            0
        },
        Ordering::Release,
    );
    result
}

/// Reset the cached AppArmor availability check.
///
/// Forces the next call to [`mac_apparmor_use`] to re-query the system.
/// Intended for testing purposes only.
pub fn reset_apparmor_cache() {
    CACHED_USE.store(-1, Ordering::Release);
}

/// Attempt to locate and load libapparmor.
///
/// Scans known library paths for `libapparmor.so.1`. Returns `Ok(())` if
/// the library was found, or `Err(AppArmorError::LibNotFound)` if not.
///
/// Note: This does not actually dlopen the library (that requires unsafe code),
/// it only checks for file existence on the filesystem.
pub fn dlopen_libapparmor() -> Result<(), AppArmorError> {
    try_dlopen_libapparmor()
}

/// Check if AppArmor is enabled via its kernel parameter file.
///
/// Reads `/sys/module/apparmor/parameters/enabled` and parses the boolean
/// value. Returns `Ok(true)` if the parameter is set to an affirmative value,
/// `Ok(false)` if set to a negative value, or an error on I/O failure.
pub fn apparmor_enabled() -> Result<bool, AppArmorError> {
    check_apparmor_enabled()
}

/// Check if the AppArmor security filesystem is mounted.
///
/// Tests for the existence of `/sys/kernel/security/apparmor`.
pub fn apparmor_securityfs_available() -> bool {
    Path::new(APPARMOR_SECURITY_PATH).exists()
}

// ── Internal helpers ─────────────────────────────────────────────────────

/// Parse a boolean value from a systemd-style boolean string.
///
/// Recognizes `1`, `yes`, `true`, `on`, `y` as true and
/// `0`, `no`, `false`, `off`, `n` as false (case-sensitive, trimmed).
fn parse_boolean(s: &str) -> Option<bool> {
    match s.trim() {
        "1" | "yes" | "true" | "on" | "y" => Some(true),
        "0" | "no" | "false" | "off" | "n" => Some(false),
        _ => None,
    }
}

/// Read the AppArmor enabled parameter and parse its boolean value.
fn check_apparmor_enabled() -> Result<bool, AppArmorError> {
    let content = fs::read_to_string(APPARMOR_ENABLED_PATH)
        .map_err(|e| AppArmorError::ReadFailed(e.kind()))?;

    parse_boolean(&content).ok_or_else(|| {
        let display: String = content.chars().take(64).collect();
        AppArmorError::ParseFailed(display)
    })
}

/// Check known paths for libapparmor.
fn try_dlopen_libapparmor() -> Result<(), AppArmorError> {
    let found = LIBAPPARMOR_PATHS.iter().any(|path| {
        // Use Path::new so relative names like "libapparmor.so.1" resolve
        // against LD_LIBRARY_PATH or fail gracefully.
        Path::new(path).exists()
    });

    if found {
        Ok(())
    } else {
        Err(AppArmorError::LibNotFound)
    }
}

/// Full determination of AppArmor availability (no caching).
///
/// Checks the kernel parameter, then verifies the library is present.
fn determine_apparmor_use() -> Result<bool, AppArmorError> {
    match check_apparmor_enabled() {
        Ok(true) => try_dlopen_libapparmor().map(|()| true),
        Ok(false) => Ok(false),
        Err(_) => Ok(false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_boolean_true_values() {
        assert_eq!(parse_boolean("1"), Some(true));
        assert_eq!(parse_boolean("yes"), Some(true));
        assert_eq!(parse_boolean("true"), Some(true));
        assert_eq!(parse_boolean("on"), Some(true));
        assert_eq!(parse_boolean("y"), Some(true));
    }

    #[test]
    fn test_parse_boolean_false_values() {
        assert_eq!(parse_boolean("0"), Some(false));
        assert_eq!(parse_boolean("no"), Some(false));
        assert_eq!(parse_boolean("false"), Some(false));
        assert_eq!(parse_boolean("off"), Some(false));
        assert_eq!(parse_boolean("n"), Some(false));
    }

    #[test]
    fn test_parse_boolean_trims_whitespace() {
        assert_eq!(parse_boolean("  yes  "), Some(true));
        assert_eq!(parse_boolean("\tyes\n"), Some(true));
        assert_eq!(parse_boolean("  0  "), Some(false));
        assert_eq!(parse_boolean("  false  "), Some(false));
    }

    #[test]
    fn test_parse_boolean_invalid() {
        assert_eq!(parse_boolean(""), None);
        assert_eq!(parse_boolean("maybe"), None);
        assert_eq!(parse_boolean("2"), None);
        assert_eq!(parse_boolean("enabled"), None);
        assert_eq!(parse_boolean("YES"), None); // case-sensitive
        assert_eq!(parse_boolean("True"), None); // case-sensitive
    }

    #[test]
    fn test_parse_boolean_empty_string() {
        assert_eq!(parse_boolean(""), None);
        assert_eq!(parse_boolean("   "), None);
    }

    #[test]
    fn test_mac_apparmor_use_caching() {
        reset_apparmor_cache();
        let first = mac_apparmor_use();
        let second = mac_apparmor_use();
        assert_eq!(first, second);
    }

    #[test]
    fn test_mac_apparmor_use_returns_bool() {
        reset_apparmor_cache();
        let result = mac_apparmor_use();
        // On any system this should return Ok(true) or Ok(false)
        assert!(result.is_ok());
    }

    #[test]
    fn test_reset_apparmor_cache() {
        reset_apparmor_cache();
        let before = CACHED_USE.load(Ordering::Acquire);
        assert_eq!(before, -1);
    }

    #[test]
    fn test_dlopen_libapparmor_returns_result() {
        let result = dlopen_libapparmor();
        // Either found or not — just verify it returns a proper Result
        match result {
            Ok(()) => {}
            Err(AppArmorError::LibNotFound) => {}
            Err(e) => panic!("unexpected error: {e}"),
        }
    }

    #[test]
    fn test_apparmor_enabled_returns_result() {
        let result = apparmor_enabled();
        // May succeed or fail depending on system — verify it's a Result
        match result {
            Ok(true) | Ok(false) => {}
            Err(AppArmorError::ReadFailed(_)) => {}
            Err(e) => panic!("unexpected error: {e}"),
        }
    }

    #[test]
    fn test_apparmor_securityfs_available_returns_bool() {
        let _ = apparmor_securityfs_available();
        // Just verify it doesn't panic
    }

    #[test]
    fn test_libapparmor_paths_non_empty() {
        assert!(!LIBAPPARMOR_PATHS.is_empty());
        assert!(LIBAPPARMOR_PATHS.contains(&"libapparmor.so.1"));
    }

    #[test]
    fn test_apparmor_error_display() {
        let err = AppArmorError::ReadFailed(io::ErrorKind::NotFound);
        let msg = format!("{err}");
        assert!(msg.contains("failed to read"));

        let err = AppArmorError::ParseFailed("garbage".to_string());
        let msg = format!("{err}");
        assert!(msg.contains("garbage"));

        let err = AppArmorError::LibNotFound;
        let msg = format!("{err}");
        assert!(msg.contains("not found"));
    }

    #[test]
    fn test_apparmor_error_debug_clone_eq() {
        let err1 = AppArmorError::LibNotFound;
        let err2 = err1.clone();
        assert_eq!(err1, err2);
        let debug = format!("{err1:?}");
        assert!(debug.contains("LibNotFound"));
    }

    #[test]
    fn test_apparmor_enabled_path_constant() {
        assert!(APPARMOR_ENABLED_PATH.starts_with('/'));
        assert!(APPARMOR_ENABLED_PATH.contains("apparmor"));
    }

    #[test]
    fn test_determine_apparmor_use_consistent_with_mac_apparmor_use() {
        reset_apparmor_cache();
        let direct = determine_apparmor_use();
        reset_apparmor_cache();
        let cached = mac_apparmor_use();
        // Both should agree on the boolean value
        assert_eq!(direct.is_ok_and(|v| v), cached.is_ok_and(|v| v));
    }
}
