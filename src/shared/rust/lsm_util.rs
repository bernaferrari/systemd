// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/lsm-util.c, src/shared/lsm-util.h
//
// Linux Security Module (LSM) detection utilities.
//
// Provides a pure-Rust implementation for checking whether a given
// LSM (e.g. "selinux", "apparmor", "smack", "tomoyo") is enabled
// on the running kernel by reading /sys/kernel/security/lsm.
//
// Faithfully mirrors the C implementation in lsm-util.c:
//   - Reads the comma-separated LSM list from sysfs.
//   - Handles ENOENT by checking whether securityfs is mounted.
//   - Returns an LsmError when the status cannot be determined.

use crate::ffi::*;
use std::fs;
use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

// ── Constants ─────────────────────────────────────────────────────────────

/// Sysfs path that lists the active LSMs (comma-separated).
const LSM_LIST_PATH: &str = "/sys/kernel/security/lsm";

/// Path to the securityfs mount point.
const SECURITY_PATH: &str = "/sys/kernel/security";

// ── Error type ────────────────────────────────────────────────────────────

/// Errors that can occur when querying LSM support.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LsmError {
    /// `/sys/kernel/security/lsm` could not be read.
    ReadLsmFailed(io::ErrorKind),
    /// Failed to check whether `/sys/kernel/security` is a mount point.
    MountPointCheckFailed(io::ErrorKind),
    /// securityfs is not mounted; LSM status is indeterminate.
    SecurityfsNotMounted,
}

impl std::fmt::Display for LsmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LsmError::ReadLsmFailed(kind) => {
                write!(f, "failed to read {}: {kind}", LSM_LIST_PATH)
            }
            LsmError::MountPointCheckFailed(kind) => {
                write!(
                    f,
                    "failed to check if {} is a mount point: {kind}",
                    SECURITY_PATH
                )
            }
            LsmError::SecurityfsNotMounted => {
                write!(
                    f,
                    "{} is not mounted, can't determine LSM status",
                    SECURITY_PATH
                )
            }
        }
    }
}

impl std::error::Error for LsmError {}

// ── Public API ────────────────────────────────────────────────────────────

/// Check whether a given Linux Security Module is supported by the running kernel.
///
/// Reads `/sys/kernel/security/lsm`, which contains a comma-separated list of
/// active LSM names (e.g. `"selinux,apparmor, smack"`), and checks whether
/// `name` appears in that list.
///
/// # Arguments
/// * `name` - The LSM name to check (e.g. `"selinux"`, `"apparmor"`).
///
/// # Returns
/// * `Ok(true)`  — the LSM is listed as active.
/// * `Ok(false)` — the LSM is not listed, or the securityfs mount point does
///   not exist at all (meaning no LSM support is available).
/// * `Err(LsmError)` — an I/O error occurred while reading the LSM list or
///   checking mount-point status.
///
/// # Port-sync
/// Equivalent to `lsm_supported(const char *name)` in `src/shared/lsm-util.c`.
pub fn lsm_supported(name: &str) -> Result<bool, LsmError> {
    // Step 1: Try to read the comma-separated LSM list.
    match fs::read_to_string(LSM_LIST_PATH) {
        Ok(lsm_list) => {
            // Step 2: Search for `name` among the comma-separated entries.
            for entry in lsm_list.split(',') {
                if entry == name {
                    return Ok(true);
                }
            }
            Ok(false)
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            // The LSM list file does not exist — securityfs might not be mounted.
            // Check whether /sys/kernel/security is a mount point.
            match path_is_mount_point(Path::new(SECURITY_PATH)) {
                Ok(true) => {
                    // securityfs IS mounted but /sys/kernel/security/lsm is missing.
                    // The C code returns `false` in this case (LSM support not available).
                    Ok(false)
                }
                Ok(false) => {
                    // securityfs is NOT mounted — we cannot determine LSM status.
                    // The C code returns ENOPKG via SYNTHETIC_ERRNO.
                    Err(LsmError::SecurityfsNotMounted)
                }
                Err(e2) => Err(LsmError::MountPointCheckFailed(e2.kind())),
            }
        }
        Err(e) => Err(LsmError::ReadLsmFailed(e.kind())),
    }
}

// ── Internal helpers ──────────────────────────────────────────────────────

/// Check if a path is a mount point by comparing device IDs of the path
/// and its parent directory.
///
/// This mirrors the approach used in `mount_util::path_is_mount_point()`.
/// We keep it local to avoid cross-module coupling for this simple utility.
fn path_is_mount_point(path: &Path) -> io::Result<bool> {
    let metadata = fs::metadata(path)?;
    let parent = path.parent().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "path has no parent directory")
    })?;
    let parent_metadata = fs::metadata(parent)?;
    Ok(metadata.dev() != parent_metadata.dev())
}

/// Parse a comma-separated LSM list string and collect all entries.
///
/// This is the pure-parsing counterpart of the loop in the C code that
/// calls `extract_first_word(&p, &word, ",", 0)`.
fn parse_lsm_list(lsm_list: &str) -> Vec<&str> {
    lsm_list.split(',').filter(|s| !s.is_empty()).collect()
}

/// Check whether a given name appears in a comma-separated LSM list.
///
/// This is the pure-logic extraction from `lsm_supported`, useful for
/// testing parsing independently from filesystem access.
fn lsm_name_in_list(name: &str, lsm_list: &str) -> bool {
    parse_lsm_list(lsm_list).iter().any(|&entry| entry == name)
}

/// Build the path to the LSM list file (used for testability of path construction).
fn lsm_list_path() -> PathBuf {
    PathBuf::from(LSM_LIST_PATH)
}

/// Build the path to the securityfs mount point (used for testability).
fn security_path() -> PathBuf {
    PathBuf::from(SECURITY_PATH)
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Parsing tests ──────────────────────────────────────────────────

    #[test]
    fn test_parse_lsm_list_single() {
        let entries = parse_lsm_list("selinux");
        assert_eq!(entries, vec!["selinux"]);
    }

    #[test]
    fn test_parse_lsm_list_multiple() {
        let entries = parse_lsm_list("selinux,apparmor,smack");
        assert_eq!(entries, vec!["selinux", "apparmor", "smack"]);
    }

    #[test]
    fn test_parse_lsm_list_empty_string() {
        let entries = parse_lsm_list("");
        assert!(entries.is_empty());
    }

    #[test]
    fn test_parse_lsm_list_trailing_comma() {
        let entries = parse_lsm_list("selinux,");
        assert_eq!(entries, vec!["selinux"]);
    }

    #[test]
    fn test_parse_lsm_list_leading_comma() {
        let entries = parse_lsm_list(",selinux");
        assert_eq!(entries, vec!["selinux"]);
    }

    #[test]
    fn test_parse_lsm_list_only_commas() {
        let entries = parse_lsm_list(",,,");
        assert!(entries.is_empty());
    }

    // ── Name-in-list tests ─────────────────────────────────────────────

    #[test]
    fn test_lsm_name_in_list_found() {
        assert!(lsm_name_in_list("selinux", "selinux,apparmor,smack"));
    }

    #[test]
    fn test_lsm_name_in_list_found_first() {
        assert!(lsm_name_in_list("selinux", "selinux"));
    }

    #[test]
    fn test_lsm_name_in_list_found_last() {
        assert!(lsm_name_in_list("smack", "selinux,apparmor,smack"));
    }

    #[test]
    fn test_lsm_name_in_list_not_found() {
        assert!(!lsm_name_in_list("tomoyo", "selinux,apparmor,smack"));
    }

    #[test]
    fn test_lsm_name_in_list_empty_list() {
        assert!(!lsm_name_in_list("selinux", ""));
    }

    #[test]
    fn test_lsm_name_in_list_empty_name() {
        // Empty name should not match empty entries (filtered out).
        assert!(!lsm_name_in_list("", "selinux,apparmor"));
    }

    #[test]
    fn test_lsm_name_in_list_partial_match() {
        // "selinuxx" should NOT match "selinux".
        assert!(!lsm_name_in_list("selinuxx", "selinux,apparmor"));
    }

    #[test]
    fn test_lsm_name_in_list_case_sensitive() {
        // Matching is case-sensitive.
        assert!(!lsm_name_in_list("SELinux", "selinux,apparmor"));
    }

    // ── Path construction tests ────────────────────────────────────────

    #[test]
    fn test_lsm_list_path_value() {
        assert_eq!(lsm_list_path(), PathBuf::from("/sys/kernel/security/lsm"));
    }

    #[test]
    fn test_security_path_value() {
        assert_eq!(security_path(), PathBuf::from("/sys/kernel/security"));
    }

    // ── Integration tests (filesystem-dependent) ───────────────────────

    #[cfg(target_os = "linux")]
    #[test]
    fn test_lsm_supported_unknown_name() {
        // A completely fabricated name should never be active.
        // On any system, this must be either Ok(false) or an Err (if
        // securityfs is not mounted, which returns SecurityfsNotMounted).
        match lsm_supported("definitely_not_a_real_lsm_module_12345") {
            Ok(false) => {}                           // Expected: LSM not found in list.
            Err(LsmError::SecurityfsNotMounted) => {} // Also acceptable.
            other => panic!("unexpected result: {other:?}"),
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_lsm_supported_empty_name() {
        // An empty name should not match any real LSM entry.
        match lsm_supported("") {
            Ok(false) => {}
            Err(LsmError::SecurityfsNotMounted) => {}
            Err(LsmError::ReadLsmFailed(_)) => {}
            other => panic!("unexpected result: {other:?}"),
        }
    }

    #[test]
    fn test_lsm_supported_known_names_no_panic() {
        // Querying well-known LSM names should never panic, regardless
        // of whether they are actually active on the host.
        for name in &["selinux", "apparmor", "smack", "tomoyo", "capability"] {
            let _ = lsm_supported(name);
        }
    }

    // ── Error display tests ────────────────────────────────────────────

    #[test]
    fn test_lsm_error_display_read_failed() {
        let err = LsmError::ReadLsmFailed(io::ErrorKind::PermissionDenied);
        let msg = format!("{err}");
        assert!(msg.contains("/sys/kernel/security/lsm"));
        assert!(msg.contains("permission denied"));
    }

    #[test]
    fn test_lsm_error_display_mount_check_failed() {
        let err = LsmError::MountPointCheckFailed(io::ErrorKind::NotFound);
        let msg = format!("{err}");
        assert!(msg.contains("/sys/kernel/security"));
        assert!(msg.contains("mount point"));
    }

    #[test]
    fn test_lsm_error_display_securityfs_not_mounted() {
        let err = LsmError::SecurityfsNotMounted;
        let msg = format!("{err}");
        assert!(msg.contains("not mounted"));
        assert!(msg.contains("can't determine LSM status"));
    }

    #[test]
    fn test_lsm_error_is_send_sync() {
        // LsmError must be Send + Sync for use in async contexts.
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<LsmError>();
    }
}
