// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/tomoyo-util.c, src/shared/tomoyo-util.h
//
// TOMOYO MAC (Mandatory Access Control) support detection utility.
//
// TOMOYO is a Mandatory Access Control (MAC) implementation in the Linux
// kernel. This module provides functions to detect whether TOMOYO is
// enabled and available on the current system by checking for the
// presence of the TOMOYO version file in sysfs.

use std::path::Path;
use std::sync::OnceLock;

// ── Constants ─────────────────────────────────────────────────────────────

/// Path to the TOMOYO version file in sysfs.
/// If this file exists, TOMOYO is enabled in the kernel.
pub const TOMOYO_VERSION_PATH: &str = "/sys/kernel/security/tomoyo/version";

// ── Core detection logic ─────────────────────────────────────────────────

/// Check if a TOMOYO version file exists at the given path.
///
/// This is the core detection logic, factored out for testability.
/// Uses `Path::exists()` which internally calls `stat()` on the
/// filesystem, equivalent to `access(path, F_OK)` in the original C.
///
/// Note: `Path::exists()` returns `false` for broken symlinks, matching
/// the behavior of `access(F_OK)`.
pub(crate) fn check_tomoyo_at_path(path: &Path) -> bool {
    path.exists()
}

/// Check if TOMOYO MAC is available at the given path, returning a `Result`.
///
/// Returns `Ok(true)` if the path exists, `Ok(false)` if it doesn't,
/// or `Err` if the filesystem check itself fails (e.g., permission denied
/// on a parent directory). This allows callers to distinguish between
/// "not available" and "unable to determine".
pub fn check_tomoyo_at_path_result(path: &Path) -> Result<bool, std::io::Error> {
    path.try_exists()
}

// ── Public API ───────────────────────────────────────────────────────────

/// Check if TOMOYO MAC is available on the system.
///
/// Returns `true` if `/sys/kernel/security/tomoyo/version` exists,
/// indicating that the TOMOYO security module is enabled in the kernel.
///
/// The result is lazily computed and cached for the lifetime of the process,
/// mirroring the `static int cached_use` behavior in the original C
/// implementation. This is important because `mac_tomoyo_use()` may be
/// called frequently and the TOMOYO status does not change at runtime.
pub fn mac_tomoyo_use() -> bool {
    static CACHED: OnceLock<bool> = OnceLock::new();
    *CACHED.get_or_init(|| check_tomoyo_at_path(Path::new(TOMOYO_VERSION_PATH)))
}

/// Check if TOMOYO MAC is available, returning a `Result`.
///
/// This variant does **not** cache the result, allowing callers to handle
/// I/O errors explicitly. Use this when you need to distinguish between
/// "TOMOYO is not available" and "could not determine TOMOYO availability".
pub fn mac_tomoyo_use_result() -> Result<bool, std::io::Error> {
    check_tomoyo_at_path_result(Path::new(TOMOYO_VERSION_PATH))
}

/// Get the sysfs path used to detect TOMOYO availability.
///
/// Returns a static reference to the `Path` that is checked by
/// `mac_tomoyo_use()`. Useful for logging and debugging.
pub fn tomoyo_version_path() -> &'static Path {
    Path::new(TOMOYO_VERSION_PATH)
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    /// RAII helper that creates a temporary file and removes it on drop.
    struct TempFile {
        path: PathBuf,
    }

    impl TempFile {
        fn new(filename: &str) -> Self {
            let dir = std::env::temp_dir();
            let path = dir.join(filename);
            fs::write(&path, "2.6\n").unwrap();
            Self { path }
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TempFile {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.path);
        }
    }

    /// RAII helper that creates a temporary directory and removes it on drop.
    struct TempDir {
        path: PathBuf,
    }

    impl TempDir {
        fn new(prefix: &str) -> Self {
            let dir = std::env::temp_dir().join(format!("{}_{}", prefix, std::process::id()));
            fs::create_dir_all(&dir).unwrap();
            Self { path: dir }
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    // ── Constant tests ────────────────────────────────────────────────

    #[test]
    fn test_tomoyo_version_path_constant_value() {
        assert_eq!(TOMOYO_VERSION_PATH, "/sys/kernel/security/tomoyo/version");
    }

    #[test]
    fn test_tomoyo_version_path_is_not_empty() {
        assert!(!TOMOYO_VERSION_PATH.is_empty());
    }

    #[test]
    fn test_tomoyo_version_path_starts_with_sys() {
        assert!(
            TOMOYO_VERSION_PATH.starts_with("/sys/"),
            "TOMOYO path should be under /sys/"
        );
    }

    #[test]
    fn test_tomoyo_version_path_contains_tomoyo() {
        assert!(
            TOMOYO_VERSION_PATH.contains("tomoyo"),
            "TOMOYO path should contain 'tomoyo'"
        );
    }

    // ── tomoyo_version_path() tests ──────────────────────────────────

    #[test]
    fn test_tomoyo_version_path_function() {
        let path = tomoyo_version_path();
        assert_eq!(path.as_os_str(), TOMOYO_VERSION_PATH);
    }

    #[test]
    fn test_tomoyo_version_path_is_absolute() {
        let path = tomoyo_version_path();
        assert!(path.is_absolute(), "TOMOYO path must be absolute");
    }

    // ── check_tomoyo_at_path() tests ─────────────────────────────────

    #[test]
    fn test_check_tomoyo_at_path_existing_file() {
        let tmp = TempFile::new("tomoyo_test_version_existing");
        assert!(check_tomoyo_at_path(tmp.path()));
    }

    #[test]
    fn test_check_tomoyo_at_path_nonexistent_file() {
        let path = Path::new("/tmp/tomoyo_test_nonexistent_file_12345");
        // Ensure it doesn't exist
        let _ = fs::remove_file(path);
        assert!(!check_tomoyo_at_path(path));
    }

    #[test]
    fn test_check_tomoyo_at_path_directory() {
        let tmp = TempDir::new("tomoyo_test_dir");
        assert!(check_tomoyo_at_path(tmp.path()));
    }

    #[test]
    fn test_check_tomoyo_at_path_deep_nonexistent() {
        let path = Path::new("/tmp/tomoyo_test_deep/nested/path/version");
        assert!(!check_tomoyo_at_path(path));
    }

    // ── check_tomoyo_at_path_result() tests ──────────────────────────

    #[test]
    fn test_check_tomoyo_at_path_result_existing_file() {
        let tmp = TempFile::new("tomoyo_test_version_result");
        let result = check_tomoyo_at_path_result(tmp.path());
        assert_eq!(result.unwrap(), true);
    }

    #[test]
    fn test_check_tomoyo_at_path_result_nonexistent_file() {
        let path = Path::new("/tmp/tomoyo_test_result_nonexistent_12345");
        let _ = fs::remove_file(path);
        let result = check_tomoyo_at_path_result(path);
        assert_eq!(result.unwrap(), false);
    }

    // ── mac_tomoyo_use() tests ───────────────────────────────────────

    #[test]
    fn test_mac_tomoyo_use_returns_bool() {
        // Should not panic and should return a valid boolean
        let result = mac_tomoyo_use();
        // We don't assert true or false since it depends on the host kernel
        let _ = result;
    }

    #[test]
    fn test_mac_tomoyo_use_cached_consistency() {
        let result1 = mac_tomoyo_use();
        let result2 = mac_tomoyo_use();
        assert_eq!(
            result1, result2,
            "mac_tomoyo_use() must return consistent results (cached)"
        );
    }

    // ── mac_tomoyo_use_result() tests ────────────────────────────────

    #[test]
    fn test_mac_tomoyo_use_result_returns_result() {
        let result = mac_tomoyo_use_result();
        // Should be Ok(true) or Ok(false) — Err only if sysfs is broken
        match result {
            Ok(_) => {}
            Err(e) => {
                // If we get an error, it should be a real I/O error
                assert!(!e.to_string().is_empty());
            }
        }
    }

    // ── Symlink tests ────────────────────────────────────────────────

    #[test]
    fn test_check_tomoyo_at_path_symlink_to_existing_file() {
        let tmp = TempFile::new("tomoyo_test_symlink_target");
        let link_path = std::env::temp_dir().join("tomoyo_test_symlink_link");
        let _ = fs::remove_file(&link_path);
        std::os::unix::fs::symlink(tmp.path(), &link_path).unwrap();

        assert!(check_tomoyo_at_path(&link_path));

        let _ = fs::remove_file(&link_path);
    }

    #[test]
    fn test_check_tomoyo_at_path_broken_symlink() {
        let link_path = std::env::temp_dir().join("tomoyo_test_broken_symlink");
        let _ = fs::remove_file(&link_path);
        // Symlink to a target that doesn't exist
        std::os::unix::fs::symlink("/tmp/tomoyo_test_does_not_exist_99999", &link_path).unwrap();

        // Broken symlinks should return false (matches access(F_OK) behavior)
        assert!(!check_tomoyo_at_path(&link_path));

        let _ = fs::remove_file(&link_path);
    }
}
