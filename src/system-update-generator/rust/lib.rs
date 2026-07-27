// SPDX-License-Identifier: LGPL-2.1-or-later
#![deny(unsafe_op_in_unsafe_fn)]
//
// PORT-SYNC: src/system-update-generator/system-update-generator.c
//
// System update generator.
//
// Implements the logic described in systemd.offline-updates(7).
// Checks for /system-update or /etc/system-update symlink and creates
// a default.target symlink pointing to system-update.target.

// ── Constants ─────────────────────────────────────────────────────────────

/// Paths checked for the system update indicator symlink.
pub const UPDATE_PATHS: &[&str] = &["/system-update", "/etc/system-update"];

/// Default target unit name used by the generator.
pub const SPECIAL_DEFAULT_TARGET: &str = "default.target";

/// System update target unit directory.
pub const SYSTEM_UPDATE_TARGET: &str = "/usr/lib/systemd/system/system-update.target";

// ── Enums ─────────────────────────────────────────────────────────────────

/// Result of the generator run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GeneratorResult {
    /// No update symlink found, nothing generated.
    NoUpdate,
    /// Symlink was created successfully.
    SymlinkCreated,
    /// Skipped because running in initrd.
    SkippedInitrd,
}

// ── Error type ────────────────────────────────────────────────────────────

/// Errors that can occur during system update generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GeneratorError {
    /// Failed to check if a path exists.
    AccessCheckFailed(String, String),
    /// Failed to create the target symlink.
    SymlinkCreateFailed(String, String),
    /// Failed to parse the kernel command line.
    CmdlineParseFailed(String),
    /// A required path is not valid UTF-8.
    InvalidUtf8(String),
}

impl std::fmt::Display for GeneratorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GeneratorError::AccessCheckFailed(path, err) => {
                write!(f, "Failed to check if {} symlink exists: {}", path, err)
            }
            GeneratorError::SymlinkCreateFailed(path, err) => {
                write!(f, "Failed to create symlink {}: {}", path, err)
            }
            GeneratorError::CmdlineParseFailed(err) => {
                write!(f, "Failed to parse kernel command line: {}", err)
            }
            GeneratorError::InvalidUtf8(path) => {
                write!(f, "Path is not valid UTF-8: {}", path)
            }
        }
    }
}

impl std::error::Error for GeneratorError {}

// ── Core logic ────────────────────────────────────────────────────────────

/// Check if a path exists (follows symlinks, returns true if accessible).
pub fn path_exists(path: &str) -> bool {
    std::path::Path::new(path).exists()
}

/// Attempt to create a symlink at `dest/default.target` pointing to the
/// system-update.target unit. Returns `Ok(())` on success.
pub fn create_update_symlink(dest: &str) -> Result<(), GeneratorError> {
    let target_path = std::path::Path::new(dest).join(SPECIAL_DEFAULT_TARGET);
    let target_str = target_path
        .to_str()
        .ok_or_else(|| GeneratorError::InvalidUtf8(dest.to_string()))?;

    // Remove existing symlink/file if present
    let _ = std::fs::remove_file(target_str);

    std::os::unix::fs::symlink(SYSTEM_UPDATE_TARGET, target_str)
        .map_err(|e| GeneratorError::SymlinkCreateFailed(target_str.to_string(), e.to_string()))
}

/// Search for the system update indicator among the standard paths.
/// Returns `Ok(true)` if an update symlink was found and target created.
pub fn generate_symlink(dest: &str) -> Result<bool, GeneratorError> {
    for p in UPDATE_PATHS {
        if path_exists(p) {
            create_update_symlink(dest)?;
            return Ok(true);
        }
    }
    Ok(false)
}

/// Parse a kernel command line item and check for conflicts.
///
/// In the C version this emits warnings when systemd.unit= or a runlevel
/// is set on the kernel command line, because those override the update.
/// Returns a list of warning messages.
pub fn check_cmdline_overrides(key: &str, value: Option<&str>) -> Vec<String> {
    let mut warnings = Vec::new();

    if key == "systemd.unit" && value.is_some() {
        warnings.push(
            "Offline system update overridden by kernel command line systemd.unit= setting"
                .to_string(),
        );
    }

    // Known runlevel keys that map to targets
    let runlevel_keys = ["1", "2", "3", "4", "5", "s", "S", "emergency"];
    if value.is_none() && runlevel_keys.contains(&key) {
        warnings.push(format!(
            "Offline system update overridden by runlevel \"{}\" on the kernel command line",
            key
        ));
    }

    warnings
}

/// Main generator entry point.
///
/// Mirrors the C `run()` function: skips in initrd, checks for update
/// symlinks, parses cmdline for warnings.
pub fn run(
    dest_early: &str,
    in_initrd: bool,
    cmdline_items: &[(&str, Option<&str>)],
) -> Result<GeneratorResult, GeneratorError> {
    if in_initrd {
        return Ok(GeneratorResult::SkippedInitrd);
    }

    let created = generate_symlink(dest_early)?;
    if !created {
        return Ok(GeneratorResult::NoUpdate);
    }

    // Parse cmdline only to emit warnings (collect them)
    let _warnings: Vec<String> = cmdline_items
        .iter()
        .flat_map(|(k, v)| check_cmdline_overrides(k, *v))
        .collect();

    Ok(GeneratorResult::SymlinkCreated)
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_update_paths_contains_expected_entries() {
        assert!(UPDATE_PATHS.contains(&"/system-update"));
        assert!(UPDATE_PATHS.contains(&"/etc/system-update"));
        assert_eq!(UPDATE_PATHS.len(), 2);
    }

    #[test]
    fn test_generator_result_variants() {
        assert_ne!(GeneratorResult::NoUpdate, GeneratorResult::SymlinkCreated);
        assert_ne!(
            GeneratorResult::SkippedInitrd,
            GeneratorResult::SymlinkCreated
        );
    }

    #[test]
    fn test_path_exists_nonexistent() {
        assert!(!path_exists("/no/such/path/ever"));
    }

    #[test]
    fn test_path_exists_root() {
        assert!(path_exists("/"));
    }

    #[test]
    fn test_check_cmdline_overrides_systemd_unit() {
        let warnings = check_cmdline_overrides("systemd.unit", Some("rescue.target"));
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("systemd.unit"));
    }

    #[test]
    fn test_check_cmdline_overrides_runlevel() {
        let warnings = check_cmdline_overrides("3", None);
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("runlevel"));
    }

    #[test]
    fn test_check_cmdline_overrides_no_override() {
        let warnings = check_cmdline_overrides("quiet", None);
        assert!(warnings.is_empty());
    }

    #[test]
    fn test_check_cmdline_overrides_systemd_unit_no_value() {
        let warnings = check_cmdline_overrides("systemd.unit", None);
        assert!(warnings.is_empty());
    }

    #[test]
    fn test_run_skips_in_initrd() {
        let result = run("/tmp", true, &[("quiet", None::<&str>)][..]).unwrap();
        assert_eq!(result, GeneratorResult::SkippedInitrd);
    }

    #[test]
    fn test_run_no_update_symlink() {
        let result = run(
            "/tmp/nonexistent_dest_for_test",
            false,
            &[("quiet", None::<&str>)][..],
        )
        .unwrap();
        assert_eq!(result, GeneratorResult::NoUpdate);
    }

    #[test]
    fn test_create_symlink_error_on_invalid_dest() {
        let result = create_update_symlink("/nonexistent/dir/that/does/not/exist");
        assert!(result.is_err());
    }

    #[test]
    fn test_error_display() {
        let err = GeneratorError::AccessCheckFailed("/test".to_string(), "ENOENT".to_string());
        let msg = format!("{}", err);
        assert!(msg.contains("/test"));
        assert!(msg.contains("ENOENT"));
    }

    #[test]
    fn test_special_default_target_constant() {
        assert_eq!(SPECIAL_DEFAULT_TARGET, "default.target");
    }

    #[test]
    fn test_system_update_target_constant() {
        assert!(SYSTEM_UPDATE_TARGET.contains("system-update.target"));
    }
}
