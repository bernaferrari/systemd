// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/system-update-generator/system-update-generator.c
//
pub const UPDATE_PATHS: &[&str] = &["/system-update", "/etc/system-update"];
pub const SPECIAL_DEFAULT_TARGET: &str = "default.target";
pub const SYSTEM_UPDATE_TARGET: &str = "/usr/lib/systemd/system/system-update.target";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GeneratorResult {
    NoUpdate,
    SymlinkCreated,
    SkippedInitrd,
}

pub fn update_marker_found(existing_paths: &[&str]) -> bool {
    UPDATE_PATHS
        .iter()
        .any(|candidate| existing_paths.contains(candidate))
}

pub fn generated_symlink_path(dest_early: &str) -> String {
    format!("{dest_early}/{SPECIAL_DEFAULT_TARGET}")
}

pub fn cmdline_warning(key: &str, value: Option<&str>) -> Option<String> {
    if key == "systemd.unit" && value.is_some() {
        Some("Offline system update overridden by kernel command line systemd.unit= setting".into())
    } else if value.is_none() && matches!(key, "1" | "s" | "single" | "rescue" | "3" | "5") {
        Some(format!(
            "Offline system update overridden by runlevel \"{key}\" on the kernel command line"
        ))
    } else {
        None
    }
}

pub fn run(
    in_initrd: bool,
    existing_paths: &[&str],
    dest_early: &str,
) -> (GeneratorResult, Option<String>) {
    if in_initrd {
        return (GeneratorResult::SkippedInitrd, None);
    }
    if update_marker_found(existing_paths) {
        return (
            GeneratorResult::SymlinkCreated,
            Some(generated_symlink_path(dest_early)),
        );
    }
    (GeneratorResult::NoUpdate, None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_update_marker() {
        assert!(update_marker_found(&["/system-update"]));
    }

    #[test]
    fn ignores_missing_update_marker() {
        assert!(!update_marker_found(&["/other"]));
    }

    #[test]
    fn builds_target_path() {
        assert_eq!(
            generated_symlink_path("/tmp/gen"),
            "/tmp/gen/default.target"
        );
    }

    #[test]
    fn warns_for_systemd_unit_override() {
        assert!(cmdline_warning("systemd.unit", Some("x")).is_some());
    }

    #[test]
    fn warns_for_runlevel_override() {
        assert!(cmdline_warning("rescue", None).is_some());
    }

    #[test]
    fn does_not_warn_for_irrelevant_key() {
        assert!(cmdline_warning("quiet", None).is_none());
    }

    #[test]
    fn skips_in_initrd() {
        assert_eq!(run(true, &[], "/d").0, GeneratorResult::SkippedInitrd);
    }

    #[test]
    fn creates_symlink_when_marker_exists() {
        assert_eq!(
            run(false, &["/etc/system-update"], "/d").0,
            GeneratorResult::SymlinkCreated
        );
    }
}
