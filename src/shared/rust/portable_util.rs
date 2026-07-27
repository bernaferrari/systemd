// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/portable-util.c, src/shared/portable-util.h
//
// Portable service profile discovery and path resolution.
//
// Provides directory lists for portable profile lookup across system, user,
// and global runtime scopes, and searches those directories for profile
// configuration files matching a given unit suffix.

use std::path::Path;

// ── Constants ─────────────────────────────────────────────────────────────

/// Base directories for system-scope portable profiles (CONF_PATHS_NULSTR).
pub const SYSTEM_PROFILE_DIRS: &[&str] = &[
    "/etc/systemd/portable/profile",
    "/run/systemd/portable/profile",
    "/usr/local/lib/systemd/portable/profile",
    "/usr/lib/systemd/portable/profile",
];

/// Base directories for global-scope portable profiles (CONF_PATHS_STRV).
pub const GLOBAL_PROFILE_DIRS: &[&str] = &[
    "/etc/systemd/user/portable/profile",
    "/run/systemd/user/portable/profile",
    "/usr/local/lib/systemd/user/portable/profile",
    "/usr/lib/systemd/user/portable/profile",
];

// ── Enums ─────────────────────────────────────────────────────────────────

/// Runtime scope determining which profile directories to search.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeScope {
    System,
    User,
    Global,
}

// ── Error type ────────────────────────────────────────────────────────────

/// Errors returned by portable profile operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PortableError {
    /// Invalid argument (e.g. unknown scope).
    InvalidArgument,
    /// No matching profile was found.
    NotFound,
    /// An I/O error occurred while probing the filesystem.
    Io(String),
}

impl std::fmt::Display for PortableError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PortableError::InvalidArgument => write!(f, "invalid argument"),
            PortableError::NotFound => write!(f, "profile not found"),
            PortableError::Io(msg) => write!(f, "I/O error: {msg}"),
        }
    }
}

impl std::error::Error for PortableError {}

// ── Core logic ────────────────────────────────────────────────────────────

/// Return the list of profile directories for the given [`RuntimeScope`].
///
/// For [`RuntimeScope::User`] the caller supplies `user_config` and
/// `user_runtime` base paths (corresponding to the XDG config and runtime
/// directories for the user). They are prepended before the global
/// fallback directories.
///
/// For [`RuntimeScope::System`] and [`RuntimeScope::Global`] these
/// parameters are ignored.
pub fn portable_profile_dirs(
    scope: RuntimeScope,
    user_config: Option<&str>,
    user_runtime: Option<&str>,
) -> Vec<String> {
    match scope {
        RuntimeScope::System => SYSTEM_PROFILE_DIRS
            .iter()
            .map(|s| (*s).to_owned())
            .collect(),
        RuntimeScope::User => {
            let mut dirs = Vec::new();
            if let Some(p) = user_config {
                dirs.push(p.to_owned());
            }
            if let Some(p) = user_runtime {
                dirs.push(p.to_owned());
            }
            dirs.extend(GLOBAL_PROFILE_DIRS.iter().map(|s| (*s).to_owned()));
            dirs
        }
        RuntimeScope::Global => GLOBAL_PROFILE_DIRS
            .iter()
            .map(|s| (*s).to_owned())
            .collect(),
    }
}

/// Extract the extension (suffix after the last `.`) from a unit name.
///
/// Returns `None` if the string contains no dot.
pub fn unit_extension(unit: &str) -> Option<&str> {
    let idx = unit.rfind('.')?;
    Some(&unit[idx + 1..])
}

/// Build the expected profile configuration path for a given profile name
/// and unit extension inside a specific directory.
///
/// The resulting path is `<dir>/<name>/<extension>.conf`.
pub fn profile_conf_path(dir: &str, name: &str, extension: &str) -> String {
    format!("{dir}/{name}/{extension}.conf")
}

/// Check whether a path exists on the filesystem without following symlinks.
///
/// This is a safe wrapper around `std::fs::symlink_metadata` that returns
/// `true` only when the path exists and is accessible.
pub fn path_exists_nofollow(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok()
}

/// Search the given directory list for a portable profile configuration file.
///
/// For each directory `d`, the candidate path `d / name / <extension>.conf`
/// is tested, where `<extension>` is the part of `unit` after the last dot.
///
/// Returns the first existing candidate path, or a [`PortableError`] if none
/// match.
pub fn find_portable_profile(
    dirs: &[String],
    name: &str,
    unit: &str,
) -> Result<String, PortableError> {
    let extension = unit_extension(unit).ok_or(PortableError::InvalidArgument)?;

    for dir in dirs {
        let candidate = profile_conf_path(dir, name, extension);
        if path_exists_nofollow(Path::new(&candidate)) {
            return Ok(candidate);
        }
    }

    Err(PortableError::NotFound)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_scope_returns_four_standard_dirs() {
        let dirs = portable_profile_dirs(RuntimeScope::System, None, None);
        assert_eq!(dirs.len(), 4);
        assert_eq!(dirs[0], "/etc/systemd/portable/profile");
        assert_eq!(dirs[1], "/run/systemd/portable/profile");
        assert_eq!(dirs[2], "/usr/local/lib/systemd/portable/profile");
        assert_eq!(dirs[3], "/usr/lib/systemd/portable/profile");
    }

    #[test]
    fn global_scope_returns_four_user_dirs() {
        let dirs = portable_profile_dirs(RuntimeScope::Global, None, None);
        assert_eq!(dirs.len(), 4);
        assert!(dirs.iter().all(|d| d.contains("user/portable/profile")));
    }

    #[test]
    fn user_scope_prepends_user_dirs_before_global() {
        let dirs = portable_profile_dirs(
            RuntimeScope::User,
            Some("/home/alice/.config/systemd/portable/profile"),
            Some("/run/user/1000/systemd/portable/profile"),
        );
        assert_eq!(dirs.len(), 6);
        assert_eq!(dirs[0], "/home/alice/.config/systemd/portable/profile");
        assert_eq!(dirs[1], "/run/user/1000/systemd/portable/profile");
        assert!(dirs[2].contains("user/portable/profile"));
    }

    #[test]
    fn user_scope_without_runtime_dir_skips_it() {
        let dirs = portable_profile_dirs(
            RuntimeScope::User,
            Some("/home/alice/.config/systemd/portable/profile"),
            None,
        );
        assert_eq!(dirs.len(), 5);
        assert_eq!(dirs[0], "/home/alice/.config/systemd/portable/profile");
        assert!(dirs[1].contains("user/portable/profile"));
    }

    #[test]
    fn user_scope_without_any_user_dirs_only_global() {
        let dirs = portable_profile_dirs(RuntimeScope::User, None, None);
        assert_eq!(dirs.len(), 4);
        assert!(dirs.iter().all(|d| d.contains("user/portable/profile")));
    }

    #[test]
    fn unit_extension_extracts_suffix() {
        assert_eq!(unit_extension("foo.service"), Some("service"));
        assert_eq!(unit_extension("bar.socket"), Some("socket"));
        assert_eq!(unit_extension("a.b.c"), Some("c"));
        assert_eq!(unit_extension("nosuffix"), None);
        assert_eq!(unit_extension(""), None);
        assert_eq!(unit_extension("."), Some(""));
    }

    #[test]
    fn profile_conf_path_formats_correctly() {
        assert_eq!(
            profile_conf_path("/etc/systemd/portable/profile", "default", "service"),
            "/etc/systemd/portable/profile/default/service.conf"
        );
    }

    #[test]
    fn profile_conf_path_with_nested_name() {
        assert_eq!(
            profile_conf_path("/run/systemd/portable/profile", "strict", "socket"),
            "/run/systemd/portable/profile/strict/socket.conf"
        );
    }

    #[test]
    fn find_profile_returns_invalid_argument_for_no_dot() {
        let dirs: Vec<String> = vec!["/tmp/nonexistent".into()];
        let result = find_portable_profile(&dirs, "default", "nosuffix");
        assert_eq!(result.unwrap_err(), PortableError::InvalidArgument);
    }

    #[test]
    fn find_profile_returns_not_found_when_no_candidate_matches() {
        let dirs: Vec<String> = vec!["/absolutely/no/such/directory".into()];
        let result = find_portable_profile(&dirs, "default", "test.service");
        assert_eq!(result.unwrap_err(), PortableError::NotFound);
    }

    #[test]
    fn find_profile_returns_not_found_with_empty_dirs() {
        let dirs: Vec<String> = vec![];
        let result = find_portable_profile(&dirs, "default", "test.service");
        assert_eq!(result.unwrap_err(), PortableError::NotFound);
    }

    #[test]
    fn portable_error_display_messages() {
        assert_eq!(
            format!("{}", PortableError::InvalidArgument),
            "invalid argument"
        );
        assert_eq!(format!("{}", PortableError::NotFound), "profile not found");
        assert_eq!(
            format!("{}", PortableError::Io("broken".into())),
            "I/O error: broken"
        );
    }

    #[test]
    fn system_profile_dirs_constant_matches_function_output() {
        let from_fn = portable_profile_dirs(RuntimeScope::System, None, None);
        let from_const: Vec<String> = SYSTEM_PROFILE_DIRS
            .iter()
            .map(|s| (*s).to_owned())
            .collect();
        assert_eq!(from_fn, from_const);
    }

    #[test]
    fn global_profile_dirs_constant_matches_function_output() {
        let from_fn = portable_profile_dirs(RuntimeScope::Global, None, None);
        let from_const: Vec<String> = GLOBAL_PROFILE_DIRS
            .iter()
            .map(|s| (*s).to_owned())
            .collect();
        assert_eq!(from_fn, from_const);
    }
}
