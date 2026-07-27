// SPDX-License-Identifier: LGPL-2.1-or-later
#![deny(unsafe_op_in_unsafe_fn)]
//
// PORT-SYNC: src/sysext/sysext.c
//
// System extension image manager.
//
// Manages merging and unmerging of system extension images (sysext) and
// configuration extension images (confext) into /usr/, /opt/, and /etc/
// hierarchies using overlayfs.

// ── Constants ─────────────────────────────────────────────────────────────

/// Base directory for mutable extensions.
pub const MUTABLE_EXTENSIONS_BASE_DIR: &str = "/var/lib/extensions.mutable";

/// Default overlayfs mount options for mutable extensions.
pub const MUTABLE_EXTENSIONS_MOUNT_OPTIONS: &str = "redirect_dir=on,noatime,metacopy=off,index=off";

/// Default hierarchies for sysext.
pub const SYSEXT_DEFAULT_HIERARCHIES: &[&str] = &["/usr", "/opt"];

/// Default hierarchies for confext.
pub const CONFEXT_DEFAULT_HIERARCHIES: &[&str] = &["/etc"];

/// Exit code when no extensions were found during merge.
pub const MERGE_EXIT_NOTHING_FOUND: i32 = 123;

/// Exit code when refresh was skipped during merge.
pub const MERGE_EXIT_SKIP_REFRESH: i32 = 124;

// ── Enums ─────────────────────────────────────────────────────────────────

/// Controls whether the merged hierarchy is mutable and how.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MutableMode {
    No,
    Yes,
    Auto,
    Import,
    Ephemeral,
    EphemeralImport,
}

impl MutableMode {
    /// All variants for iteration.
    pub const ALL: [MutableMode; 6] = [
        MutableMode::No,
        MutableMode::Yes,
        MutableMode::Auto,
        MutableMode::Import,
        MutableMode::Ephemeral,
        MutableMode::EphemeralImport,
    ];

    /// Parse from string.
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "no" => Some(MutableMode::No),
            "yes" => Some(MutableMode::Yes),
            "auto" => Some(MutableMode::Auto),
            "import" => Some(MutableMode::Import),
            "ephemeral" => Some(MutableMode::Ephemeral),
            "ephemeral-import" => Some(MutableMode::EphemeralImport),
            _ => None,
        }
    }

    /// Convert to string.
    pub fn to_str(self) -> &'static str {
        match self {
            MutableMode::No => "no",
            MutableMode::Yes => "yes",
            MutableMode::Auto => "auto",
            MutableMode::Import => "import",
            MutableMode::Ephemeral => "ephemeral",
            MutableMode::EphemeralImport => "ephemeral-import",
        }
    }
}

/// Image class: sysext or confext.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageClass {
    Sysext,
    Confext,
}

impl ImageClass {
    /// Get the short identifier string.
    pub fn short_identifier(self) -> &'static str {
        match self {
            ImageClass::Sysext => "sysext",
            ImageClass::Confext => "confext",
        }
    }

    /// Get the full identifier string.
    pub fn full_identifier(self) -> &'static str {
        match self {
            ImageClass::Sysext => "systemd-sysext",
            ImageClass::Confext => "systemd-confext",
        }
    }

    /// Get the dot directory name for metadata.
    pub fn dot_directory_name(self) -> &'static str {
        match self {
            ImageClass::Sysext => ".systemd-sysext",
            ImageClass::Confext => ".systemd-confext",
        }
    }

    /// Get the plural short identifier.
    pub fn short_identifier_plural(self) -> &'static str {
        match self {
            ImageClass::Sysext => "extensions",
            ImageClass::Confext => "confexts",
        }
    }

    /// Get the default hierarchies for this image class.
    pub fn default_hierarchies(self) -> &'static [&'static str] {
        match self {
            ImageClass::Sysext => &["/usr", "/opt"],
            ImageClass::Confext => &["/etc"],
        }
    }

    /// Get the environment variable name for hierarchies.
    pub fn hierarchies_env(self) -> &'static str {
        match self {
            ImageClass::Sysext => "SYSTEMD_SYSEXT_HIERARCHIES",
            ImageClass::Confext => "SYSTEMD_CONFEXT_HIERARCHIES",
        }
    }

    /// Get the environment variable name for mutable mode.
    pub fn mutable_mode_env(self) -> &'static str {
        match self {
            ImageClass::Sysext => "SYSTEMD_SYSEXT_MUTABLE_MODE",
            ImageClass::Confext => "SYSTEMD_CONFEXT_MUTABLE_MODE",
        }
    }

    /// Get the environment variable name for overlayfs mount options.
    pub fn overlayfs_opts_env(self) -> &'static str {
        match self {
            ImageClass::Sysext => "SYSTEMD_SYSEXT_OVERLAYFS_MOUNT_OPTIONS",
            ImageClass::Confext => "SYSTEMD_CONFEXT_OVERLAYFS_MOUNT_OPTIONS",
        }
    }
}

/// Result of a merge attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MergeResult {
    NothingFound,
    Mounted,
    SkipRefresh,
}

impl MergeResult {
    /// Convert to process exit code.
    pub fn exit_code(self) -> i32 {
        match self {
            MergeResult::NothingFound => MERGE_EXIT_NOTHING_FOUND,
            MergeResult::Mounted => 0,
            MergeResult::SkipRefresh => MERGE_EXIT_SKIP_REFRESH,
        }
    }
}

// ── Error type ────────────────────────────────────────────────────────────

/// Errors from sysext operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SysextError {
    /// Insufficient privileges.
    PermissionDenied,
    /// Path not found.
    PathNotFound(String),
    /// Mount operation failed.
    MountFailed(String),
    /// Configuration parse error.
    ConfigError(String),
    /// D-Bus connection or call failed.
    BusError(String),
    /// Invalid mutable mode string.
    InvalidMutableMode(String),
    /// Extension metadata error.
    MetadataError(String),
}

impl std::fmt::Display for SysextError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SysextError::PermissionDenied => write!(f, "Need to be privileged"),
            SysextError::PathNotFound(p) => write!(f, "Path not found: {}", p),
            SysextError::MountFailed(msg) => write!(f, "Mount failed: {}", msg),
            SysextError::ConfigError(msg) => write!(f, "Configuration error: {}", msg),
            SysextError::BusError(msg) => write!(f, "D-Bus error: {}", msg),
            SysextError::InvalidMutableMode(s) => {
                write!(f, "Invalid mutable mode: {}", s)
            }
            SysextError::MetadataError(msg) => write!(f, "Extension metadata error: {}", msg),
        }
    }
}

impl std::error::Error for SysextError {}

// ── Helper functions ──────────────────────────────────────────────────────

/// Convert a hierarchy path to a single path component by stripping leading
/// and trailing slashes and replacing remaining slashes with dots.
///
/// Mirrors the C `hierarchy_as_single_path_component()`.
pub fn hierarchy_as_single_path_component(hierarchy: &str) -> String {
    let stripped = hierarchy.trim_matches('/');
    stripped.replace('/', ".")
}

/// Check if a mutable mode is one of the ephemeral variants.
pub fn is_ephemeral_mode(mode: MutableMode) -> bool {
    mode == MutableMode::Ephemeral || mode == MutableMode::EphemeralImport
}

/// Check if a mutable mode requires creating directories.
pub fn mode_requires_directory(mode: MutableMode) -> bool {
    mode == MutableMode::Yes
        || mode == MutableMode::Ephemeral
        || mode == MutableMode::EphemeralImport
}

/// Build overlayfs options string from lower dirs, upper dir, work dir, and
/// mount options.
pub fn build_overlayfs_options<S: AsRef<str>>(
    lower_dirs: &[S],
    upper_dir: Option<&str>,
    work_dir: Option<&str>,
    mount_options: Option<&str>,
) -> String {
    let mut options = format!(
        "lowerdir={}",
        lower_dirs
            .iter()
            .map(|s| s.as_ref())
            .collect::<Vec<_>>()
            .join(":")
    );

    if let Some(upper) = upper_dir {
        options.push_str(&format!(",upperdir={}", upper));
        if let Some(work) = work_dir {
            options.push_str(&format!(",workdir={}", work));
        }
    }

    if let Some(opts) = mount_options {
        if !opts.is_empty() {
            options.push_str(&format!(",{}", opts));
        }
    } else if upper_dir.is_some() {
        // Use default mutable options when no options given but upper dir exists
        options.push_str(&format!(",{}", MUTABLE_EXTENSIONS_MOUNT_OPTIONS));
    }

    options
}

/// Check if two paths are on the same filesystem by comparing device IDs.
/// This is a pure logic check — callers provide the device IDs.
pub fn paths_on_same_fs(dev1: u64, dev2: u64) -> bool {
    dev1 == dev2
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mutable_mode_from_str() {
        assert_eq!(MutableMode::from_str("no"), Some(MutableMode::No));
        assert_eq!(MutableMode::from_str("yes"), Some(MutableMode::Yes));
        assert_eq!(MutableMode::from_str("auto"), Some(MutableMode::Auto));
        assert_eq!(MutableMode::from_str("import"), Some(MutableMode::Import));
        assert_eq!(
            MutableMode::from_str("ephemeral"),
            Some(MutableMode::Ephemeral)
        );
        assert_eq!(
            MutableMode::from_str("ephemeral-import"),
            Some(MutableMode::EphemeralImport)
        );
        assert_eq!(MutableMode::from_str("invalid"), None);
    }

    #[test]
    fn test_mutable_mode_to_str() {
        assert_eq!(MutableMode::No.to_str(), "no");
        assert_eq!(MutableMode::Yes.to_str(), "yes");
        assert_eq!(MutableMode::Auto.to_str(), "auto");
        assert_eq!(MutableMode::Import.to_str(), "import");
        assert_eq!(MutableMode::Ephemeral.to_str(), "ephemeral");
        assert_eq!(MutableMode::EphemeralImport.to_str(), "ephemeral-import");
    }

    #[test]
    fn test_mutable_mode_roundtrip() {
        for mode in MutableMode::ALL {
            assert_eq!(MutableMode::from_str(mode.to_str()), Some(mode));
        }
    }

    #[test]
    fn test_image_class_sysext_identifiers() {
        assert_eq!(ImageClass::Sysext.short_identifier(), "sysext");
        assert_eq!(ImageClass::Sysext.full_identifier(), "systemd-sysext");
        assert_eq!(ImageClass::Sysext.dot_directory_name(), ".systemd-sysext");
        assert_eq!(ImageClass::Sysext.short_identifier_plural(), "extensions");
    }

    #[test]
    fn test_image_class_confext_identifiers() {
        assert_eq!(ImageClass::Confext.short_identifier(), "confext");
        assert_eq!(ImageClass::Confext.full_identifier(), "systemd-confext");
        assert_eq!(ImageClass::Confext.dot_directory_name(), ".systemd-confext");
        assert_eq!(ImageClass::Confext.short_identifier_plural(), "confexts");
    }

    #[test]
    fn test_image_class_default_hierarchies() {
        assert_eq!(ImageClass::Sysext.default_hierarchies(), &["/usr", "/opt"]);
        assert_eq!(ImageClass::Confext.default_hierarchies(), &["/etc"]);
    }

    #[test]
    fn test_hierarchy_as_single_path_component() {
        assert_eq!(hierarchy_as_single_path_component("/usr"), "usr");
        assert_eq!(hierarchy_as_single_path_component("/opt"), "opt");
        assert_eq!(hierarchy_as_single_path_component("/etc"), "etc");
        assert_eq!(
            hierarchy_as_single_path_component("/foo/bar/baz/"),
            "foo.bar.baz"
        );
        assert_eq!(hierarchy_as_single_path_component("///"), "");
    }

    #[test]
    fn test_is_ephemeral_mode() {
        assert!(!is_ephemeral_mode(MutableMode::No));
        assert!(!is_ephemeral_mode(MutableMode::Yes));
        assert!(!is_ephemeral_mode(MutableMode::Auto));
        assert!(!is_ephemeral_mode(MutableMode::Import));
        assert!(is_ephemeral_mode(MutableMode::Ephemeral));
        assert!(is_ephemeral_mode(MutableMode::EphemeralImport));
    }

    #[test]
    fn test_mode_requires_directory() {
        assert!(!mode_requires_directory(MutableMode::No));
        assert!(mode_requires_directory(MutableMode::Yes));
        assert!(mode_requires_directory(MutableMode::Ephemeral));
        assert!(mode_requires_directory(MutableMode::EphemeralImport));
        assert!(!mode_requires_directory(MutableMode::Auto));
    }

    #[test]
    fn test_build_overlayfs_options_readonly() {
        let opts = build_overlayfs_options::<&str>(&["/lower1", "/lower2"], None, None, None);
        assert!(opts.starts_with("lowerdir=/lower1:/lower2"));
        assert!(!opts.contains("upperdir"));
        assert!(!opts.contains("workdir"));
    }

    #[test]
    fn test_build_overlayfs_options_mutable() {
        let opts =
            build_overlayfs_options::<&str>(&["/lower1"], Some("/upper"), Some("/work"), None);
        assert!(opts.contains("lowerdir=/lower1"));
        assert!(opts.contains("upperdir=/upper"));
        assert!(opts.contains("workdir=/work"));
        assert!(opts.contains(MUTABLE_EXTENSIONS_MOUNT_OPTIONS));
    }

    #[test]
    fn test_build_overlayfs_options_custom_mount_options() {
        let opts = build_overlayfs_options::<&str>(
            &["/lower"],
            Some("/upper"),
            Some("/work"),
            Some("custom_option=1"),
        );
        assert!(opts.contains("custom_option=1"));
        assert!(!opts.contains(MUTABLE_EXTENSIONS_MOUNT_OPTIONS));
    }

    #[test]
    fn test_merge_result_exit_codes() {
        assert_eq!(
            MergeResult::NothingFound.exit_code(),
            MERGE_EXIT_NOTHING_FOUND
        );
        assert_eq!(MergeResult::Mounted.exit_code(), 0);
        assert_eq!(
            MergeResult::SkipRefresh.exit_code(),
            MERGE_EXIT_SKIP_REFRESH
        );
    }

    #[test]
    fn test_paths_on_same_fs() {
        assert!(paths_on_same_fs(42, 42));
        assert!(!paths_on_same_fs(42, 43));
    }

    #[test]
    fn test_error_display() {
        assert!(format!("{}", SysextError::PermissionDenied).contains("privileged"));
        assert!(format!("{}", SysextError::InvalidMutableMode("bad".into())).contains("bad"));
    }
}
