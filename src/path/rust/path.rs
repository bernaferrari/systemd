// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/path/path-tool.c
//
// Queries and lists systemd path unit properties.
//
// Provides a table of well-known path identifiers and their string names,
// with lookup and sorted listing capabilities matching the C implementation.

// ── Constants ─────────────────────────────────────────────────────────────

/// Well-known systemd path identifiers, indexed by sd-path enum values.
/// Mirrors the `path_table` array in path-tool.c.
pub const PATH_TABLE: &[(&str, &str)] = &[
    ("temporary", "Temporary directory"),
    ("temporary-large", "Temporary directory (large)"),
    ("system-search-configuration", "System search configuration"),
    ("system-binaries", "System binaries"),
    ("system-include", "System include"),
    ("system-library-private", "System library private"),
    ("system-library-arch", "System library arch"),
    ("system-shared", "System shared"),
    (
        "system-configuration-factory",
        "System configuration factory",
    ),
    ("system-state-factory", "System state factory"),
    ("system-configuration", "System configuration"),
    ("system-runtime", "System runtime"),
    ("system-runtime-logs", "System runtime logs"),
    ("system-state-private", "System state private"),
    ("system-state-logs", "System state logs"),
    ("system-state-cache", "System state cache"),
    ("system-state-spool", "System state spool"),
    ("user-binaries", "User binaries"),
    ("user-library-private", "User library private"),
    ("user-library-arch", "User library arch"),
    ("user-shared", "User shared"),
    ("user-configuration", "User configuration"),
    ("user-runtime", "User runtime"),
    ("user-state-cache", "User state cache"),
    ("user-state-private", "User state private"),
    ("user", "User home"),
    ("user-documents", "User documents"),
    ("user-music", "User music"),
    ("user-pictures", "User pictures"),
    ("user-videos", "User videos"),
    ("user-download", "User download"),
    ("user-public", "User public"),
    ("user-templates", "User templates"),
    ("user-desktop", "User desktop"),
    ("search-binaries", "Search binaries"),
    ("search-binaries-default", "Search binaries default"),
    ("search-library-private", "Search library private"),
    ("search-library-arch", "Search library arch"),
    ("search-shared", "Search shared"),
    (
        "search-configuration-factory",
        "Search configuration factory",
    ),
    ("search-state-factory", "Search state factory"),
    ("search-configuration", "Search configuration"),
    ("systemd-util", "systemd utility directory"),
    ("systemd-system-unit", "systemd system unit"),
    ("systemd-system-preset", "systemd system preset"),
    ("systemd-system-conf", "systemd system conf"),
    ("systemd-user-unit", "systemd user unit"),
    ("systemd-user-preset", "systemd user preset"),
    ("systemd-user-conf", "systemd user conf"),
    ("systemd-initrd-preset", "systemd initrd preset"),
    ("systemd-search-system-unit", "systemd search system unit"),
    ("systemd-search-user-unit", "systemd search user unit"),
    ("systemd-system-generator", "systemd system generator"),
    ("systemd-user-generator", "systemd user generator"),
    (
        "systemd-search-system-generator",
        "systemd search system generator",
    ),
    (
        "systemd-search-user-generator",
        "systemd search user generator",
    ),
    ("systemd-sleep", "systemd sleep"),
    ("systemd-shutdown", "systemd shutdown"),
    ("tmpfiles", "tmpfiles"),
    ("sysusers", "sysusers"),
    ("sysctl", "sysctl"),
    ("binfmt", "binfmt"),
    ("modules-load", "modules-load"),
    ("catalog", "catalog"),
    ("systemd-search-network", "systemd search network"),
    (
        "systemd-system-environment-generator",
        "systemd system environment generator",
    ),
    (
        "systemd-user-environment-generator",
        "systemd user environment generator",
    ),
    (
        "systemd-search-system-environment-generator",
        "systemd search system environment generator",
    ),
    (
        "systemd-search-user-environment-generator",
        "systemd search user environment generator",
    ),
    ("system-credential-store", "System credential store"),
    (
        "system-search-credential-store",
        "System search credential store",
    ),
    (
        "system-credential-store-encrypted",
        "System credential store encrypted",
    ),
    (
        "system-search-credential-store-encrypted",
        "System search credential store encrypted",
    ),
    ("user-credential-store", "User credential store"),
    (
        "user-search-credential-store",
        "User search credential store",
    ),
    (
        "user-credential-store-encrypted",
        "User credential store encrypted",
    ),
    (
        "user-search-credential-store-encrypted",
        "User search credential store encrypted",
    ),
];

// ── Error type ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Errno(pub i32);

impl std::fmt::Display for Errno {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "errno {}", self.0)
    }
}

impl std::error::Error for Errno {}

pub type Result<T> = std::result::Result<T, Errno>;

// ── Path config ───────────────────────────────────────────────────────────

/// Configuration for systemd-path invocation, mirroring the static args in path-tool.c.
#[derive(Debug, Clone)]
pub struct PathConfig {
    /// Optional suffix to append to queried paths (`--suffix=`).
    pub suffix: Option<String>,
}

impl Default for PathConfig {
    fn default() -> Self {
        Self { suffix: None }
    }
}

impl PathConfig {
    pub fn new() -> Self {
        Self::default()
    }
}

// ── Lookup helpers ────────────────────────────────────────────────────────

/// Look up a path name in the table and return its index.
/// Corresponds to the linear scan in `print_path()` in path-tool.c.
pub fn find_path_index(name: &str) -> Option<usize> {
    PATH_TABLE.iter().position(|(key, _)| *key == name)
}

/// Return all path names sorted lexicographically.
/// Corresponds to `list_paths()` which sorts `order[]` by name via `order_cmp()`.
pub fn sorted_path_names() -> Vec<&'static str> {
    let mut names: Vec<&str> = PATH_TABLE.iter().map(|(name, _)| *name).collect();
    names.sort();
    names
}

/// Build the suffix string for display. Returns the suffix if set, else empty.
pub fn format_path_suffix(config: &PathConfig) -> &str {
    config.suffix.as_deref().unwrap_or("")
}

/// Validate that a path name exists in the table.
/// Returns `Ok(())` if found, or an error corresponding to `EOPNOTSUPP`.
pub fn validate_path_name(name: &str) -> Result<()> {
    if find_path_index(name).is_some() {
        Ok(())
    } else {
        Err(Errno(-95)) // -EOPNOTSUPP
    }
}

/// Return the description for a given path name, if found.
pub fn path_description(name: &str) -> Option<&'static str> {
    PATH_TABLE
        .iter()
        .find_map(|(key, desc)| if *key == name { Some(*desc) } else { None })
}

/// Count of known path entries.
pub fn path_count() -> usize {
    PATH_TABLE.len()
}

/// Return all path entries matching a case-insensitive prefix.
pub fn paths_with_prefix(prefix: &str) -> Vec<&'static str> {
    let lower = prefix.to_ascii_lowercase();
    PATH_TABLE
        .iter()
        .filter(|(name, _)| name.to_ascii_lowercase().starts_with(&lower))
        .map(|(name, _)| *name)
        .collect()
}

/// Format a path line for display: "name: path" or "name: path/suffix".
/// Corresponds to the printf in `list_paths()`.
pub fn format_path_line(name: &str, resolved_path: &str, config: &PathConfig) -> String {
    let suffix = format_path_suffix(config);
    format!("{}:{}{}", name, resolved_path, suffix)
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn find_known_path() {
        assert!(find_path_index("temporary").is_some());
        assert!(find_path_index("system-binaries").is_some());
        assert!(find_path_index("user").is_some());
    }

    #[test]
    fn find_unknown_path_returns_none() {
        assert!(find_path_index("nonexistent-path-xyz").is_none());
    }

    #[test]
    fn sorted_path_names_is_sorted() {
        let names = sorted_path_names();
        for window in names.windows(2) {
            assert!(
                window[0] <= window[1],
                "not sorted: {} > {}",
                window[0],
                window[1]
            );
        }
    }

    #[test]
    fn sorted_path_names_contains_all() {
        let sorted = sorted_path_names();
        assert_eq!(sorted.len(), PATH_TABLE.len());
    }

    #[test]
    fn validate_known_names() {
        assert!(validate_path_name("temporary").is_ok());
        assert!(validate_path_name("system-binaries").is_ok());
        assert!(validate_path_name("catalog").is_ok());
    }

    #[test]
    fn validate_unknown_name_fails() {
        assert!(validate_path_name("does-not-exist").is_err());
    }

    #[test]
    fn default_config_no_suffix() {
        let cfg = PathConfig::new();
        assert!(cfg.suffix.is_none());
        assert_eq!(format_path_suffix(&cfg), "");
    }

    #[test]
    fn config_with_suffix() {
        let cfg = PathConfig {
            suffix: Some("/suffix".into()),
        };
        assert_eq!(format_path_suffix(&cfg), "/suffix");
    }

    #[test]
    fn format_path_line_without_suffix() {
        let cfg = PathConfig::new();
        let line = format_path_line("temporary", "/tmp", &cfg);
        assert_eq!(line, "temporary:/tmp");
    }

    #[test]
    fn format_path_line_with_suffix() {
        let cfg = PathConfig {
            suffix: Some("/sub".into()),
        };
        let line = format_path_line("temporary", "/tmp", &cfg);
        assert_eq!(line, "temporary:/tmp/sub");
    }

    #[test]
    fn path_description_found() {
        assert_eq!(path_description("temporary"), Some("Temporary directory"));
        assert_eq!(path_description("user"), Some("User home"));
    }

    #[test]
    fn path_description_missing() {
        assert_eq!(path_description("no-such-path"), None);
    }

    #[test]
    fn path_count_matches_table() {
        assert_eq!(path_count(), PATH_TABLE.len());
        assert!(path_count() > 50);
    }

    #[test]
    fn paths_with_prefix_system() {
        let results = paths_with_prefix("system-");
        assert!(!results.is_empty());
        assert!(results.iter().all(|n| n.starts_with("system-")));
    }

    #[test]
    fn paths_with_prefix_case_insensitive() {
        let upper = paths_with_prefix("SYSTEM-");
        let lower = paths_with_prefix("system-");
        assert_eq!(upper, lower);
    }

    #[test]
    fn find_path_index_consistency() {
        for (i, (name, _)) in PATH_TABLE.iter().enumerate() {
            assert_eq!(find_path_index(name), Some(i));
        }
    }
}
