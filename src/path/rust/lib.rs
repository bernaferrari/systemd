// SPDX-License-Identifier: LGPL-2.1-or-later
#![deny(unsafe_op_in_unsafe_fn)]
//
// PORT-SYNC: src/path/path-tool.c
pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    UnknownPathName(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownPathName(name) => write!(f, "path {name} not known"),
        }
    }
}

impl std::error::Error for Error {}

pub const PATH_TABLE: &[&str] = &[
    "temporary",
    "temporary-large",
    "system-search-configuration",
    "system-binaries",
    "system-include",
    "system-library-private",
    "system-library-arch",
    "system-shared",
    "system-configuration-factory",
    "system-state-factory",
    "system-configuration",
    "system-runtime",
    "system-runtime-logs",
    "system-state-private",
    "system-state-logs",
    "system-state-cache",
    "system-state-spool",
    "user-binaries",
    "user-library-private",
    "user-library-arch",
    "user-shared",
    "user-configuration",
    "user-runtime",
    "user-state-cache",
    "user-state-private",
    "user",
    "user-documents",
    "user-music",
    "user-pictures",
    "user-videos",
    "user-download",
    "user-public",
    "user-templates",
    "user-desktop",
    "search-binaries",
    "search-binaries-default",
    "search-library-private",
    "search-library-arch",
    "search-shared",
    "search-configuration-factory",
    "search-state-factory",
    "search-configuration",
    "systemd-util",
    "systemd-system-unit",
    "systemd-system-preset",
    "systemd-system-conf",
    "systemd-user-unit",
    "systemd-user-preset",
    "systemd-user-conf",
    "systemd-initrd-preset",
    "systemd-search-system-unit",
    "systemd-search-user-unit",
    "systemd-system-generator",
    "systemd-user-generator",
    "systemd-search-system-generator",
    "systemd-search-user-generator",
    "systemd-sleep",
    "systemd-shutdown",
    "tmpfiles",
    "sysusers",
    "sysctl",
    "binfmt",
    "modules-load",
    "catalog",
    "systemd-search-network",
    "systemd-system-environment-generator",
    "systemd-user-environment-generator",
    "systemd-search-system-environment-generator",
    "systemd-search-user-environment-generator",
    "system-credential-store",
    "system-search-credential-store",
    "system-credential-store-encrypted",
    "system-search-credential-store-encrypted",
    "user-credential-store",
    "user-search-credential-store",
    "user-credential-store-encrypted",
    "user-search-credential-store-encrypted",
];

pub fn sorted_path_names() -> Vec<&'static str> {
    let mut names = PATH_TABLE.to_vec();
    names.sort_unstable();
    names
}

pub fn lookup_path_name(name: &str) -> Result<usize> {
    PATH_TABLE
        .iter()
        .position(|candidate| *candidate == name)
        .ok_or_else(|| Error::UnknownPathName(name.to_string()))
}

pub fn append_suffix(path: &str, suffix: Option<&str>) -> String {
    match suffix.filter(|value| !value.is_empty()) {
        Some(suffix) if path.ends_with('/') => format!("{path}{suffix}"),
        Some(suffix) => format!("{path}/{suffix}"),
        None => path.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_table_contains_expected_entries() {
        assert!(PATH_TABLE.contains(&"temporary"));
        assert!(PATH_TABLE.contains(&"systemd-system-unit"));
        assert!(PATH_TABLE.contains(&"user-search-credential-store-encrypted"));
    }

    #[test]
    fn sorted_path_names_orders_alphabetically() {
        let sorted = sorted_path_names();
        assert_eq!(sorted.first(), Some(&"binfmt"));
        assert!(sorted.windows(2).all(|window| window[0] <= window[1]));
    }

    #[test]
    fn lookup_path_name_returns_original_index() {
        assert_eq!(lookup_path_name("temporary").unwrap(), 0);
    }

    #[test]
    fn lookup_path_name_rejects_unknown_values() {
        assert_eq!(
            lookup_path_name("definitely-not-a-systemd-path"),
            Err(Error::UnknownPathName(
                "definitely-not-a-systemd-path".to_string()
            ))
        );
    }

    #[test]
    fn append_suffix_joins_cleanly() {
        assert_eq!(append_suffix("/run", Some("foo")), "/run/foo");
    }

    #[test]
    fn append_suffix_preserves_trailing_separator() {
        assert_eq!(append_suffix("/run/", Some("foo")), "/run/foo");
    }

    #[test]
    fn append_suffix_ignores_empty_suffix() {
        assert_eq!(append_suffix("/run", Some("")), "/run");
    }

    #[test]
    fn append_suffix_ignores_missing_suffix() {
        assert_eq!(append_suffix("/run", None), "/run");
    }

    #[test]
    fn sorted_names_include_systemd_search_network() {
        assert!(sorted_path_names().contains(&"systemd-search-network"));
    }
}
