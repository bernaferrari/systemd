// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/home/homed-conf.c, src/home/homed-conf.h
//
// Configuration helpers for systemd-homed.

use crate::home_util::supported_fstype;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum UserStorage {
    #[default]
    Luks,
    Subvolume,
    Fscrypt,
    Directory,
    Cifs,
}

impl UserStorage {
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "luks" => Some(Self::Luks),
            "subvolume" | "btrfs" => Some(Self::Subvolume),
            "fscrypt" => Some(Self::Fscrypt),
            "directory" => Some(Self::Directory),
            "cifs" => Some(Self::Cifs),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagerConfig {
    pub default_storage: UserStorage,
    pub default_file_system_type: Option<String>,
}

impl Default for ManagerConfig {
    fn default() -> Self {
        Self {
            default_storage: UserStorage::Luks,
            default_file_system_type: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigError {
    InvalidStorage(String),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidStorage(storage) => write!(f, "invalid storage backend: {storage}"),
        }
    }
}

impl std::error::Error for ConfigError {}

pub fn config_parse_default_storage(value: &str) -> Result<Option<UserStorage>, ConfigError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }

    UserStorage::parse(trimmed)
        .map(Some)
        .ok_or_else(|| ConfigError::InvalidStorage(trimmed.to_string()))
}

pub fn config_parse_default_file_system_type(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() || !supported_fstype(trimmed) {
        None
    } else {
        Some(trimmed.to_string())
    }
}

pub fn manager_parse_config(contents: &str) -> Result<ManagerConfig, ConfigError> {
    let mut config = ManagerConfig::default();

    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }

        let Some((key, value)) = line.split_once('=') else {
            continue;
        };

        match key.trim() {
            "DefaultStorage" => {
                if let Some(storage) = config_parse_default_storage(value)? {
                    config.default_storage = storage;
                }
            }
            "DefaultFileSystemType" => {
                config.default_file_system_type = config_parse_default_file_system_type(value);
            }
            _ => {}
        }
    }

    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_storage_accepts_luks() {
        assert_eq!(
            config_parse_default_storage("luks").unwrap(),
            Some(UserStorage::Luks)
        );
    }

    #[test]
    fn parse_storage_accepts_btrfs_alias() {
        assert_eq!(
            config_parse_default_storage("btrfs").unwrap(),
            Some(UserStorage::Subvolume)
        );
    }

    #[test]
    fn parse_storage_accepts_empty_as_none() {
        assert_eq!(config_parse_default_storage("   ").unwrap(), None);
    }

    #[test]
    fn parse_storage_rejects_unknown_value() {
        assert_eq!(
            config_parse_default_storage("nfs"),
            Err(ConfigError::InvalidStorage("nfs".into()))
        );
    }

    #[test]
    fn parse_fs_type_keeps_supported_value() {
        assert_eq!(
            config_parse_default_file_system_type("ext4"),
            Some("ext4".into())
        );
    }

    #[test]
    fn parse_fs_type_ignores_unsupported_value() {
        assert_eq!(config_parse_default_file_system_type("zfs"), None);
    }

    #[test]
    fn parse_config_sets_both_known_keys() {
        let config =
            manager_parse_config("DefaultStorage=directory\nDefaultFileSystemType=btrfs\n")
                .unwrap();
        assert_eq!(config.default_storage, UserStorage::Directory);
        assert_eq!(config.default_file_system_type, Some("btrfs".into()));
    }

    #[test]
    fn parse_config_ignores_comments_and_unknown_keys() {
        let config = manager_parse_config("# comment\nUnknown=1\nDefaultStorage=luks\n").unwrap();
        assert_eq!(config.default_storage, UserStorage::Luks);
        assert_eq!(config.default_file_system_type, None);
    }

    #[test]
    fn parse_config_last_assignment_wins() {
        let config = manager_parse_config("DefaultStorage=luks\nDefaultStorage=fscrypt\n").unwrap();
        assert_eq!(config.default_storage, UserStorage::Fscrypt);
    }
}
