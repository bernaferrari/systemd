// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/home/home-util.c, src/home/home-util.h

use std::collections::HashMap;
use std::env;
use std::path::{Component, Path, PathBuf};

pub const USER_DISK_SIZE_DEFAULT_PERCENT: u32 = 83;
pub type BlobFdMap = HashMap<String, i32>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HomeUtilError {
    InvalidUserName(String),
    InvalidRealm(String),
}

impl std::fmt::Display for HomeUtilError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidUserName(name) => write!(f, "invalid user name: {name}"),
            Self::InvalidRealm(realm) => write!(f, "invalid realm: {realm}"),
        }
    }
}

impl std::error::Error for HomeUtilError {}

pub fn suitable_user_name(name: &str) -> bool {
    if name.is_empty() || matches!(name, "root" | "nobody") {
        return false;
    }
    if name.starts_with("systemd-") || name.starts_with('_') {
        return false;
    }
    name.chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-'))
}

pub fn suitable_realm(realm: &str) -> Result<bool, HomeUtilError> {
    if realm.is_empty() {
        return Ok(false);
    }

    let normalized = realm.to_ascii_lowercase();
    if realm != normalized {
        return Ok(false);
    }
    if !normalized.contains('.') {
        return Ok(false);
    }

    for label in normalized.split('.') {
        if label.is_empty() || label.starts_with('-') || label.ends_with('-') {
            return Ok(false);
        }
        if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return Ok(false);
        }
    }
    Ok(true)
}

pub fn suitable_image_path(path: &str) -> bool {
    !path.is_empty() && path != "/" && Path::new(path).is_absolute() && path_is_valid(path)
}

pub fn supported_fstype(fstype: &str) -> bool {
    matches!(fstype, "ext4" | "btrfs" | "xfs")
}

pub fn split_user_name_realm(value: &str) -> Result<(String, Option<String>), HomeUtilError> {
    let (user, realm) = match value.split_once('@') {
        Some((user, realm)) => (user.to_string(), Some(realm.to_string())),
        None => (value.to_string(), None),
    };

    if !suitable_user_name(&user) {
        return Err(HomeUtilError::InvalidUserName(user));
    }
    if let Some(ref realm_value) = realm {
        if !suitable_realm(realm_value)
            .map_err(|_| HomeUtilError::InvalidRealm(realm_value.clone()))?
        {
            return Err(HomeUtilError::InvalidRealm(realm_value.clone()));
        }
    }

    Ok((user, realm))
}

pub fn suitable_blob_filename(name: &str) -> bool {
    !name.is_empty()
        && !name.starts_with('/')
        && !matches!(name, "." | "..")
        && !name.contains('\0')
        && !name.split('/').any(|part| part == ".." || part.is_empty())
}

pub fn bus_message_append_secret(secret_json: Option<&str>) -> String {
    secret_json.unwrap_or("{}").to_string()
}

pub fn home_record_dir() -> PathBuf {
    env::var("SYSTEMD_HOME_RECORD_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| "/var/lib/systemd/home/".into())
}

pub fn home_system_blob_dir() -> PathBuf {
    env::var("SYSTEMD_HOME_SYSTEM_BLOB_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| "/var/cache/systemd/home/".into())
}

fn path_is_valid(path: &str) -> bool {
    !path.contains('\0')
        && Path::new(path)
            .components()
            .all(|component| matches!(component, Component::RootDir | Component::Normal(_)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suitable_user_name_filters_reserved_names() {
        assert!(!suitable_user_name("root"));
        assert!(!suitable_user_name("systemd-user"));
    }

    #[test]
    fn suitable_user_name_accepts_normal_names() {
        assert!(suitable_user_name("alice"));
        assert!(suitable_user_name("bob-user"));
    }

    #[test]
    fn suitable_realm_requires_multiple_labels() {
        assert!(!suitable_realm("com").unwrap());
        assert!(suitable_realm("example.com").unwrap());
    }

    #[test]
    fn suitable_image_path_requires_absolute_path() {
        assert!(suitable_image_path("/var/lib/systemd/home/alice"));
        assert!(!suitable_image_path("alice"));
    }

    #[test]
    fn supported_fstype_matches_c_set() {
        assert!(supported_fstype("ext4"));
        assert!(!supported_fstype("tmpfs"));
    }

    #[test]
    fn split_user_name_realm_parses_optional_realm() {
        assert_eq!(
            split_user_name_realm("alice@example.com").unwrap(),
            ("alice".into(), Some("example.com".into()))
        );
    }

    #[test]
    fn split_user_name_realm_rejects_bad_user() {
        assert_eq!(
            split_user_name_realm("root@example.com"),
            Err(HomeUtilError::InvalidUserName("root".into()))
        );
    }

    #[test]
    fn suitable_blob_filename_rejects_parent_reference() {
        assert!(!suitable_blob_filename("../x"));
        assert!(suitable_blob_filename("avatar.png"));
    }

    #[test]
    fn append_secret_defaults_to_empty_object() {
        assert_eq!(bus_message_append_secret(None), "{}");
    }

    #[test]
    fn home_dirs_have_expected_defaults() {
        assert_eq!(home_record_dir(), PathBuf::from("/var/lib/systemd/home/"));
        assert_eq!(
            home_system_blob_dir(),
            PathBuf::from("/var/cache/systemd/home/")
        );
    }
}
