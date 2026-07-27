// SPDX-License-Identifier: LGPL-2.1-or-later

// PORT-SYNC: src/home/user-record-util.c, src/home/user-record-util.h

// Port of user-record-util.c/h - User record synthesis and utility functions

use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};

use crate::home_util::{suitable_realm, suitable_user_name, supported_fstype};
use crate::homed_conf::UserStorage;

pub const USER_DISK_SIZE_DEFAULT_PERCENT: u32 = 83;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserRecord {
    pub user_name: String,
    pub realm: Option<String>,
    pub home_directory: Option<String>,
    pub shell: Option<String>,
    pub real_name: Option<String>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub storage: UserStorage,
    pub image_path: Option<PathBuf>,
    pub file_system_type: Option<String>,
    pub disk_size: Option<u64>,
    pub password: Vec<String>,
    pub hashed_password: Vec<String>,
    pub secret: Option<Box<UserRecord>>,
    pub cifs_service: Option<String>,
    pub fido2_user_presence_permitted: i32,
    pub fido2_user_verification_permitted: i32,
    pub pkcs11_protected_authentication_path_permitted: i32,
    pub token_pin: Vec<String>,
}

impl UserRecord {
    pub fn new() -> Self {
        Self {
            user_name: String::new(),
            realm: None,
            home_directory: None,
            shell: None,
            real_name: None,
            uid: None,
            gid: None,
            storage: UserStorage::Luks,
            image_path: None,
            file_system_type: None,
            disk_size: None,
            password: Vec::new(),
            hashed_password: Vec::new(),
            secret: None,
            cifs_service: None,
            fido2_user_presence_permitted: 0,
            fido2_user_verification_permitted: 0,
            pkcs11_protected_authentication_path_permitted: 0,
            token_pin: Vec::new(),
        }
    }

    pub fn storage(&self) -> UserStorage {
        self.storage
    }

    pub fn gid(&self) -> u32 {
        self.gid.unwrap_or(0)
    }

    pub fn real_name(&self) -> &str {
        self.real_name.as_deref().unwrap_or("")
    }

    pub fn home_dir(&self) -> &str {
        self.home_directory.as_deref().unwrap_or("")
    }

    pub fn shell(&self) -> &str {
        self.shell.as_deref().unwrap_or("/bin/bash")
    }

    pub fn image_path_str(&self) -> Option<&str> {
        self.image_path.as_ref().map(|p| p.to_str().unwrap_or(""))
    }
}

impl Default for UserRecord {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
pub enum UserRecordError {
    InvalidName(String),
    InvalidRealm(String),
    InvalidStorage(String),
    InvalidPath(String),
    AlreadyInitialized,
    OutOfMemory,
    Io(io::Error),
}

impl From<io::Error> for UserRecordError {
    fn from(e: io::Error) -> Self {
        UserRecordError::Io(e)
    }
}

impl std::fmt::Display for UserRecordError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UserRecordError::InvalidName(n) => write!(f, "Invalid user name: {}", n),
            UserRecordError::InvalidRealm(r) => write!(f, "Invalid realm: {}", r),
            UserRecordError::InvalidStorage(s) => write!(f, "Invalid storage: {}", s),
            UserRecordError::InvalidPath(p) => write!(f, "Invalid path: {}", p),
            UserRecordError::AlreadyInitialized => write!(f, "Record already initialized"),
            UserRecordError::OutOfMemory => write!(f, "Out of memory"),
            UserRecordError::Io(e) => write!(f, "IO error: {}", e),
        }
    }
}

impl std::error::Error for UserRecordError {}

pub fn user_record_synthesize(
    record: &mut UserRecord,
    user_name: &str,
    realm: Option<&str>,
    image_path: &str,
    storage: UserStorage,
    uid: u32,
    gid: u32,
) -> Result<(), UserRecordError> {
    if !record.user_name.is_empty() {
        return Err(UserRecordError::AlreadyInitialized);
    }
    if !suitable_user_name(user_name) {
        return Err(UserRecordError::InvalidName(user_name.to_string()));
    }
    if let Some(r) = realm {
        if !suitable_realm(r).map_err(|e| UserRecordError::InvalidRealm(e.to_string()))? {
            return Err(UserRecordError::InvalidRealm(r.to_string()));
        }
    }

    let home_dir = format!("/home/{}", user_name);
    record.user_name = user_name.to_string();
    record.realm = realm.map(String::from);
    record.home_directory = Some(home_dir);
    record.shell = Some("/bin/bash".to_string());
    record.uid = Some(uid);
    record.gid = Some(gid);
    record.storage = storage;
    record.image_path = Some(PathBuf::from(image_path));
    Ok(())
}

pub fn user_record_good_password(record: &UserRecord, password: &str) -> bool {
    !password.is_empty() && password.len() >= 8 && record.password.iter().all(|p| p != password)
}

pub fn default_disk_size(total: u64) -> u64 {
    total * USER_DISK_SIZE_DEFAULT_PERCENT as u64 / 100
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_user_record_new() {
        let record = UserRecord::new();
        assert!(record.user_name.is_empty());
        assert_eq!(record.storage(), UserStorage::Luks);
    }

    #[test]
    fn test_user_record_synthesize() {
        let mut record = UserRecord::new();
        user_record_synthesize(
            &mut record,
            "alice",
            None,
            "/home/alice.img",
            UserStorage::Luks,
            60001,
            60001,
        )
        .unwrap();
        assert_eq!(record.user_name, "alice");
        assert_eq!(record.uid, Some(60001));
        assert_eq!(record.home_directory, Some("/home/alice".to_string()));
    }

    #[test]
    fn test_user_record_synthesize_invalid_name() {
        let mut record = UserRecord::new();
        assert!(user_record_synthesize(
            &mut record,
            "root",
            None,
            "/root.img",
            UserStorage::Luks,
            0,
            0
        )
        .is_err());
    }

    #[test]
    fn test_user_record_synthesize_double_init() {
        let mut record = UserRecord::new();
        user_record_synthesize(
            &mut record,
            "alice",
            None,
            "/home/alice.img",
            UserStorage::Luks,
            60001,
            60001,
        )
        .unwrap();
        assert!(user_record_synthesize(
            &mut record,
            "bob",
            None,
            "/home/bob.img",
            UserStorage::Luks,
            60002,
            60002
        )
        .is_err());
    }

    #[test]
    fn test_good_password() {
        let record = UserRecord::new();
        assert!(user_record_good_password(&record, "longpassword"));
        assert!(!user_record_good_password(&record, "short"));
        assert!(!user_record_good_password(&record, ""));
    }

    #[test]
    fn test_default_disk_size() {
        let size = default_disk_size(10 * 1024 * 1024 * 1024);
        assert_eq!(size, 8912057139);
    }
}

#[cfg(test)]
mod extra_tests {
    use super::*;

    #[test]
    fn test_default_shell_fallback() {
        let record = UserRecord::new();
        assert_eq!(record.shell(), "/bin/bash");
    }

    #[test]
    fn test_image_path_str_roundtrip() {
        let mut record = UserRecord::new();
        record.image_path = Some(PathBuf::from("/tmp/alice.home"));
        assert_eq!(record.image_path_str(), Some("/tmp/alice.home"));
    }
}
