// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/home/homework-password-cache.c, src/home/homework-password-cache.h
//
// Password and volume-key caching helpers for homework.

use std::collections::HashMap;

use crate::user_record_util::UserRecord;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PasswordCache {
    pub volume_key: Option<Vec<u8>>,
    pub pkcs11_passwords: Vec<String>,
    pub fido2_passwords: Vec<String>,
}

impl PasswordCache {
    pub fn volume_key_size(&self) -> usize {
        self.volume_key.as_ref().map_or(0, Vec::len)
    }

    pub fn clear(&mut self) {
        self.volume_key = None;
        self.pkcs11_passwords.clear();
        self.fido2_passwords.clear();
    }

    pub fn store_volume_key(&mut self, key: Vec<u8>) {
        self.volume_key = Some(key);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyringError {
    MissingUserName,
}

impl std::fmt::Display for KeyringError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingUserName => {
                write!(f, "user name is required to resolve kernel keyring entry")
            }
        }
    }
}

impl std::error::Error for KeyringError {}

pub fn keyring_entry_name(record: &UserRecord) -> Result<String, KeyringError> {
    if record.user_name.is_empty() {
        return Err(KeyringError::MissingUserName);
    }

    Ok(format!("homework-user-{}", record.user_name))
}

pub fn password_cache_load_keyring(
    record: &UserRecord,
    cache: &mut PasswordCache,
    keyring: &HashMap<String, Vec<u8>>,
) -> Result<bool, KeyringError> {
    let name = keyring_entry_name(record)?;
    if let Some(value) = keyring.get(&name) {
        cache.volume_key = Some(value.clone());
        Ok(true)
    } else {
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(name: &str) -> UserRecord {
        let mut record = UserRecord::new();
        record.user_name = name.into();
        record
    }

    #[test]
    fn default_cache_is_empty() {
        let cache = PasswordCache::default();
        assert!(cache.volume_key.is_none());
        assert!(cache.pkcs11_passwords.is_empty());
        assert!(cache.fido2_passwords.is_empty());
    }

    #[test]
    fn volume_key_size_tracks_current_key() {
        let mut cache = PasswordCache::default();
        cache.store_volume_key(vec![1, 2, 3]);
        assert_eq!(cache.volume_key_size(), 3);
    }

    #[test]
    fn clear_removes_all_cached_values() {
        let mut cache = PasswordCache::default();
        cache.store_volume_key(vec![1, 2, 3]);
        cache.pkcs11_passwords.push("pin".into());
        cache.fido2_passwords.push("secret".into());
        cache.clear();
        assert_eq!(cache.volume_key_size(), 0);
        assert!(cache.pkcs11_passwords.is_empty());
        assert!(cache.fido2_passwords.is_empty());
    }

    #[test]
    fn keyring_entry_name_matches_c_prefix() {
        assert_eq!(
            keyring_entry_name(&record("alice")).unwrap(),
            "homework-user-alice"
        );
    }

    #[test]
    fn keyring_entry_requires_user_name() {
        assert_eq!(
            keyring_entry_name(&UserRecord::new()),
            Err(KeyringError::MissingUserName)
        );
    }

    #[test]
    fn load_keyring_returns_false_when_missing() {
        let mut cache = PasswordCache::default();
        let loaded =
            password_cache_load_keyring(&record("alice"), &mut cache, &HashMap::new()).unwrap();
        assert!(!loaded);
        assert!(cache.volume_key.is_none());
    }

    #[test]
    fn load_keyring_copies_volume_key() {
        let mut cache = PasswordCache::default();
        let mut keyring = HashMap::new();
        keyring.insert("homework-user-alice".into(), vec![9, 8, 7]);
        let loaded = password_cache_load_keyring(&record("alice"), &mut cache, &keyring).unwrap();
        assert!(loaded);
        assert_eq!(cache.volume_key, Some(vec![9, 8, 7]));
    }

    #[test]
    fn loading_replaces_previous_key() {
        let mut cache = PasswordCache::default();
        cache.store_volume_key(vec![1]);
        let mut keyring = HashMap::new();
        keyring.insert("homework-user-bob".into(), vec![4, 5]);
        password_cache_load_keyring(&record("bob"), &mut cache, &keyring).unwrap();
        assert_eq!(cache.volume_key, Some(vec![4, 5]));
    }

    #[test]
    fn store_volume_key_accepts_empty_key() {
        let mut cache = PasswordCache::default();
        cache.store_volume_key(Vec::new());
        assert_eq!(cache.volume_key_size(), 0);
        assert_eq!(cache.volume_key, Some(Vec::new()));
    }
}
