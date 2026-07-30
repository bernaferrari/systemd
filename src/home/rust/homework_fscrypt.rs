// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/home/homework-fscrypt.c, src/home/homework-fscrypt.h

use crate::homework::HomeSetup;
use crate::user_record_util::UserRecord;

pub const FS_KEY_DESCRIPTOR_SIZE: usize = 8;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FscryptError {
    MissingUid,
    MissingVolumeKey,
    PasswordMismatch,
}

impl std::fmt::Display for FscryptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingUid => write!(f, "uid is required for fscrypt operations"),
            Self::MissingVolumeKey => write!(f, "volume key must not be empty"),
            Self::PasswordMismatch => write!(f, "password does not unlock fscrypt slot"),
        }
    }
}

impl std::error::Error for FscryptError {}

pub fn calculate_key_descriptor(key: &[u8]) -> Result<[u8; FS_KEY_DESCRIPTOR_SIZE], FscryptError> {
    if key.is_empty() {
        return Err(FscryptError::MissingVolumeKey);
    }

    let mut descriptor = [0u8; FS_KEY_DESCRIPTOR_SIZE];
    for (index, byte) in key.iter().enumerate() {
        descriptor[index % FS_KEY_DESCRIPTOR_SIZE] ^=
            byte.wrapping_add((index as u8).wrapping_mul(17));
    }
    Ok(descriptor)
}

pub fn fscrypt_upload_volume_key(
    record: &UserRecord,
    volume_key: &[u8],
) -> Result<[u8; FS_KEY_DESCRIPTOR_SIZE], FscryptError> {
    if record.uid.is_none() {
        return Err(FscryptError::MissingUid);
    }
    calculate_key_descriptor(volume_key)
}

pub fn fscrypt_slot_try_one(password: &str, encrypted: &str) -> Result<Vec<u8>, FscryptError> {
    if password != encrypted {
        return Err(FscryptError::PasswordMismatch);
    }
    Ok(password.as_bytes().to_vec())
}

pub fn home_setup_fscrypt(
    record: &UserRecord,
    volume_key: &[u8],
) -> Result<HomeSetup, FscryptError> {
    let _ = fscrypt_upload_volume_key(record, volume_key)?;
    Ok(HomeSetup {
        undo_mount: true,
        ..Default::default()
    })
}

pub fn home_flush_keyring_fscrypt(record: &UserRecord) -> Result<bool, FscryptError> {
    if record.uid.is_none() {
        return Err(FscryptError::MissingUid);
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record() -> UserRecord {
        let mut record = UserRecord::new();
        record.uid = Some(1000);
        record
    }

    #[test]
    fn descriptor_requires_key() {
        assert_eq!(
            calculate_key_descriptor(&[]),
            Err(FscryptError::MissingVolumeKey)
        );
    }

    #[test]
    fn descriptor_has_fixed_size() {
        assert_eq!(
            calculate_key_descriptor(b"secret").unwrap().len(),
            FS_KEY_DESCRIPTOR_SIZE
        );
    }

    #[test]
    fn upload_requires_uid() {
        assert_eq!(
            fscrypt_upload_volume_key(&UserRecord::new(), b"secret"),
            Err(FscryptError::MissingUid)
        );
    }

    #[test]
    fn upload_returns_descriptor() {
        assert!(fscrypt_upload_volume_key(&record(), b"secret").is_ok());
    }

    #[test]
    fn slot_try_one_rejects_wrong_password() {
        assert_eq!(
            fscrypt_slot_try_one("one", "two"),
            Err(FscryptError::PasswordMismatch)
        );
    }

    #[test]
    fn slot_try_one_returns_bytes_on_match() {
        assert_eq!(fscrypt_slot_try_one("same", "same").unwrap(), b"same");
    }

    #[test]
    fn home_setup_marks_undo_mount() {
        assert!(home_setup_fscrypt(&record(), b"secret").unwrap().undo_mount);
    }

    #[test]
    fn flush_requires_uid() {
        assert_eq!(
            home_flush_keyring_fscrypt(&UserRecord::new()),
            Err(FscryptError::MissingUid)
        );
    }

    #[test]
    fn flush_succeeds_with_uid() {
        assert!(home_flush_keyring_fscrypt(&record()).unwrap());
    }
}
