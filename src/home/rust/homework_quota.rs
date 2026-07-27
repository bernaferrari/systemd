// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/home/homework-quota.c, src/home/homework-quota.h

use crate::user_record_util::UserRecord;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuotaBackend {
    Btrfs,
    Classic,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuotaError {
    MissingPath,
    MissingUid,
    InvalidUid,
    UnsupportedFileSystem,
    NotSubvolume,
}

impl std::fmt::Display for QuotaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingPath => write!(f, "path is required"),
            Self::MissingUid => write!(f, "uid is required"),
            Self::InvalidUid => write!(f, "uid 0 is invalid for quota management"),
            Self::UnsupportedFileSystem => {
                write!(f, "file system type not known, cannot apply quota")
            }
            Self::NotSubvolume => write!(f, "directory is not a subvolume, cannot apply quota"),
        }
    }
}

impl std::error::Error for QuotaError {}

pub fn home_update_quota_btrfs(
    record: &UserRecord,
    path: &str,
    is_subvolume: bool,
) -> Result<Option<u64>, QuotaError> {
    if path.is_empty() {
        return Err(QuotaError::MissingPath);
    }
    if record.disk_size == Some(u64::MAX) {
        return Ok(None);
    }
    if !is_subvolume {
        return Err(QuotaError::NotSubvolume);
    }
    Ok(record.disk_size)
}

pub fn home_update_quota_classic(
    record: &UserRecord,
    path: &str,
) -> Result<Option<u64>, QuotaError> {
    if path.is_empty() {
        return Err(QuotaError::MissingPath);
    }
    let uid = record.uid.ok_or(QuotaError::MissingUid)?;
    if uid == 0 {
        return Err(QuotaError::InvalidUid);
    }
    if record.disk_size == Some(u64::MAX) {
        return Ok(None);
    }
    Ok(record.disk_size)
}

pub fn home_update_quota_auto(
    record: &UserRecord,
    path: Option<&str>,
    backend: QuotaBackend,
    is_subvolume: bool,
) -> Result<Option<u64>, QuotaError> {
    let path = path
        .or(record.image_path_str())
        .ok_or(QuotaError::MissingPath)?;
    match backend {
        QuotaBackend::Btrfs => home_update_quota_btrfs(record, path, is_subvolume),
        QuotaBackend::Classic => home_update_quota_classic(record, path),
        QuotaBackend::Unknown => Err(QuotaError::UnsupportedFileSystem),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(uid: Option<u32>, disk_size: Option<u64>) -> UserRecord {
        let mut record = UserRecord::new();
        record.uid = uid;
        record.disk_size = disk_size;
        record.image_path = Some("/home/alice.image".into());
        record
    }

    #[test]
    fn btrfs_requires_path() {
        assert_eq!(
            home_update_quota_btrfs(&record(Some(1000), Some(1)), "", true),
            Err(QuotaError::MissingPath)
        );
    }

    #[test]
    fn btrfs_skips_unlimited_quota() {
        assert_eq!(
            home_update_quota_btrfs(&record(Some(1000), Some(u64::MAX)), "/x", true).unwrap(),
            None
        );
    }

    #[test]
    fn btrfs_requires_subvolume() {
        assert_eq!(
            home_update_quota_btrfs(&record(Some(1000), Some(64)), "/x", false),
            Err(QuotaError::NotSubvolume)
        );
    }

    #[test]
    fn btrfs_returns_limit() {
        assert_eq!(
            home_update_quota_btrfs(&record(Some(1000), Some(64)), "/x", true).unwrap(),
            Some(64)
        );
    }

    #[test]
    fn classic_requires_uid() {
        assert_eq!(
            home_update_quota_classic(&record(None, Some(1)), "/x"),
            Err(QuotaError::MissingUid)
        );
    }

    #[test]
    fn classic_rejects_uid_zero() {
        assert_eq!(
            home_update_quota_classic(&record(Some(0), Some(1)), "/x"),
            Err(QuotaError::InvalidUid)
        );
    }

    #[test]
    fn classic_returns_limit() {
        assert_eq!(
            home_update_quota_classic(&record(Some(1000), Some(88)), "/x").unwrap(),
            Some(88)
        );
    }

    #[test]
    fn auto_uses_record_image_path() {
        assert_eq!(
            home_update_quota_auto(
                &record(Some(1000), Some(77)),
                None,
                QuotaBackend::Classic,
                false
            )
            .unwrap(),
            Some(77)
        );
    }

    #[test]
    fn auto_rejects_unknown_backend() {
        assert_eq!(
            home_update_quota_auto(
                &record(Some(1000), Some(77)),
                Some("/x"),
                QuotaBackend::Unknown,
                false
            ),
            Err(QuotaError::UnsupportedFileSystem)
        );
    }
}
