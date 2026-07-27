// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/home/homework-directory.c, src/home/homework-directory.h

use crate::homework::{HomeSetup, HomeSetupFlags, HomeworkError};
use crate::user_record_util::UserRecord;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DirectoryError {
    MissingImagePath,
    MissingHomeDirectory,
    InvalidUid,
    MountFailed(String),
    ChownFailed(String),
    QuotaFailed(String),
    Io(String),
}

impl std::fmt::Display for DirectoryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingImagePath => write!(f, "home record lacks image path"),
            Self::MissingHomeDirectory => write!(f, "home record lacks home directory"),
            Self::InvalidUid => write!(f, "home record lacks valid uid"),
            Self::MountFailed(s) => write!(f, "mount failed: {}", s),
            Self::ChownFailed(s) => write!(f, "chown failed: {}", s),
            Self::QuotaFailed(s) => write!(f, "quota failed: {}", s),
            Self::Io(e) => write!(f, "I/O error: {}", e),
        }
    }
}

impl From<std::io::Error> for DirectoryError {
    fn from(e: std::io::Error) -> Self {
        DirectoryError::Io(e.to_string())
    }
}

impl std::error::Error for DirectoryError {}

impl From<DirectoryError> for HomeworkError {
    fn from(value: DirectoryError) -> Self {
        HomeworkError::MountFailed(value.to_string())
    }
}

pub fn home_setup_directory(record: &UserRecord) -> Result<HomeSetup, DirectoryError> {
    let image_path = record
        .image_path_str()
        .ok_or(DirectoryError::MissingImagePath)?;
    let mut setup = HomeSetup::default();
    setup.undo_mount = true;
    setup.mount_point = Some(image_path.into());
    Ok(setup)
}

pub fn home_activate_directory(
    record: &UserRecord,
    _flags: HomeSetupFlags,
) -> Result<UserRecord, DirectoryError> {
    let _ = home_setup_directory(record)?;
    let home_directory = record.home_dir();
    if home_directory.is_empty() {
        return Err(DirectoryError::MissingHomeDirectory);
    }

    let mut activated = record.clone();
    activated.home_directory = Some(home_directory.to_string());
    Ok(activated)
}

pub fn home_create_directory_or_subvolume(
    record: &UserRecord,
) -> Result<UserRecord, DirectoryError> {
    if record.uid.unwrap_or(0) == 0 {
        return Err(DirectoryError::InvalidUid);
    }
    if record.image_path_str().is_none() {
        return Err(DirectoryError::MissingImagePath);
    }

    let mut created = record.clone();
    if created.home_directory.is_none() {
        created.home_directory = Some(format!("/home/{}", created.user_name));
    }
    Ok(created)
}

pub fn home_resize_directory(record: &UserRecord) -> Result<UserRecord, DirectoryError> {
    home_create_directory_or_subvolume(record)
}

pub fn home_create_directory(
    _record: &UserRecord,
    _flags: HomeSetupFlags,
) -> Result<HomeSetup, DirectoryError> {
    Ok(HomeSetup::default())
}

pub fn home_cleanup_directory(_setup: HomeSetup) -> Result<(), DirectoryError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record() -> UserRecord {
        let mut record = UserRecord::new();
        record.user_name = "alice".into();
        record.uid = Some(1000);
        record.image_path = Some("/var/lib/systemd/home/alice".into());
        record.home_directory = Some("/home/alice".into());
        record
    }

    #[test]
    fn setup_requires_image_path() {
        assert_eq!(
            home_setup_directory(&UserRecord::new()),
            Err(DirectoryError::MissingImagePath)
        );
    }

    #[test]
    fn setup_marks_mount_for_cleanup() {
        let setup = home_setup_directory(&record()).unwrap();
        assert!(setup.undo_mount);
    }

    #[test]
    fn setup_uses_image_path_as_mount_point() {
        let setup = home_setup_directory(&record()).unwrap();
        assert_eq!(
            setup.mount_point.as_deref().and_then(|p| p.to_str()),
            Some("/var/lib/systemd/home/alice")
        );
    }

    #[test]
    fn activate_requires_home_directory() {
        let mut missing = record();
        missing.home_directory = None;
        assert_eq!(
            home_activate_directory(&missing, HomeSetupFlags::None),
            Err(DirectoryError::MissingHomeDirectory)
        );
    }

    #[test]
    fn activate_returns_cloned_record() {
        let activated = home_activate_directory(&record(), HomeSetupFlags::None).unwrap();
        assert_eq!(activated.home_directory.as_deref(), Some("/home/alice"));
    }

    #[test]
    fn create_requires_uid() {
        let mut invalid = record();
        invalid.uid = Some(0);
        assert_eq!(
            home_create_directory_or_subvolume(&invalid),
            Err(DirectoryError::InvalidUid)
        );
    }

    #[test]
    fn create_adds_default_home_directory_when_missing() {
        let mut missing = record();
        missing.home_directory = None;
        let created = home_create_directory_or_subvolume(&missing).unwrap();
        assert_eq!(created.home_directory.as_deref(), Some("/home/alice"));
    }

    #[test]
    fn resize_reuses_create_validation() {
        let resized = home_resize_directory(&record()).unwrap();
        assert_eq!(resized.user_name, "alice");
    }

    #[test]
    fn create_requires_image_path() {
        let mut missing = record();
        missing.image_path = None;
        assert_eq!(
            home_create_directory_or_subvolume(&missing),
            Err(DirectoryError::MissingImagePath)
        );
    }
}

#[cfg(test)]
mod extra_tests {
    use super::*;
    use std::io;

    #[test]
    fn test_home_create_directory() {
        let record = UserRecord::new();
        let setup = home_create_directory(&record, HomeSetupFlags::None).unwrap();
        assert!(setup.root_fd.is_none());
    }

    #[test]
    fn test_home_cleanup_directory() {
        assert!(home_cleanup_directory(HomeSetup::default()).is_ok());
    }

    #[test]
    fn test_mount_error_display() {
        let error = DirectoryError::MountFailed("no mount".into());
        assert!(error.to_string().contains("no mount"));
    }

    #[test]
    fn test_chown_error_display() {
        let error = DirectoryError::ChownFailed("no owner".into());
        assert!(error.to_string().contains("no owner"));
    }

    #[test]
    fn test_quota_error_display() {
        let error = DirectoryError::QuotaFailed("quota".into());
        assert!(error.to_string().contains("quota"));
    }

    #[test]
    fn test_io_error_conversion() {
        let error = DirectoryError::from(io::Error::other("boom"));
        assert!(matches!(error, DirectoryError::Io(_)));
    }

    #[test]
    fn test_homework_error_conversion() {
        let error: HomeworkError = DirectoryError::MountFailed("x".into()).into();
        assert!(matches!(error, HomeworkError::MountFailed(_)));
    }
}
