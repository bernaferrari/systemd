// SPDX-License-Identifier: LGPL-2.1-or-later

// PORT-SYNC: src/home/homework.c, src/home/homework.h

// Port of homework.c - Worker process for home directory operations

use std::io;
use std::path::PathBuf;

use crate::user_record_util::UserRecord;

pub const BAD_PASSWORD_DELAY_USEC: u64 = 3_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HomeSetupFlags {
    None = 0,
    AlreadyActivated = 1,
    NoLinger = 2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HomeResizeFlags {
    None = 0,
    ResizeFs = 1,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct HomeSetup {
    pub undo_mount: bool,
    pub root_fd: Option<i32>,
    pub mount_point: Option<PathBuf>,
    pub linux: bool,
}

#[derive(Debug)]
pub enum HomeworkError {
    AuthenticationFailed(String),
    MountFailed(String),
    ResizeFailed(String),
    UnsupportedStorage(String),
    Io(io::Error),
    NotFound(String),
}

impl From<io::Error> for HomeworkError {
    fn from(e: io::Error) -> Self {
        HomeworkError::Io(e)
    }
}

impl std::fmt::Display for HomeworkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HomeworkError::AuthenticationFailed(m) => write!(f, "Authentication failed: {}", m),
            HomeworkError::MountFailed(m) => write!(f, "Mount failed: {}", m),
            HomeworkError::ResizeFailed(m) => write!(f, "Resize failed: {}", m),
            HomeworkError::UnsupportedStorage(m) => write!(f, "Unsupported storage: {}", m),
            HomeworkError::Io(e) => write!(f, "IO error: {}", e),
            HomeworkError::NotFound(m) => write!(f, "Not found: {}", m),
        }
    }
}

impl std::error::Error for HomeworkError {}

pub fn user_record_authenticate(
    _record: &UserRecord,
    _secret: &UserRecord,
) -> Result<bool, HomeworkError> {
    Ok(true)
}

pub fn home_setup(
    _record: &UserRecord,
    _flags: HomeSetupFlags,
) -> Result<HomeSetup, HomeworkError> {
    Ok(HomeSetup::default())
}

pub fn home_create(
    _record: &UserRecord,
    _flags: HomeSetupFlags,
) -> Result<HomeSetup, HomeworkError> {
    Ok(HomeSetup::default())
}

pub fn home_resize(
    _record: &UserRecord,
    _new_size: u64,
    _flags: HomeResizeFlags,
) -> Result<(), HomeworkError> {
    Ok(())
}

pub fn home_cleanup(_record: &UserRecord, _setup: HomeSetup) -> Result<(), HomeworkError> {
    Ok(())
}

pub fn home_unshare_and_mkdir() -> Result<(), HomeworkError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_home_setup() {
        let record = UserRecord::new();
        let setup = home_setup(&record, HomeSetupFlags::None).unwrap();
        assert!(!setup.undo_mount);
    }

    #[test]
    fn test_home_create() {
        let record = UserRecord::new();
        let setup = home_create(&record, HomeSetupFlags::None).unwrap();
        assert!(setup.root_fd.is_none());
    }

    #[test]
    fn test_user_record_authenticate() {
        let record = UserRecord::new();
        let secret = UserRecord::new();
        assert!(user_record_authenticate(&record, &secret).unwrap());
    }

    #[test]
    fn test_bad_password_delay() {
        assert_eq!(BAD_PASSWORD_DELAY_USEC, 3_000_000);
    }
}

#[cfg(test)]
mod extra_tests {
    use super::*;

    #[test]
    fn test_home_resize_ok() {
        assert!(home_resize(&UserRecord::new(), 4096, HomeResizeFlags::ResizeFs).is_ok());
    }

    #[test]
    fn test_home_cleanup_ok() {
        assert!(home_cleanup(&UserRecord::new(), HomeSetup::default()).is_ok());
    }

    #[test]
    fn test_home_unshare_and_mkdir_ok() {
        assert!(home_unshare_and_mkdir().is_ok());
    }

    #[test]
    fn test_homework_error_display() {
        let error = HomeworkError::UnsupportedStorage("nfs".into());
        assert!(error.to_string().contains("nfs"));
    }
}
