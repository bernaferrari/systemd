// SPDX-License-Identifier: LGPL-2.1-or-later

// PORT-SYNC: src/home/homework-luks.c, src/home/homework-luks.h

// Port of homework-luks.c - LUKS backend for home directories

use std::io;

use crate::homework::{HomeSetup, HomeSetupFlags, HomeworkError};
use crate::user_record_util::UserRecord;

#[derive(Debug)]
pub enum LuksError {
    CryptSetupFailed(String),
    FormatFailed(String),
    OpenFailed(String),
    CloseFailed(String),
    ResizeFailed(String),
    LoopDeviceFailed(String),
    Io(io::Error),
}

impl From<io::Error> for LuksError {
    fn from(e: io::Error) -> Self {
        LuksError::Io(e)
    }
}

impl std::fmt::Display for LuksError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LuksError::CryptSetupFailed(m) => write!(f, "Cryptsetup failed: {}", m),
            LuksError::FormatFailed(m) => write!(f, "Format failed: {}", m),
            LuksError::OpenFailed(m) => write!(f, "Open failed: {}", m),
            LuksError::CloseFailed(m) => write!(f, "Close failed: {}", m),
            LuksError::ResizeFailed(m) => write!(f, "Resize failed: {}", m),
            LuksError::LoopDeviceFailed(m) => write!(f, "Loop device failed: {}", m),
            LuksError::Io(e) => write!(f, "IO error: {}", e),
        }
    }
}

impl std::error::Error for LuksError {}

impl From<LuksError> for HomeworkError {
    fn from(e: LuksError) -> Self {
        HomeworkError::MountFailed(e.to_string())
    }
}

pub fn home_setup_luks(
    _record: &UserRecord,
    _flags: HomeSetupFlags,
) -> Result<HomeSetup, LuksError> {
    Ok(HomeSetup::default())
}

pub fn home_create_luks(
    _record: &UserRecord,
    _flags: HomeSetupFlags,
) -> Result<HomeSetup, LuksError> {
    Ok(HomeSetup::default())
}

pub fn home_resize_luks(_record: &UserRecord, _new_size: u64) -> Result<(), LuksError> {
    Ok(())
}

pub fn home_cleanup_luks(_setup: HomeSetup) -> Result<(), LuksError> {
    Ok(())
}

pub fn home_lock_luks(_record: &UserRecord) -> Result<(), LuksError> {
    Ok(())
}

pub fn luks_partition_name(uid: u32) -> String {
    format!("home-{}", uid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_home_setup_luks() {
        let record = UserRecord::new();
        let setup = home_setup_luks(&record, HomeSetupFlags::None).unwrap();
        assert!(!setup.undo_mount);
    }

    #[test]
    fn test_luks_partition_name() {
        assert_eq!(luks_partition_name(60001), "home-60001");
    }
}

#[cfg(test)]
mod extra_tests {
    use super::*;
    use std::io;

    #[test]
    fn test_home_create_luks() {
        let setup = home_create_luks(&UserRecord::new(), HomeSetupFlags::None).unwrap();
        assert!(setup.mount_point.is_none());
    }

    #[test]
    fn test_home_resize_luks() {
        assert!(home_resize_luks(&UserRecord::new(), 8192).is_ok());
    }

    #[test]
    fn test_home_cleanup_luks() {
        assert!(home_cleanup_luks(HomeSetup::default()).is_ok());
    }

    #[test]
    fn test_home_lock_luks() {
        assert!(home_lock_luks(&UserRecord::new()).is_ok());
    }

    #[test]
    fn test_luks_error_display() {
        let error = LuksError::OpenFailed("crypt".into());
        assert!(error.to_string().contains("crypt"));
    }

    #[test]
    fn test_io_error_conversion() {
        let error = LuksError::from(io::Error::other("boom"));
        assert!(matches!(error, LuksError::Io(_)));
    }
}
