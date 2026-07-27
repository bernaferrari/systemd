// SPDX-License-Identifier: LGPL-2.1-or-later

// PORT-SYNC: src/home/homed-home.c, src/home/homed-home.h

// Port of homed-home.c/h - Home object lifecycle management

use std::io;
use std::path::{Path, PathBuf};

use crate::homed_conf::UserStorage;
use crate::homed_home_bus::{Home, HomeState};
use crate::homed_operation::{Operation, OperationType};


pub const RETRY_DEACTIVATE_USEC: u64 = 15_000_000;

#[derive(Debug)]
pub enum HomeError {
    InvalidState {
        current: HomeState,
        expected: HomeState,
    },
    NotFound(String),
    AuthenticationFailed(String),
    MountFailed(String),
    Io(io::Error),
    Busy,
}

impl From<io::Error> for HomeError {
    fn from(e: io::Error) -> Self {
        HomeError::Io(e)
    }
}

impl std::fmt::Display for HomeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HomeError::InvalidState { current, expected } => {
                write!(f, "Invalid state: {:?} (expected {:?})", current, expected)
            }
            HomeError::NotFound(n) => write!(f, "Not found: {}", n),
            HomeError::AuthenticationFailed(m) => write!(f, "Authentication failed: {}", m),
            HomeError::MountFailed(m) => write!(f, "Mount failed: {}", m),
            HomeError::Io(e) => write!(f, "IO error: {}", e),
            HomeError::Busy => write!(f, "Home is busy"),
        }
    }
}

impl std::error::Error for HomeError {}

pub struct HomeSetup {
    pub undo_mount: bool,
    pub root_fd: Option<i32>,
    pub mount_point: Option<PathBuf>,
}

impl Default for HomeSetup {
    fn default() -> Self {
        Self {
            undo_mount: false,
            root_fd: None,
            mount_point: None,
        }
    }
}

impl Home {
    pub fn start_work(&mut self) -> Result<Operation, HomeError> {
        if self.is_busy() {
            return Err(HomeError::Busy);
        }
        self.state = HomeState::Activating;
        Ok(Operation::new(OperationType::Activate))
    }

    pub fn finish_work(&mut self, op: Operation, ret: i32) -> Result<(), HomeError> {
        if ret >= 0 {
            self.state = HomeState::Active;
        } else {
            self.state = HomeState::Absent;
        }
        Ok(())
    }

    pub fn start_deactivate(&mut self) -> Result<Operation, HomeError> {
        if !self.is_active() {
            return Err(HomeError::InvalidState {
                current: self.state,
                expected: HomeState::Active,
            });
        }
        self.state = HomeState::Deactivating;
        Ok(Operation::new(OperationType::Deactivate))
    }

    pub fn start_remove(&mut self) -> Result<Operation, HomeError> {
        if self.is_busy() {
            return Err(HomeError::Busy);
        }
        self.state = HomeState::Removing;
        Ok(Operation::new(OperationType::Remove))
    }

    pub fn verify_user_record(&self) -> Result<(), HomeError> {
        if self.user_name.is_empty() {
            return Err(HomeError::NotFound("empty user name".to_string()));
        }
        if self.uid == 0 {
            return Err(HomeError::NotFound("invalid uid".to_string()));
        }
        Ok(())
    }
}

pub fn home_augment_status(_home: &Home, _flags: u32) -> Result<(), HomeError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_home_start_work() {
        let mut home = Home::new("alice".to_string(), 1000);
        let op = home.start_work().unwrap();
        assert_eq!(home.state, HomeState::Activating);
        home.finish_work(op, 0).unwrap();
        assert_eq!(home.state, HomeState::Active);
    }

    #[test]
    fn test_home_start_work_busy() {
        let mut home = Home::new("alice".to_string(), 1000);
        home.state = HomeState::Activating;
        assert!(home.start_work().is_err());
    }

    #[test]
    fn test_home_start_deactivate() {
        let mut home = Home::new("alice".to_string(), 1000);
        home.state = HomeState::Active;
        let op = home.start_deactivate().unwrap();
        assert_eq!(home.state, HomeState::Deactivating);
        drop(op);
    }

    #[test]
    fn test_home_start_remove() {
        let mut home = Home::new("alice".to_string(), 1000);
        let op = home.start_remove().unwrap();
        assert_eq!(home.state, HomeState::Removing);
        drop(op);
    }

    #[test]
    fn test_home_verify_record() {
        let home = Home::new("alice".to_string(), 1000);
        assert!(home.verify_user_record().is_ok());
    }

    #[test]
    fn test_home_verify_record_empty() {
        let home = Home::new("".to_string(), 1000);
        assert!(home.verify_user_record().is_err());
    }
}

#[cfg(test)]
mod extra_tests {
    use super::*;

    #[test]
    fn test_finish_work_failure_resets_absent() {
        let mut home = Home::new("alice".into(), 1000);
        let operation = home.start_work().unwrap();
        home.finish_work(operation, -1).unwrap();
        assert_eq!(home.state, HomeState::Absent);
    }

    #[test]
    fn test_home_augment_status_ok() {
        let home = Home::new("alice".into(), 1000);
        assert!(home_augment_status(&home, 0).is_ok());
    }
}
