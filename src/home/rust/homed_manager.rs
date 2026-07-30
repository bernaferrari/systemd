// SPDX-License-Identifier: LGPL-2.1-or-later

// PORT-SYNC: src/home/homed-manager.c, src/home/homed-manager.h

// Port of homed-manager.c/h - Manager object for systemd-homed

use std::io;

use crate::home_util::{split_user_name_realm, suitable_user_name};
use crate::homed_conf::ManagerConfig;
use crate::homed_home_bus::Home;
use crate::homed_manager_bus::ManagerBus;

pub const HOME_UID_MIN: u32 = 60000;
pub const HOME_UID_MAX: u32 = 65533;
pub const HOME_USERS_MAX: usize = 500;
pub const PENDING_OPERATIONS_MAX: usize = 100;
pub const RETRY_DEACTIVATE_USEC: u64 = 15_000_000;

#[derive(Debug)]
pub enum ManagerError {
    AlreadyExists(String),
    NotFound(String),
    InvalidUserName(String),
    InvalidRecord(String),
    Busy(String),
    Io(io::Error),
    Quota(String),
}

impl From<io::Error> for ManagerError {
    fn from(e: io::Error) -> Self {
        ManagerError::Io(e)
    }
}

impl std::fmt::Display for ManagerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ManagerError::AlreadyExists(n) => write!(f, "Home already exists: {}", n),
            ManagerError::NotFound(n) => write!(f, "Home not found: {}", n),
            ManagerError::InvalidUserName(n) => write!(f, "Invalid user name: {}", n),
            ManagerError::InvalidRecord(r) => write!(f, "Invalid record: {}", r),
            ManagerError::Busy(n) => write!(f, "Home is busy: {}", n),
            ManagerError::Io(e) => write!(f, "IO error: {}", e),
            ManagerError::Quota(m) => write!(f, "Quota error: {}", m),
        }
    }
}

impl std::error::Error for ManagerError {}

pub struct Manager {
    pub config: ManagerConfig,
    pub bus: ManagerBus,
}

impl Manager {
    pub fn new(config: ManagerConfig) -> Self {
        Self {
            config,
            bus: ManagerBus::new(),
        }
    }

    pub fn home_count(&self) -> usize {
        self.bus.home_count()
    }

    pub fn get_home_by_name(&self, name: &str) -> Option<&Home> {
        self.bus.lookup_user_name(name)
    }

    pub fn get_home_by_uid(&self, uid: u32) -> Option<&Home> {
        self.bus.lookup_uid(uid)
    }

    pub fn create_home(&mut self, user_name: &str, uid: u32) -> Result<(), ManagerError> {
        if !suitable_user_name(user_name) {
            return Err(ManagerError::InvalidUserName(user_name.to_string()));
        }
        if self.bus.lookup_user_name(user_name).is_some() {
            return Err(ManagerError::AlreadyExists(user_name.to_string()));
        }
        if self.bus.home_count() >= HOME_USERS_MAX {
            return Err(ManagerError::Busy("Maximum home count reached".to_string()));
        }
        let home = Home::new(user_name.to_string(), uid);
        self.bus.register_home(home);
        Ok(())
    }

    pub fn remove_home(&mut self, user_name: &str) -> Result<(), ManagerError> {
        let home = self
            .bus
            .lookup_user_name(user_name)
            .ok_or_else(|| ManagerError::NotFound(user_name.to_string()))?;
        if home.is_busy() {
            return Err(ManagerError::Busy(user_name.to_string()));
        }
        self.bus.unregister_home(user_name);
        Ok(())
    }

    pub fn activate_home(&mut self, user_name: &str) -> Result<(), ManagerError> {
        let home = self
            .bus
            .lookup_user_name(user_name)
            .ok_or_else(|| ManagerError::NotFound(user_name.to_string()))?;
        if home.is_busy() {
            return Err(ManagerError::Busy(user_name.to_string()));
        }
        Ok(())
    }

    pub fn deactivate_home(&mut self, user_name: &str) -> Result<(), ManagerError> {
        let home = self
            .bus
            .lookup_user_name(user_name)
            .ok_or_else(|| ManagerError::NotFound(user_name.to_string()))?;
        if home.is_busy() {
            return Err(ManagerError::Busy(user_name.to_string()));
        }
        Ok(())
    }

    pub fn list_homes(&self) -> Vec<&Home> {
        self.bus.homes_by_uid.values().collect()
    }

    pub fn parse_user_name_with_realm(
        &self,
        input: &str,
    ) -> Result<(String, Option<String>), ManagerError> {
        split_user_name_realm(input).map_err(|e| ManagerError::InvalidRecord(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_manager() -> Manager {
        Manager::new(ManagerConfig::default())
    }

    #[test]
    fn test_manager_create_home() {
        let mut mgr = test_manager();
        mgr.create_home("alice", 60001).unwrap();
        assert_eq!(mgr.home_count(), 1);
    }

    #[test]
    fn test_manager_duplicate_home() {
        let mut mgr = test_manager();
        mgr.create_home("alice", 60001).unwrap();
        assert!(mgr.create_home("alice", 60002).is_err());
    }

    #[test]
    fn test_manager_remove_home() {
        let mut mgr = test_manager();
        mgr.create_home("alice", 60001).unwrap();
        mgr.remove_home("alice").unwrap();
        assert_eq!(mgr.home_count(), 0);
    }

    #[test]
    fn test_manager_remove_nonexistent() {
        let mut mgr = test_manager();
        assert!(mgr.remove_home("nobody").is_err());
    }

    #[test]
    fn test_manager_lookup() {
        let mut mgr = test_manager();
        mgr.create_home("alice", 60001).unwrap();
        assert!(mgr.get_home_by_name("alice").is_some());
        assert!(mgr.get_home_by_uid(60001).is_some());
        assert!(mgr.get_home_by_name("bob").is_none());
    }

    #[test]
    fn test_manager_invalid_user_name() {
        let mut mgr = test_manager();
        assert!(mgr.create_home("root", 0).is_err());
    }

    #[test]
    fn test_manager_list_homes() {
        let mut mgr = test_manager();
        mgr.create_home("alice", 60001).unwrap();
        mgr.create_home("bob", 60002).unwrap();
        assert_eq!(mgr.list_homes().len(), 2);
    }
}

#[cfg(test)]
mod extra_tests {
    use super::*;

    #[test]
    fn test_parse_user_name_with_realm() {
        let manager = Manager::new(ManagerConfig::default());
        let (user, realm) = manager
            .parse_user_name_with_realm("alice@example.com")
            .unwrap();
        assert_eq!(user, "alice");
        assert_eq!(realm.as_deref(), Some("example.com"));
    }
}
