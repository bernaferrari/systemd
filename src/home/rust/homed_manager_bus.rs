// SPDX-License-Identifier: LGPL-2.1-or-later

// PORT-SYNC: src/home/homed-manager-bus.c, src/home/homed-manager-bus.h

// Port of homed-manager-bus.c/h - D-Bus interface for Manager object

use std::collections::HashMap;

use crate::homed_home_bus::{Home, bus_home_path};

#[derive(Debug, Clone)]
pub struct AutoLoginEntry {
    pub user_name: String,
    pub seat: String,
    pub object_path: String,
}

pub struct ManagerBus {
    pub homes_by_uid: HashMap<u32, Home>,
    pub homes_by_name: HashMap<String, u32>,
}

impl ManagerBus {
    pub fn new() -> Self {
        Self {
            homes_by_uid: HashMap::new(),
            homes_by_name: HashMap::new(),
        }
    }

    pub fn register_home(&mut self, home: Home) {
        let uid = home.uid;
        let name = home.user_name.clone();
        self.homes_by_name.insert(name, uid);
        self.homes_by_uid.insert(uid, home);
    }

    pub fn unregister_home(&mut self, user_name: &str) -> Option<Home> {
        if let Some(uid) = self.homes_by_name.remove(user_name) {
            return self.homes_by_uid.remove(&uid);
        }
        None
    }

    pub fn get_auto_login_entries(&self) -> Vec<AutoLoginEntry> {
        let mut entries = Vec::new();
        for home in self.homes_by_uid.values() {
            if home.auto_login() {
                let path = bus_home_path(&home.user_name);
                for seat in &home.auto_login_seats {
                    entries.push(AutoLoginEntry {
                        user_name: home.user_name.clone(),
                        seat: seat.clone(),
                        object_path: path.clone(),
                    });
                }
            }
        }
        entries
    }

    pub fn lookup_user_name(&self, user_name: &str) -> Option<&Home> {
        self.homes_by_name
            .get(user_name)
            .and_then(|uid| self.homes_by_uid.get(uid))
    }

    pub fn lookup_uid(&self, uid: u32) -> Option<&Home> {
        self.homes_by_uid.get(&uid)
    }

    pub fn home_count(&self) -> usize {
        self.homes_by_uid.len()
    }
}

impl Default for ManagerBus {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_manager_bus_new() {
        let mgr = ManagerBus::new();
        assert_eq!(mgr.home_count(), 0);
    }

    #[test]
    fn test_register_and_lookup() {
        let mut mgr = ManagerBus::new();
        let home = Home::new("alice".to_string(), 1000);
        mgr.register_home(home);
        assert_eq!(mgr.home_count(), 1);
        assert!(mgr.lookup_user_name("alice").is_some());
        assert!(mgr.lookup_uid(1000).is_some());
        assert!(mgr.lookup_user_name("bob").is_none());
    }

    #[test]
    fn test_unregister_home() {
        let mut mgr = ManagerBus::new();
        let home = Home::new("alice".to_string(), 1000);
        mgr.register_home(home);
        let removed = mgr.unregister_home("alice");
        assert!(removed.is_some());
        assert_eq!(mgr.home_count(), 0);
    }

    #[test]
    fn test_auto_login_entries() {
        let mut mgr = ManagerBus::new();
        let mut home = Home::new("alice".to_string(), 1000);
        home.auto_login_seats = vec!["seat0".to_string()];
        mgr.register_home(home);
        let entries = mgr.get_auto_login_entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].user_name, "alice");
        assert_eq!(entries[0].seat, "seat0");
    }
}

#[cfg(test)]
mod extra_tests {
    use super::*;

    #[test]
    fn test_default_manager_bus() {
        let manager = ManagerBus::default();
        assert_eq!(manager.home_count(), 0);
    }

    #[test]
    fn test_unregister_missing_home() {
        let mut manager = ManagerBus::new();
        assert!(manager.unregister_home("missing").is_none());
    }

    #[test]
    fn test_auto_login_entries_empty_without_seats() {
        let mut manager = ManagerBus::new();
        manager.register_home(Home::new("alice".into(), 1000));
        assert!(manager.get_auto_login_entries().is_empty());
    }

    #[test]
    fn test_lookup_by_uid_missing() {
        let manager = ManagerBus::new();
        assert!(manager.lookup_uid(9999).is_none());
    }
}
