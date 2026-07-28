// SPDX-License-Identifier: LGPL-2.1-or-later

// PORT-SYNC: src/home/homed-home-bus.c, src/home/homed-home-bus.h

// Port of homed-home-bus.c/h - D-Bus interface for Home objects

use std::collections::HashMap;

use crate::homed_operation::OperationType;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HomeState {
    Absent,
    Activating,
    ActivatingLinger,
    Active,
    Deactivating,
    Removing,
}

impl HomeState {
    pub fn as_str(&self) -> &'static str {
        match self {
            HomeState::Absent => "absent",
            HomeState::Activating => "activating",
            HomeState::ActivatingLinger => "activating-linger",
            HomeState::Active => "active",
            HomeState::Deactivating => "deactivating",
            HomeState::Removing => "removing",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "absent" => Some(HomeState::Absent),
            "activating" => Some(HomeState::Activating),
            "activating-linger" => Some(HomeState::ActivatingLinger),
            "active" => Some(HomeState::Active),
            "deactivating" => Some(HomeState::Deactivating),
            "removing" => Some(HomeState::Removing),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct UnixRecord {
    pub user_name: String,
    pub uid: u32,
    pub gid: u32,
    pub real_name: Option<String>,
    pub home_directory: Option<String>,
    pub shell: Option<String>,
}

pub struct Home {
    pub user_name: String,
    pub uid: u32,
    pub state: HomeState,
    pub unix_record: Option<UnixRecord>,
    pub auto_login_seats: Vec<String>,
}

impl Home {
    pub fn new(user_name: String, uid: u32) -> Self {
        Self {
            user_name,
            uid,
            state: HomeState::Absent,
            unix_record: None,
            auto_login_seats: Vec::new(),
        }
    }

    pub fn state_to_string(&self) -> &'static str {
        self.state.as_str()
    }

    pub fn get_state(&self) -> HomeState {
        self.state
    }

    pub fn set_state(&mut self, state: HomeState) {
        self.state = state;
    }

    pub fn auto_login(&self) -> bool {
        !self.auto_login_seats.is_empty()
    }

    pub fn is_active(&self) -> bool {
        self.state == HomeState::Active
    }

    pub fn is_busy(&self) -> bool {
        matches!(
            self.state,
            HomeState::Activating
                | HomeState::ActivatingLinger
                | HomeState::Deactivating
                | HomeState::Removing
        )
    }
}

pub fn bus_home_path(user_name: &str) -> String {
    format!("/org/freedesktop/home1/home/{}", user_name)
}

pub const BUS_HOME_INTERFACE: &str = "org.freedesktop.home1.Home";
pub const BUS_HOME_MANAGER_INTERFACE: &str = "org.freedesktop.home1.Manager";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_home_state_roundtrip() {
        assert_eq!(HomeState::from_str("active"), Some(HomeState::Active));
        assert_eq!(HomeState::from_str("absent"), Some(HomeState::Absent));
        assert_eq!(HomeState::from_str("invalid"), None);
    }

    #[test]
    fn test_home_new() {
        let home = Home::new("alice".to_string(), 1000);
        assert_eq!(home.user_name, "alice");
        assert_eq!(home.uid, 1000);
        assert_eq!(home.state, HomeState::Absent);
        assert!(!home.is_active());
        assert!(!home.is_busy());
    }

    #[test]
    fn test_home_state_transitions() {
        let mut home = Home::new("bob".to_string(), 1001);
        home.set_state(HomeState::Activating);
        assert!(home.is_busy());
        home.set_state(HomeState::Active);
        assert!(home.is_active());
        assert!(!home.is_busy());
    }

    #[test]
    fn test_bus_home_path() {
        assert_eq!(
            bus_home_path("testuser"),
            "/org/freedesktop/home1/home/testuser"
        );
    }
}

#[cfg(test)]
mod extra_tests {
    use super::*;

    #[test]
    fn test_state_to_string_matches_state() {
        let mut home = Home::new("alice".into(), 1000);
        home.set_state(HomeState::Active);
        assert_eq!(home.state_to_string(), "active");
    }

    #[test]
    fn test_auto_login_reflects_seats() {
        let mut home = Home::new("alice".into(), 1000);
        assert!(!home.auto_login());
        home.auto_login_seats.push("seat0".into());
        assert!(home.auto_login());
    }

    #[test]
    fn test_removing_state_is_busy() {
        let mut home = Home::new("alice".into(), 1000);
        home.set_state(HomeState::Removing);
        assert!(home.is_busy());
    }

    #[test]
    fn test_interface_constants() {
        assert!(BUS_HOME_INTERFACE.contains("home1"));
        assert!(BUS_HOME_MANAGER_INTERFACE.contains("Manager"));
    }
}
