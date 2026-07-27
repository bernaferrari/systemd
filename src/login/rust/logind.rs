// SPDX-License-Identifier: LGPL-2.1-or-later
// PORT-SYNC: src/login/logind.c

use std::collections::HashMap;

use crate::logind_action::HandleAction;
use crate::logind_core::ManagerConfig;
use crate::logind_device::Device;
use crate::logind_inhibit::Inhibitor;
use crate::logind_seat::Seat;
use crate::logind_session::Session;
use crate::logind_user::User;

#[derive(Debug, Clone)]
pub struct Manager {
    pub config: ManagerConfig,
    pub devices: HashMap<String, Device>,
    pub seats: HashMap<String, Seat>,
    pub sessions: HashMap<String, Session>,
    pub users: HashMap<u32, User>,
    pub inhibitors: HashMap<String, Inhibitor>,
    pub scheduled_shutdown_action: Option<HandleAction>,
}

impl Manager {
    pub fn new() -> Self {
        Self {
            config: ManagerConfig::default(),
            devices: HashMap::new(),
            seats: HashMap::new(),
            sessions: HashMap::new(),
            users: HashMap::new(),
            inhibitors: HashMap::new(),
            scheduled_shutdown_action: None,
        }
    }

    pub fn add_device(&mut self, device: Device) {
        self.devices.insert(device.sysfs.clone(), device);
    }

    pub fn add_seat(&mut self, seat: Seat) {
        self.seats.insert(seat.id.clone(), seat);
    }

    pub fn add_session(&mut self, session: Session) {
        self.sessions.insert(session.id.clone(), session);
    }

    pub fn add_user(&mut self, user: User) {
        self.users.insert(user.uid, user);
    }

    pub fn add_inhibitor(&mut self, inhibitor: Inhibitor) {
        self.inhibitors.insert(inhibitor.id.clone(), inhibitor);
    }
}

impl Default for Manager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::logind_seat::Seat;
    use crate::logind_session::Session;
    use crate::logind_user::User;

    #[test]
    fn manager_starts_empty() {
        let manager = Manager::new();
        assert!(manager.devices.is_empty());
        assert!(manager.seats.is_empty());
        assert!(manager.sessions.is_empty());
        assert!(manager.users.is_empty());
    }

    #[test]
    fn manager_collections_update_on_add() {
        let mut manager = Manager::new();
        manager.add_seat(Seat::new("seat0").expect("valid seat"));
        manager.add_session(Session::new("c1".into(), "alice".into(), 1000));
        manager.add_user(User::new(1000, 1000, "alice"));

        assert!(manager.seats.contains_key("seat0"));
        assert!(manager.sessions.contains_key("c1"));
        assert!(manager.users.contains_key(&1000));
    }
}
