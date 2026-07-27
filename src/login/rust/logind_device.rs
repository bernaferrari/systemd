// SPDX-License-Identifier: LGPL-2.1-or-later
// PORT-SYNC: src/login/logind-device.c

use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DualTimestamp {
    pub realtime_usec: u64,
    pub monotonic_usec: u64,
}

impl DualTimestamp {
    pub fn now() -> Self {
        let realtime_usec = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros() as u64;
        Self {
            realtime_usec,
            monotonic_usec: 0,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Device {
    pub sysfs: String,
    pub master: bool,
    pub seat: Option<String>,
    pub timestamp: DualTimestamp,
    pub session_devices: Vec<String>,
}

impl Device {
    pub fn new(sysfs: String, master: bool) -> Self {
        Self {
            sysfs,
            master,
            seat: None,
            timestamp: DualTimestamp::now(),
            session_devices: Vec::new(),
        }
    }

    pub fn attach(&mut self, seat: impl Into<String>) {
        self.seat = Some(seat.into());
    }

    pub fn detach(&mut self) {
        self.seat = None;
        self.session_devices.clear();
    }

    pub fn add_session_device(&mut self, id: impl Into<String>) {
        let id = id.into();
        if !self.session_devices.contains(&id) {
            self.session_devices.push(id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detaching_clears_state() {
        let mut device = Device::new("/sys/devices/card0".into(), true);
        device.attach("seat0");
        device.add_session_device("card0");
        device.detach();
        assert!(device.seat.is_none());
        assert!(device.session_devices.is_empty());
    }
}
