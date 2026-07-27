// SPDX-License-Identifier: LGPL-2.1-or-later
// PORT-SYNC: src/login/logind-session-device.c

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionDeviceType {
    Unknown,
    Drm,
    Evdev,
    Hidraw,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionDevice {
    pub id: String,
    pub device_path: String,
    pub device_type: SessionDeviceType,
    pub active: bool,
}

impl SessionDevice {
    pub fn new(
        id: impl Into<String>,
        device_path: impl Into<String>,
        device_type: SessionDeviceType,
    ) -> Self {
        Self {
            id: id.into(),
            device_path: device_path.into(),
            device_type,
            active: false,
        }
    }

    pub fn activate(&mut self) {
        self.active = true;
    }

    pub fn deactivate(&mut self) {
        self.active = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn devices_toggle_state() {
        let mut device = SessionDevice::new("a", "/dev/dri/card0", SessionDeviceType::Drm);
        device.activate();
        assert!(device.active);
        device.deactivate();
        assert!(!device.active);
    }
}
