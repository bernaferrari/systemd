// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/core/dbus-device.c
//
// Device units represent sysfs devices via udev.
// D-Bus property: SysFSPath (faithful to bus_device_vtable[] in C).

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceState {
    pub id: String,
    pub sysfs_path: Option<String>,
}

impl DeviceState {
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            sysfs_path: None,
        }
    }

    pub fn with_sysfs(id: impl Into<String>, sysfs_path: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            sysfs_path: Some(sysfs_path.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_state_new() {
        let d = DeviceState::new("dev-sda1.device");
        assert_eq!(d.id, "dev-sda1.device");
        assert!(d.sysfs_path.is_none());
    }

    #[test]
    fn device_with_sysfs() {
        let d = DeviceState::with_sysfs(
            "dev-sda1.device",
            "/sys/devices/pci0000:00/0000:00:1f.2/ata1/host0/target0:0:0/0:0:0:0/block/sda/sda1",
        );
        assert_eq!(d.id, "dev-sda1.device");
        assert!(d.sysfs_path.unwrap().starts_with("/sys/"));
    }
}
