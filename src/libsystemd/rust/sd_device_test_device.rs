// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/libsystemd/sd-device/test-sd-device.c
//
// Mock sd-device objects and lookups covering the core test scenarios.

use std::collections::BTreeMap;

const SYSPATH_PREFIX: &str = "/sys";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeviceError {
    InvalidSyspath,
    InvalidPropertyName,
    InvalidPropertyValue,
    NotFound,
}

impl std::fmt::Display for DeviceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidSyspath => f.write_str("invalid syspath"),
            Self::InvalidPropertyName => f.write_str("invalid property name"),
            Self::InvalidPropertyValue => f.write_str("invalid property value"),
            Self::NotFound => f.write_str("device not found"),
        }
    }
}

impl std::error::Error for DeviceError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MockDevice {
    pub syspath: String,
    pub sysname: String,
    pub subsystem: Option<String>,
    pub driver_subsystem: Option<String>,
    pub devname: Option<String>,
    pub device_id: Option<String>,
    pub devtype: Option<String>,
    pub sysattrs: BTreeMap<String, String>,
    pub properties: BTreeMap<String, String>,
}

impl MockDevice {
    pub fn validate_property_name(name: &str) -> Result<(), DeviceError> {
        if name.is_empty() {
            return Ok(());
        }
        if name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
            Ok(())
        } else {
            Err(DeviceError::InvalidPropertyName)
        }
    }

    pub fn validate_property_value(value: &str) -> Result<(), DeviceError> {
        if value.contains(['\n', '\r', '\t']) {
            Err(DeviceError::InvalidPropertyValue)
        } else {
            Ok(())
        }
    }

    pub fn add_property(&mut self, name: &str, value: Option<&str>) -> Result<(), DeviceError> {
        Self::validate_property_name(name)?;
        match value {
            None | Some("") => {
                self.properties.remove(name);
            }
            Some(value) => {
                Self::validate_property_value(value)?;
                self.properties.insert(name.to_string(), value.to_string());
            }
        }
        Ok(())
    }

    pub fn property_value(&self, name: &str) -> Result<&str, DeviceError> {
        self.properties
            .get(name)
            .map(String::as_str)
            .ok_or(DeviceError::NotFound)
    }
}

pub fn syspath_is_valid(path: &str) -> bool {
    path == SYSPATH_PREFIX || path.starts_with("/sys/")
}

pub fn sysname_from_syspath(path: &str) -> Result<&str, DeviceError> {
    if !syspath_is_valid(path) {
        return Err(DeviceError::InvalidSyspath);
    }
    path.rsplit('/').next().ok_or(DeviceError::InvalidSyspath)
}

#[derive(Debug, Clone, Default)]
pub struct DeviceRegistry {
    devices: Vec<MockDevice>,
}

impl DeviceRegistry {
    pub fn insert(&mut self, device: MockDevice) {
        self.devices.push(device);
    }

    pub fn new_from_syspath(&self, syspath: &str) -> Result<MockDevice, DeviceError> {
        self.devices
            .iter()
            .find(|d| d.syspath == syspath)
            .cloned()
            .ok_or(DeviceError::NotFound)
    }

    pub fn new_from_path(&self, path: &str) -> Result<MockDevice, DeviceError> {
        self.devices
            .iter()
            .find(|d| d.syspath == path || d.devname.as_deref() == Some(path))
            .cloned()
            .ok_or(DeviceError::NotFound)
    }

    pub fn new_from_device_id(&self, device_id: &str) -> Result<MockDevice, DeviceError> {
        self.devices
            .iter()
            .find(|d| d.device_id.as_deref() == Some(device_id))
            .cloned()
            .ok_or(DeviceError::NotFound)
    }

    pub fn new_from_devname(&self, devname: &str) -> Result<MockDevice, DeviceError> {
        self.devices
            .iter()
            .find(|d| d.devname.as_deref() == Some(devname))
            .cloned()
            .ok_or(DeviceError::NotFound)
    }

    pub fn new_from_subsystem_sysname(
        &self,
        subsystem: &str,
        sysname: &str,
    ) -> Result<MockDevice, DeviceError> {
        self.devices
            .iter()
            .find(|d| {
                d.subsystem.as_deref() == Some(subsystem)
                    && if subsystem == "drivers" {
                        let composite = match (&d.driver_subsystem, d.sysname.as_str()) {
                            (Some(driver_subsystem), sysname) => {
                                format!("{driver_subsystem}:{sysname}")
                            }
                            _ => d.sysname.clone(),
                        };
                        composite == sysname
                    } else {
                        d.sysname == sysname
                    }
            })
            .cloned()
            .ok_or(DeviceError::NotFound)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_device() -> MockDevice {
        MockDevice {
            syspath: "/sys/class/net/lo".into(),
            sysname: "lo".into(),
            subsystem: Some("net".into()),
            driver_subsystem: None,
            devname: Some("/dev/lo".into()),
            device_id: Some("n1".into()),
            devtype: None,
            sysattrs: BTreeMap::from([("ifindex".into(), "1".into())]),
            properties: BTreeMap::new(),
        }
    }

    #[test]
    fn valid_syspaths_must_live_under_sys() {
        assert!(syspath_is_valid("/sys"));
        assert!(syspath_is_valid("/sys/class/net/lo"));
        assert!(!syspath_is_valid("/dev/null"));
    }

    #[test]
    fn sysname_is_last_component() {
        assert_eq!(sysname_from_syspath("/sys/class/net/lo").unwrap(), "lo");
    }

    #[test]
    fn property_names_follow_c_test_constraints() {
        assert!(MockDevice::validate_property_name("ID_NET_DRIVER").is_ok());
        assert_eq!(
            MockDevice::validate_property_name("ID-NET").unwrap_err(),
            DeviceError::InvalidPropertyName
        );
    }

    #[test]
    fn property_values_reject_control_characters() {
        assert!(MockDevice::validate_property_value("e1000").is_ok());
        assert_eq!(
            MockDevice::validate_property_value("bad\nvalue").unwrap_err(),
            DeviceError::InvalidPropertyValue
        );
    }

    #[test]
    fn add_property_supports_set_and_remove() {
        let mut device = sample_device();
        device
            .add_property("ID_NET_DRIVER", Some("loopback"))
            .unwrap();
        assert_eq!(device.property_value("ID_NET_DRIVER").unwrap(), "loopback");
        device.add_property("ID_NET_DRIVER", None).unwrap();
        assert_eq!(
            device.property_value("ID_NET_DRIVER").unwrap_err(),
            DeviceError::NotFound
        );
    }

    #[test]
    fn registry_can_lookup_by_syspath() {
        let mut registry = DeviceRegistry::default();
        let device = sample_device();
        registry.insert(device.clone());
        assert_eq!(registry.new_from_syspath(&device.syspath).unwrap(), device);
    }

    #[test]
    fn registry_can_lookup_by_devname_and_device_id() {
        let mut registry = DeviceRegistry::default();
        let device = sample_device();
        registry.insert(device.clone());
        assert_eq!(registry.new_from_devname("/dev/lo").unwrap(), device);
        assert_eq!(registry.new_from_device_id("n1").unwrap(), device);
    }

    #[test]
    fn registry_can_lookup_by_subsystem_and_sysname() {
        let mut registry = DeviceRegistry::default();
        let device = sample_device();
        registry.insert(device.clone());
        assert_eq!(
            registry.new_from_subsystem_sysname("net", "lo").unwrap(),
            device
        );
    }

    #[test]
    fn drivers_subsystem_uses_driver_subsystem_prefix() {
        let mut registry = DeviceRegistry::default();
        let device = MockDevice {
            syspath: "/sys/bus/mdio_bus/drivers/Qualcomm Atheros AR8031/AR8033".into(),
            sysname: "Qualcomm Atheros AR8031/AR8033".into(),
            subsystem: Some("drivers".into()),
            driver_subsystem: Some("mdio_bus".into()),
            devname: None,
            device_id: Some("+drivers:mdio_bus:Qualcomm Atheros AR8031!AR8033".into()),
            devtype: None,
            sysattrs: BTreeMap::new(),
            properties: BTreeMap::new(),
        };
        registry.insert(device.clone());
        assert_eq!(
            registry
                .new_from_subsystem_sysname("drivers", "mdio_bus:Qualcomm Atheros AR8031/AR8033")
                .unwrap(),
            device
        );
    }
}
