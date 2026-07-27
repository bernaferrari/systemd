// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/libsystemd/sd-device/test-device-util.c
//
// Device utility predicates modeled after the C helper tests.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceInfo {
    pub subsystem: Option<String>,
    pub devtype: Option<String>,
    pub sysname: String,
}

impl DeviceInfo {
    pub fn new(subsystem: Option<&str>, devtype: Option<&str>, sysname: &str) -> Self {
        Self {
            subsystem: subsystem.map(str::to_string),
            devtype: devtype.map(str::to_string),
            sysname: sysname.to_string(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeviceUtilError {
    EmptySysname,
}

impl std::fmt::Display for DeviceUtilError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptySysname => f.write_str("sysname must not be empty"),
        }
    }
}

impl std::error::Error for DeviceUtilError {}

pub fn device_in_subsystem(
    device: &DeviceInfo,
    subsystems: Option<&[Option<&str>]>,
) -> Result<bool, DeviceUtilError> {
    if device.sysname.is_empty() {
        return Err(DeviceUtilError::EmptySysname);
    }

    let candidates = subsystems.unwrap_or(&[]);
    match &device.subsystem {
        Some(current) => Ok(candidates
            .iter()
            .flatten()
            .any(|candidate| *candidate == current)),
        None => Ok(candidates.is_empty() || candidates.iter().any(|candidate| candidate.is_none())),
    }
}

pub fn device_is_devtype(
    device: &DeviceInfo,
    devtype: Option<&str>,
) -> Result<bool, DeviceUtilError> {
    if device.sysname.is_empty() {
        return Err(DeviceUtilError::EmptySysname);
    }
    Ok(match (&device.devtype, devtype) {
        (None, None) => true,
        (Some(found), Some(expected)) => found == expected,
        _ => false,
    })
}

pub fn device_is_subsystem_devtype(
    device: &DeviceInfo,
    subsystem: Option<&str>,
    devtype: Option<&str>,
) -> Result<bool, DeviceUtilError> {
    if !device_in_subsystem(device, Some(&[subsystem]))? {
        return Ok(false);
    }
    if devtype.is_none() {
        return Ok(true);
    }
    device_is_devtype(device, devtype)
}

pub fn device_sysname_startswith(
    device: &DeviceInfo,
    prefix: &str,
) -> Result<bool, DeviceUtilError> {
    if device.sysname.is_empty() {
        return Err(DeviceUtilError::EmptySysname);
    }
    Ok(device.sysname.starts_with(prefix))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subsystem_match_succeeds_for_exact_member() {
        let d = DeviceInfo::new(Some("block"), Some("disk"), "sda");
        assert!(device_in_subsystem(&d, Some(&[Some("net"), Some("block")])).unwrap());
    }

    #[test]
    fn subsystem_match_fails_for_missing_member() {
        let d = DeviceInfo::new(Some("block"), Some("disk"), "sda");
        assert!(!device_in_subsystem(&d, Some(&[Some("net")])).unwrap());
    }

    #[test]
    fn empty_subsystem_list_matches_devices_without_subsystem() {
        let d = DeviceInfo::new(None, None, "class");
        assert!(device_in_subsystem(&d, None).unwrap());
    }

    #[test]
    fn empty_subsystem_list_does_not_match_devices_with_subsystem() {
        let d = DeviceInfo::new(Some("net"), None, "lo");
        assert!(!device_in_subsystem(&d, None).unwrap());
    }

    #[test]
    fn devtype_matches_c_semantics() {
        let d = DeviceInfo::new(Some("block"), Some("disk"), "sda");
        assert!(device_is_devtype(&d, Some("disk")).unwrap());
        assert!(!device_is_devtype(&d, Some("partition")).unwrap());
    }

    #[test]
    fn missing_devtype_matches_none_only() {
        let d = DeviceInfo::new(Some("net"), None, "lo");
        assert!(device_is_devtype(&d, None).unwrap());
        assert!(!device_is_devtype(&d, Some("wlan")).unwrap());
    }

    #[test]
    fn subsystem_devtype_combines_both_checks() {
        let d = DeviceInfo::new(Some("block"), Some("disk"), "sda");
        assert!(device_is_subsystem_devtype(&d, Some("block"), Some("disk")).unwrap());
        assert!(!device_is_subsystem_devtype(&d, Some("block"), Some("partition")).unwrap());
    }

    #[test]
    fn none_none_matches_devices_without_subsystem_or_devtype() {
        let d = DeviceInfo::new(None, None, "class");
        assert!(device_is_subsystem_devtype(&d, None, None).unwrap());
    }

    #[test]
    fn sysname_prefix_follows_c_helper() {
        let d = DeviceInfo::new(Some("net"), None, "lo");
        assert!(device_sysname_startswith(&d, "l").unwrap());
        assert!(device_sysname_startswith(&d, "").unwrap());
        assert!(!device_sysname_startswith(&d, "00").unwrap());
    }
}
