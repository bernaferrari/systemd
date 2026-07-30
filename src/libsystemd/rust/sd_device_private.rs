// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/libsystemd/sd-device/device-private.c

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{Display, Write as _};
use std::fs::File;
use std::path::{Path, PathBuf};

pub type Result<T> = std::result::Result<T, DeviceError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeviceError {
    InvalidInput(&'static str),
    MissingIdentity,
    MissingDevnode,
    ParseInt,
    Io,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceNumbers {
    pub mode: u32,
    pub devnum: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Device {
    syspath: Option<PathBuf>,
    subsystem: Option<String>,
    sysname: Option<String>,
    devnode: Option<PathBuf>,
    ifindex: Option<i32>,
    devnum: Option<DeviceNumbers>,
    devlink_priority: i32,
    is_initialized: bool,
    db_persist: bool,
    properties: BTreeMap<String, String>,
    properties_db: BTreeMap<String, String>,
    tags: BTreeSet<String>,
}

impl Device {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_property(
        &mut self,
        key: impl Into<String>,
        value: Option<impl Into<String>>,
    ) -> Result<()> {
        let key = key.into();
        if key.is_empty() {
            return Err(DeviceError::InvalidInput("key"));
        }

        let value = value.map(Into::into).unwrap_or_default();
        self.properties.insert(key.clone(), value.clone());
        if !key.starts_with('.') {
            self.properties_db.insert(key, value);
        }
        self.capture_identity_side_effects();
        Ok(())
    }

    pub fn add_propertyf(
        &mut self,
        key: impl Into<String>,
        value: Option<impl Display>,
    ) -> Result<()> {
        match value {
            Some(value) => {
                let mut rendered = String::new();
                write!(&mut rendered, "{value}").map_err(|_| DeviceError::Io)?;
                self.add_property(key, Some(rendered))
            }
            None => self.add_property(key, Option::<String>::None),
        }
    }

    pub fn set_devlink_priority(&mut self, priority: i32) {
        self.devlink_priority = priority;
    }

    pub fn devlink_priority(&self) -> i32 {
        self.devlink_priority
    }

    pub fn set_is_initialized(&mut self) {
        self.is_initialized = true;
    }

    pub fn is_initialized(&self) -> bool {
        self.is_initialized
    }

    pub fn set_db_persist(&mut self) {
        self.db_persist = true;
    }

    pub fn db_persist(&self) -> bool {
        self.db_persist
    }

    pub fn get_id_filename(&self) -> Result<String> {
        if let Some(numbers) = self.devnum {
            return Ok(format!(
                "b{}:{}",
                major(numbers.devnum),
                minor(numbers.devnum)
            ));
        }
        if let Some(ifindex) = self.ifindex {
            return Ok(format!("n{ifindex}"));
        }
        if let (Some(subsystem), Some(sysname)) =
            (self.subsystem.as_deref(), self.sysname.as_deref())
        {
            return Ok(format!("+{subsystem}:{sysname}"));
        }
        Err(DeviceError::MissingIdentity)
    }

    pub fn new_from_nulstr(nulstr: &[u8]) -> Result<Self> {
        if nulstr.is_empty() {
            return Err(DeviceError::InvalidInput("nulstr"));
        }

        let mut device = Self::new();
        for entry in nulstr.split(|b| *b == 0).filter(|chunk| !chunk.is_empty()) {
            let text = std::str::from_utf8(entry).map_err(|_| DeviceError::InvalidInput("utf8"))?;
            let text = text.split('\n').next().unwrap_or_default();
            let (key, value) = text
                .split_once('=')
                .ok_or(DeviceError::InvalidInput("KEY=VALUE"))?;
            device.add_property(key, Some(value.to_string()))?;
        }
        Ok(device)
    }

    pub fn new_from_mode_and_devnum(mode: u32, devnum: u64) -> Result<Self> {
        let mut device = Self::new();
        device.devnum = Some(DeviceNumbers { mode, devnum });
        device.add_property("MAJOR", Some(major(devnum).to_string()))?;
        device.add_property("MINOR", Some(minor(devnum).to_string()))?;
        Ok(device)
    }

    pub fn new_from_devnum(mode: u32, devnum: u64) -> Result<Self> {
        Self::new_from_mode_and_devnum(mode, devnum)
    }

    pub fn new_from_ifindex(ifindex: i32) -> Result<Self> {
        if ifindex <= 0 {
            return Err(DeviceError::InvalidInput("ifindex"));
        }
        Ok(Self {
            ifindex: Some(ifindex),
            ..Self::new()
        })
    }

    pub fn new_from_subsystem_sysname(
        subsystem: impl Into<String>,
        sysname: impl Into<String>,
    ) -> Result<Self> {
        let subsystem = subsystem.into();
        let sysname = sysname.into();
        if subsystem.is_empty() || sysname.is_empty() {
            return Err(DeviceError::InvalidInput("subsystem/sysname"));
        }

        Ok(Self {
            subsystem: Some(subsystem),
            sysname: Some(sysname),
            ..Self::new()
        })
    }

    pub fn new_from_stat_rdev(mode: u32, rdev: u64) -> Result<Self> {
        Self::new_from_mode_and_devnum(mode, rdev)
    }

    pub fn copy_properties(&mut self, src: &Device) {
        self.properties.extend(src.properties.clone());
        self.properties_db.extend(src.properties_db.clone());
        self.capture_identity_side_effects();
    }

    pub fn clone_with_db(&self) -> Result<Self> {
        let mut dest = Self::new();
        dest.syspath = self.syspath.clone();
        dest.subsystem = self.subsystem.clone();
        dest.sysname = self.sysname.clone();
        dest.devnode = self.devnode.clone();
        dest.ifindex = self.ifindex;
        dest.devnum = self.devnum;
        dest.devlink_priority = self.devlink_priority;
        dest.properties = self.properties.clone();
        dest.properties_db = self.properties_db.clone();
        dest.tags = self.tags.clone();
        dest.db_persist = self.db_persist;
        dest.is_initialized = self.is_initialized;
        Ok(dest)
    }

    pub fn open(&self) -> Result<File> {
        let devnode = self.devnode.as_ref().ok_or(DeviceError::MissingDevnode)?;
        File::open(devnode).map_err(|_| DeviceError::Io)
    }

    pub fn read_db(&mut self, force: bool) -> Result<bool> {
        if force {
            self.properties.extend(self.properties_db.clone());
            self.capture_identity_side_effects();
            return Ok(true);
        }
        Ok(false)
    }

    pub fn write_db(&mut self) -> Result<bool> {
        for (key, value) in &self.properties {
            if !key.starts_with('.') {
                self.properties_db.insert(key.clone(), value.clone());
            }
        }
        Ok(true)
    }

    pub fn tag(&mut self, tag: impl Into<String>, add: bool) -> Result<()> {
        let tag = tag.into();
        if tag.is_empty() {
            return Err(DeviceError::InvalidInput("tag"));
        }
        if add {
            self.tags.insert(tag);
        } else {
            self.tags.remove(&tag);
        }
        Ok(())
    }

    pub fn tags(&self) -> &BTreeSet<String> {
        &self.tags
    }

    pub fn udev_update_timeout_usec(&self) -> Result<u64> {
        let value = self
            .properties
            .get("UDEV_TIMEOUT_USEC")
            .or_else(|| self.properties_db.get("UDEV_TIMEOUT_USEC"))
            .ok_or(DeviceError::MissingIdentity)?;
        value.parse::<u64>().map_err(|_| DeviceError::ParseInt)
    }

    pub fn set_syspath(&mut self, path: impl AsRef<Path>) {
        self.syspath = Some(path.as_ref().to_path_buf());
    }

    pub fn set_devnode(&mut self, path: impl AsRef<Path>) {
        self.devnode = Some(path.as_ref().to_path_buf());
    }

    fn capture_identity_side_effects(&mut self) {
        if let Some(subsystem) = self.properties.get("SUBSYSTEM") {
            self.subsystem = Some(subsystem.clone());
        }
        if let Some(sysname) = self.properties.get("SYSNAME") {
            self.sysname = Some(sysname.clone());
        }
        if let Some(devname) = self.properties.get("DEVNAME") {
            self.devnode = Some(PathBuf::from(devname));
        }
        if let Some(ifindex) = self.properties.get("IFINDEX") {
            self.ifindex = ifindex.parse().ok();
        }
        if let (Some(major), Some(minor)) =
            (self.properties.get("MAJOR"), self.properties.get("MINOR"))
            && let (Ok(major), Ok(minor)) = (major.parse::<u64>(), minor.parse::<u64>())
        {
            self.devnum = Some(DeviceNumbers {
                mode: self.devnum.map(|d| d.mode).unwrap_or_default(),
                devnum: mkdev(major, minor),
            });
        }
    }
}

fn mkdev(major: u64, minor: u64) -> u64 {
    (major << 8) | minor
}

fn major(devnum: u64) -> u64 {
    devnum >> 8
}

fn minor(devnum: u64) -> u64 {
    devnum & 0xff
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn unique_path(name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("systemd-rs-{name}-{nanos}"))
    }

    #[test]
    fn add_property_mirrors_non_private_keys_into_db() {
        let mut device = Device::new();
        device.add_property("KEY", Some("VALUE")).unwrap();
        assert_eq!(device.properties.get("KEY"), Some(&"VALUE".to_string()));
        assert_eq!(device.properties_db.get("KEY"), Some(&"VALUE".to_string()));
    }

    #[test]
    fn private_keys_stay_out_of_database_view() {
        let mut device = Device::new();
        device.add_property(".INTERNAL", Some("VALUE")).unwrap();
        assert!(!device.properties_db.contains_key(".INTERNAL"));
    }

    #[test]
    fn formatted_property_uses_display() {
        let mut device = Device::new();
        device.add_propertyf("ANSWER", Some(42)).unwrap();
        assert_eq!(device.properties.get("ANSWER"), Some(&"42".to_string()));
    }

    #[test]
    fn nulstr_parser_truncates_trailing_newline_content() {
        let device = Device::new_from_nulstr(b"MAJOR=8\0MINOR=1\0SYSNAME=sda\nextra\0").unwrap();
        assert_eq!(device.properties.get("SYSNAME"), Some(&"sda".to_string()));
        assert_eq!(device.get_id_filename().unwrap(), "b8:1");
    }

    #[test]
    fn constructors_generate_expected_identity() {
        let by_ifindex = Device::new_from_ifindex(7).unwrap();
        assert_eq!(by_ifindex.get_id_filename().unwrap(), "n7");

        let by_subsystem = Device::new_from_subsystem_sysname("block", "sda").unwrap();
        assert_eq!(by_subsystem.get_id_filename().unwrap(), "+block:sda");
    }

    #[test]
    fn clone_with_db_preserves_tags_and_db_state() {
        let mut device = Device::new();
        device.add_property("KEY", Some("VALUE")).unwrap();
        device.tag("seat", true).unwrap();
        let cloned = device.clone_with_db().unwrap();
        assert_eq!(cloned.properties_db.get("KEY"), Some(&"VALUE".to_string()));
        assert!(cloned.tags().contains("seat"));
    }

    #[test]
    fn write_then_read_db_restores_public_property() {
        let mut device = Device::new();
        device
            .add_property("UDEV_TIMEOUT_USEC", Some("1500"))
            .unwrap();
        device.write_db().unwrap();
        device.properties.clear();
        assert!(device.read_db(true).unwrap());
        assert_eq!(device.udev_update_timeout_usec().unwrap(), 1500);
    }

    #[test]
    fn tag_add_and_remove_are_idempotent() {
        let mut device = Device::new();
        device.tag("uaccess", true).unwrap();
        device.tag("uaccess", true).unwrap();
        device.tag("uaccess", false).unwrap();
        assert!(!device.tags().contains("uaccess"));
    }

    #[test]
    fn open_uses_devnode_path() {
        let path = unique_path("device-open");
        fs::write(&path, b"test").unwrap();
        let mut device = Device::new();
        device.set_devnode(&path);
        assert!(device.open().is_ok());
        let _ = fs::remove_file(path);
    }

    #[test]
    fn invalid_timeout_reports_parse_failure() {
        let mut device = Device::new();
        device
            .add_property("UDEV_TIMEOUT_USEC", Some("not-a-number"))
            .unwrap();
        assert_eq!(
            device.udev_update_timeout_usec(),
            Err(DeviceError::ParseInt)
        );
    }
}
