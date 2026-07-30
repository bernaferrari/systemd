// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/libsystemd/sd-device/sd-device.c
//
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

type Result<T> = std::result::Result<T, i32>;

const EINVAL: i32 = -libc::EINVAL;
const ENOENT: i32 = -libc::ENOENT;
const ENODEV: i32 = -libc::ENODEV;
const ENOTSUP: i32 = -libc::EOPNOTSUPP;
const EBADF: i32 = -libc::EBADF;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceAction {
    Invalid,
    Add,
    Remove,
    Change,
    Move,
    Online,
    Offline,
    Bind,
    Unbind,
}

#[derive(Debug, Clone)]
pub struct SdDevice {
    inner: Arc<Mutex<DeviceData>>,
}

#[derive(Debug, Clone)]
struct DeviceData {
    syspath: PathBuf,
    sysname: Option<String>,
    devtype: Option<String>,
    devname: Option<String>,
    subsystem: Option<String>,
    driver: Option<String>,
    action: DeviceAction,
    devnum: Option<u64>,
    devmode: Option<u32>,
    devuid: Option<u32>,
    devgid: Option<u32>,
    seqnum: Option<u64>,
    diskseq: Option<u64>,
    parent: Option<SdDevice>,
    usec_since_initialized: Option<u64>,
    properties: BTreeMap<String, String>,
    properties_db: BTreeMap<String, String>,
    sysattrs: BTreeMap<String, String>,
    tags: BTreeSet<String>,
    current_tags: BTreeSet<String>,
    devlinks: BTreeSet<String>,
    label: Option<String>,
    devnode_priority: i32,
    watch_handle: Option<i32>,
    ifindex: Option<i32>,
    recovery_state: Option<String>,
}

impl SdDevice {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(DeviceData {
                syspath: PathBuf::from("/sys"),
                sysname: None,
                devtype: None,
                devname: None,
                subsystem: None,
                driver: None,
                action: DeviceAction::Invalid,
                devnum: None,
                devmode: None,
                devuid: None,
                devgid: None,
                seqnum: None,
                diskseq: None,
                parent: None,
                usec_since_initialized: None,
                properties: BTreeMap::new(),
                properties_db: BTreeMap::new(),
                sysattrs: BTreeMap::new(),
                tags: BTreeSet::new(),
                current_tags: BTreeSet::new(),
                devlinks: BTreeSet::new(),
                label: None,
                devnode_priority: 0,
                watch_handle: None,
                ifindex: None,
                recovery_state: None,
            })),
        }
    }

    pub fn new_from_syspath(syspath: impl AsRef<Path>) -> Result<Self> {
        let device = Self::new();
        device.set_syspath(syspath, true)?;
        Ok(device)
    }

    pub fn ref_clone(&self) -> Self {
        self.clone()
    }

    pub fn unref(self) {}

    pub fn syspath(&self) -> Result<String> {
        let syspath = self.inner.lock().unwrap().syspath.clone();
        if syspath == Path::new("/sys") {
            return Err(ENOENT);
        }
        Ok(syspath.display().to_string())
    }

    pub fn sysname(&self) -> Result<String> {
        self.inner.lock().unwrap().sysname.clone().ok_or(ENOENT)
    }
    pub fn devname(&self) -> Result<String> {
        self.inner.lock().unwrap().devname.clone().ok_or(ENOENT)
    }
    pub fn devtype(&self) -> Result<String> {
        self.inner.lock().unwrap().devtype.clone().ok_or(ENOENT)
    }
    pub fn subsystem(&self) -> Result<String> {
        self.inner.lock().unwrap().subsystem.clone().ok_or(ENOENT)
    }
    pub fn driver(&self) -> Result<String> {
        self.inner.lock().unwrap().driver.clone().ok_or(ENOENT)
    }
    pub fn devnum(&self) -> Result<u64> {
        self.inner.lock().unwrap().devnum.ok_or(ENOENT)
    }
    pub fn action(&self) -> Result<DeviceAction> {
        Ok(self.inner.lock().unwrap().action)
    }
    pub fn seqnum(&self) -> Result<u64> {
        self.inner.lock().unwrap().seqnum.ok_or(ENOENT)
    }
    pub fn diskseq(&self) -> Result<u64> {
        self.inner.lock().unwrap().diskseq.ok_or(ENOENT)
    }
    pub fn parent(&self) -> Option<SdDevice> {
        self.inner.lock().unwrap().parent.clone()
    }

    pub fn parent_with_subsystem(&self, subsystem: &str) -> Result<SdDevice> {
        let mut current = self.parent();
        while let Some(device) = current {
            if device.subsystem().ok().as_deref() == Some(subsystem) {
                return Ok(device);
            }
            current = device.parent();
        }
        Err(ENOENT)
    }

    pub fn is_initialized(&self) -> bool {
        self.inner.lock().unwrap().usec_since_initialized.is_some()
    }
    pub fn usec_since_initialized(&self) -> Result<u64> {
        self.inner
            .lock()
            .unwrap()
            .usec_since_initialized
            .ok_or(ENOENT)
    }
    pub fn devpath(&self) -> Result<String> {
        Ok(self.syspath()?.trim_start_matches("/sys").to_string())
    }
    pub fn properties(&self) -> Result<Vec<String>> {
        Ok(self
            .inner
            .lock()
            .unwrap()
            .properties
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect())
    }

    pub fn properties_nulstr(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        for line in self.properties()? {
            out.extend_from_slice(line.as_bytes());
            out.push(0);
        }
        out.push(0);
        Ok(out)
    }

    pub fn property_value(&self, key: &str) -> Result<String> {
        self.inner
            .lock()
            .unwrap()
            .properties
            .get(key)
            .cloned()
            .ok_or(ENOENT)
    }
    pub fn sysattr_value(&self, sysattr: &str) -> Result<String> {
        self.inner
            .lock()
            .unwrap()
            .sysattrs
            .get(sysattr)
            .cloned()
            .ok_or(ENOENT)
    }
    pub fn sysattr(&self, sysattr: &str) -> Result<String> {
        self.sysattr_value(sysattr)
    }
    pub fn tags(&self) -> Result<Vec<String>> {
        Ok(self.inner.lock().unwrap().tags.iter().cloned().collect())
    }
    pub fn devlinks(&self) -> Result<Vec<String>> {
        Ok(self
            .inner
            .lock()
            .unwrap()
            .devlinks
            .iter()
            .cloned()
            .collect())
    }
    pub fn label(&self) -> Result<String> {
        self.inner.lock().unwrap().label.clone().ok_or(ENOENT)
    }

    pub fn property_value_int(&self, key: &str) -> Result<i32> {
        self.property_value(key)?.parse::<i32>().map_err(|_| EINVAL)
    }

    pub fn property_value_uint64(&self, key: &str) -> Result<u64> {
        self.property_value(key)?.parse::<u64>().map_err(|_| EINVAL)
    }

    pub fn property_value_bool(&self, key: &str) -> Result<bool> {
        match self.property_value(key)?.as_str() {
            "1" | "true" | "yes" => Ok(true),
            "0" | "false" | "no" => Ok(false),
            _ => Err(EINVAL),
        }
    }

    pub fn has_tag(&self, tag: &str) -> bool {
        self.inner.lock().unwrap().tags.contains(tag)
    }
    pub fn current_tags(&self) -> Result<Vec<String>> {
        Ok(self
            .inner
            .lock()
            .unwrap()
            .current_tags
            .iter()
            .cloned()
            .collect())
    }
    pub fn devnode_priority(&self) -> i32 {
        self.inner.lock().unwrap().devnode_priority
    }
    pub fn watch_handle(&self) -> Result<i32> {
        self.inner.lock().unwrap().watch_handle.ok_or(EBADF)
    }
    pub fn ifindex(&self) -> Result<i32> {
        self.inner.lock().unwrap().ifindex.ok_or(ENOENT)
    }
    pub fn devmode(&self) -> Result<u32> {
        self.inner.lock().unwrap().devmode.ok_or(ENOENT)
    }
    pub fn devuid(&self) -> Result<u32> {
        self.inner.lock().unwrap().devuid.ok_or(ENOENT)
    }
    pub fn devgid(&self) -> Result<u32> {
        self.inner.lock().unwrap().devgid.ok_or(ENOENT)
    }
    pub fn recovery_state(&self) -> Result<String> {
        self.inner
            .lock()
            .unwrap()
            .recovery_state
            .clone()
            .ok_or(ENOENT)
    }

    pub fn set_recovery_state(&self, value: impl Into<String>) -> Result<()> {
        self.inner.lock().unwrap().recovery_state = Some(value.into());
        Ok(())
    }

    pub fn trigger(&self, action: DeviceAction, devpath: Option<&str>) -> Result<String> {
        let mut inner = self.inner.lock().unwrap();
        inner.action = action;
        Ok(devpath.unwrap_or("change").to_string())
    }

    pub fn add_property_aux(&self, key: &str, value: &str, db: bool) -> Result<()> {
        if !property_is_valid(key, value) {
            return Err(EINVAL);
        }
        let mut inner = self.inner.lock().unwrap();
        let map = if db {
            &mut inner.properties_db
        } else {
            &mut inner.properties
        };
        if value.is_empty() {
            map.remove(key);
        } else {
            map.insert(key.to_string(), value.to_string());
        }
        Ok(())
    }

    pub fn add_sysattr(&self, key: &str, value: &str) {
        self.inner
            .lock()
            .unwrap()
            .sysattrs
            .insert(key.to_string(), value.to_string());
    }

    pub fn add_tag(&self, tag: &str, current: bool) {
        let mut inner = self.inner.lock().unwrap();
        inner.tags.insert(tag.to_string());
        if current {
            inner.current_tags.insert(tag.to_string());
        }
    }

    pub fn add_devlink(&self, link: &str) {
        self.inner.lock().unwrap().devlinks.insert(link.to_string());
    }

    pub fn set_parent(&self, parent: SdDevice) {
        self.inner.lock().unwrap().parent = Some(parent);
    }

    pub fn set_subsystem(&self, subsystem: &str) {
        self.inner.lock().unwrap().subsystem = Some(subsystem.to_string());
    }

    pub fn set_syspath(&self, syspath: impl AsRef<Path>, verify: bool) -> Result<()> {
        let syspath = syspath.as_ref();
        let normalized = if verify {
            syspath
                .canonicalize()
                .unwrap_or_else(|_| syspath.to_path_buf())
        } else {
            syspath.to_path_buf()
        };
        if !normalized.starts_with("/sys") {
            return Err(if verify { ENODEV } else { EINVAL });
        }
        if normalized == Path::new("/sys") {
            return Err(ENODEV);
        }

        let devpath = normalized
            .strip_prefix("/sys")
            .ok()
            .and_then(|p| p.to_str())
            .ok_or(EINVAL)?
            .to_string();
        let sysname = normalized
            .file_name()
            .and_then(|s| s.to_str())
            .map(str::to_string);
        let mut inner = self.inner.lock().unwrap();
        inner.syspath = normalized;
        inner.sysname = sysname;
        inner
            .properties
            .insert("DEVPATH".into(), format!("/{devpath}"));
        Ok(())
    }
}

impl Default for SdDevice {
    fn default() -> Self {
        Self::new()
    }
}

pub fn property_is_valid(key: &str, value: &str) -> bool {
    if key.is_empty()
        || !key
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.'))
    {
        return false;
    }
    value.is_empty()
        || (value.chars().all(|c| !c.is_control()) && std::str::from_utf8(value.as_bytes()).is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_property_names_and_values() {
        assert!(property_is_valid("ID_MODEL", "disk"));
        assert!(property_is_valid("ID.MODEL", ""));
        assert!(!property_is_valid("", "x"));
        assert!(!property_is_valid("bad-key", "x"));
        assert!(!property_is_valid("KEY", "bad\nvalue"));
    }

    #[test]
    fn syspath_sets_devpath_and_sysname() {
        let device = SdDevice::new();
        device
            .set_syspath("/sys/devices/pci0000:00/0000:00:1f.2", false)
            .unwrap();
        assert_eq!(
            device.syspath().unwrap(),
            "/sys/devices/pci0000:00/0000:00:1f.2"
        );
        assert_eq!(device.sysname().unwrap(), "0000:00:1f.2");
        assert_eq!(
            device.property_value("DEVPATH").unwrap(),
            "/devices/pci0000:00/0000:00:1f.2"
        );
    }

    #[test]
    fn adds_and_removes_properties() {
        let device = SdDevice::new();
        device.add_property_aux("MAJOR", "8", false).unwrap();
        assert_eq!(device.property_value("MAJOR").unwrap(), "8");
        device.add_property_aux("MAJOR", "", false).unwrap();
        assert_eq!(device.property_value("MAJOR"), Err(ENOENT));
    }

    #[test]
    fn encodes_properties_as_nulstr() {
        let device = SdDevice::new();
        device.add_property_aux("A", "1", false).unwrap();
        device.add_property_aux("B", "2", false).unwrap();
        let nulstr = device.properties_nulstr().unwrap();
        assert!(nulstr.ends_with(&[0, 0]));
        assert!(String::from_utf8_lossy(&nulstr).contains("A=1"));
    }

    #[test]
    fn parses_typed_property_values() {
        let device = SdDevice::new();
        device.add_property_aux("INT", "42", false).unwrap();
        device.add_property_aux("U64", "99", false).unwrap();
        device.add_property_aux("BOOL", "yes", false).unwrap();
        assert_eq!(device.property_value_int("INT").unwrap(), 42);
        assert_eq!(device.property_value_uint64("U64").unwrap(), 99);
        assert!(device.property_value_bool("BOOL").unwrap());
    }

    #[test]
    fn tracks_tags_and_devlinks() {
        let device = SdDevice::new();
        device.add_tag("seat", true);
        device.add_devlink("/dev/disk/by-id/x");
        assert!(device.has_tag("seat"));
        assert_eq!(device.current_tags().unwrap(), vec!["seat".to_string()]);
        assert_eq!(
            device.devlinks().unwrap(),
            vec!["/dev/disk/by-id/x".to_string()]
        );
    }

    #[test]
    fn finds_parent_by_subsystem() {
        let parent = SdDevice::new();
        parent.set_subsystem("block");
        let child = SdDevice::new();
        child.set_parent(parent.clone());
        assert_eq!(
            child
                .parent_with_subsystem("block")
                .unwrap()
                .subsystem()
                .unwrap(),
            "block"
        );
    }

    #[test]
    fn handles_recovery_state_and_trigger() {
        let device = SdDevice::new();
        device.set_recovery_state("recovered").unwrap();
        assert_eq!(device.recovery_state().unwrap(), "recovered");
        assert_eq!(
            device
                .trigger(DeviceAction::Change, Some("/devices/x"))
                .unwrap(),
            "/devices/x"
        );
        assert_eq!(device.action().unwrap(), DeviceAction::Change);
    }

    #[test]
    fn absent_watch_handle_is_badf() {
        let device = SdDevice::new();
        assert_eq!(device.watch_handle(), Err(EBADF));
        assert!(matches!(
            SdDevice::new_from_syspath("/tmp/not-sys"),
            Err(ENODEV)
        ));
    }
}
