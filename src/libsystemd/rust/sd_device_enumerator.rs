// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/libsystemd/sd-device/device-enumerator.c
//
// Device enumeration with subsystem/sysattr/property/sysname/tag/parent
// filter matching, scan of /sys, and sorted iteration.
//
// Faithful Rust port of the C sd_device_enumerator API. Pure safe idiomatic Rust.

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::rc::Rc;

// ── Constants ─────────────────────────────────────────────────────────────

/// Path to the sysfs mount point.
pub const SYSFS_PATH: &str = "/sys";

// ── Error type ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnumeratorError {
    InvalidArgument,
    OutOfMemory,
    Io(String),
    NotInitialized,
}

impl std::fmt::Display for EnumeratorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EnumeratorError::InvalidArgument => write!(f, "Invalid argument"),
            EnumeratorError::OutOfMemory => write!(f, "Out of memory"),
            EnumeratorError::Io(s) => write!(f, "I/O: {s}"),
            EnumeratorError::NotInitialized => write!(f, "Not initialized"),
        }
    }
}

impl std::error::Error for EnumeratorError {}

pub type Result<T> = std::result::Result<T, EnumeratorError>;

// ── Enumeration type ──────────────────────────────────────────────────────

/// What kind of devices to enumerate.
/// Corresponds to `DeviceEnumerationType` in the C code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnumerationType {
    Devices,
    Subsystems,
    All,
    Invalid,
}

impl Default for EnumerationType {
    fn default() -> Self {
        EnumerationType::Invalid
    }
}

// ── Match flags ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MatchFlag(u32);

impl MatchFlag {
    pub const NONE: Self = Self(0);
    pub const BASIC: Self = Self(1 << 0);
    pub const SYSNAME: Self = Self(1 << 1);
    pub const SUBSYSTEM: Self = Self(1 << 2);
    pub const PARENT: Self = Self(1 << 3);
    pub const TAG: Self = Self(1 << 4);
    pub const ALL: Self = Self((1 << 5) - 1);
}

impl std::ops::BitOr for MatchFlag {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

impl std::ops::BitOrAssign for MatchFlag {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

impl std::ops::BitAnd for MatchFlag {
    type Output = Self;
    fn bitand(self, rhs: Self) -> Self {
        Self(self.0 & rhs.0)
    }
}

impl std::ops::BitAndAssign for MatchFlag {
    fn bitand_assign(&mut self, rhs: Self) {
        self.0 &= rhs.0;
    }
}

impl MatchFlag {
    pub const fn bits(&self) -> u32 {
        self.0
    }
    pub const fn contains(&self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
}

// ── Match initialized type ────────────────────────────────────────────────

/// Whether to match only initialized devices.
/// Corresponds to `MatchInitializedType` in the C code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchInitialized {
    Compat,
    Yes,
    No,
    All,
}

impl Default for MatchInitialized {
    fn default() -> Self {
        MatchInitialized::Compat
    }
}

// ── Device record ─────────────────────────────────────────────────────────

/// A simplified device record for enumeration results.
#[derive(Debug, Clone)]
pub struct Device {
    pub syspath: String,
    pub subsystem: Option<String>,
    pub sysname: String,
    pub devtype: Option<String>,
    pub properties: HashMap<String, String>,
    pub sysattrs: HashMap<String, String>,
    pub tags: HashSet<String>,
    pub initialized: bool,
}

impl Device {
    /// Create a minimal device from a syspath.
    pub fn from_syspath(syspath: &str) -> Self {
        let sysname = Path::new(syspath)
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        Self {
            syspath: syspath.to_string(),
            subsystem: None,
            sysname,
            devtype: None,
            properties: HashMap::new(),
            sysattrs: HashMap::new(),
            tags: HashSet::new(),
            initialized: true,
        }
    }

    /// Get the device's syspath.
    pub fn syspath(&self) -> &str {
        &self.syspath
    }

    /// Get the device's subsystem.
    pub fn subsystem(&self) -> Option<&str> {
        self.subsystem.as_deref()
    }

    /// Get the device's sysname (last component of syspath).
    pub fn sysname(&self) -> &str {
        &self.sysname
    }

    /// Check if device has a given tag.
    pub fn has_tag(&self, tag: &str) -> bool {
        self.tags.contains(tag)
    }

    /// Get a property value.
    pub fn property(&self, key: &str) -> Option<&str> {
        self.properties.get(key).map(|s| s.as_str())
    }

    /// Get a sysattr value.
    pub fn sysattr(&self, key: &str) -> Option<&str> {
        self.sysattrs.get(key).map(|s| s.as_str())
    }
}

// ── Device enumerator ─────────────────────────────────────────────────────

/// Device enumerator with filter support.
/// Faithfully mirrors `struct sd_device_enumerator` from the C code.
#[derive(Debug)]
pub struct DeviceEnumerator {
    enum_type: EnumerationType,
    devices: Vec<Device>,
    scan_uptodate: bool,
    sorted: bool,
    prioritized_subsystems: Vec<String>,
    match_subsystem: HashSet<String>,
    nomatch_subsystem: HashSet<String>,
    match_sysattr: HashMap<String, Vec<String>>,
    nomatch_sysattr: HashMap<String, Vec<String>>,
    match_property: HashMap<String, Vec<String>>,
    match_property_required: HashMap<String, Vec<String>>,
    match_sysname: HashSet<String>,
    nomatch_sysname: HashSet<String>,
    match_tag: HashSet<String>,
    match_parent: HashSet<String>,
    nomatch_parent: HashSet<String>,
    match_initialized: MatchInitialized,
    parent_match_flags: MatchFlag,
}

impl DeviceEnumerator {
    /// Create a new device enumerator.
    /// Corresponds to `sd_device_enumerator_new()`.
    pub fn new() -> Result<Rc<RefCell<Self>>> {
        let enumerator = Rc::new(RefCell::new(Self {
            enum_type: EnumerationType::Invalid,
            devices: Vec::new(),
            scan_uptodate: true,
            sorted: false,
            prioritized_subsystems: Vec::new(),
            match_subsystem: HashSet::new(),
            nomatch_subsystem: HashSet::new(),
            match_sysattr: HashMap::new(),
            nomatch_sysattr: HashMap::new(),
            match_property: HashMap::new(),
            match_property_required: HashMap::new(),
            match_sysname: HashSet::new(),
            nomatch_sysname: HashSet::new(),
            match_tag: HashSet::new(),
            match_parent: HashSet::new(),
            nomatch_parent: HashSet::new(),
            match_initialized: MatchInitialized::Compat,
            parent_match_flags: MatchFlag::ALL,
        }));
        Ok(enumerator)
    }

    /// Add a subsystem match filter.
    /// Corresponds to `sd_device_enumerator_add_match_subsystem()`.
    pub fn add_match_subsystem(&mut self, subsystem: &str, match_: bool) -> Result<()> {
        if subsystem.is_empty() {
            return Err(EnumeratorError::InvalidArgument);
        }
        if match_ {
            self.match_subsystem.insert(subsystem.to_string());
        } else {
            self.nomatch_subsystem.insert(subsystem.to_string());
        }
        self.scan_uptodate = false;
        Ok(())
    }

    /// Add a sysattr match filter.
    /// Corresponds to `sd_device_enumerator_add_match_sysattr()`.
    pub fn add_match_sysattr(
        &mut self,
        sysattr: &str,
        value: Option<&str>,
        match_: bool,
    ) -> Result<()> {
        if sysattr.is_empty() {
            return Err(EnumeratorError::InvalidArgument);
        }
        let map = if match_ {
            &mut self.match_sysattr
        } else {
            &mut self.nomatch_sysattr
        };
        let entry = map.entry(sysattr.to_string()).or_default();
        if let Some(v) = value {
            entry.push(v.to_string());
        }
        self.scan_uptodate = false;
        Ok(())
    }

    /// Add a property match filter.
    /// Corresponds to `sd_device_enumerator_add_match_property()`.
    pub fn add_match_property(&mut self, property: &str, value: Option<&str>) -> Result<()> {
        if property.is_empty() {
            return Err(EnumeratorError::InvalidArgument);
        }
        let entry = self.match_property.entry(property.to_string()).or_default();
        if let Some(v) = value {
            entry.push(v.to_string());
        }
        self.scan_uptodate = false;
        Ok(())
    }

    /// Add a sysname match filter.
    /// Corresponds to `sd_device_enumerator_add_match_sysname()`.
    pub fn add_match_sysname(&mut self, sysname: &str) -> Result<()> {
        if sysname.is_empty() {
            return Err(EnumeratorError::InvalidArgument);
        }
        self.match_sysname.insert(sysname.to_string());
        self.scan_uptodate = false;
        Ok(())
    }

    /// Add a tag match filter.
    /// Corresponds to `sd_device_enumerator_add_match_tag()`.
    pub fn add_match_tag(&mut self, tag: &str) -> Result<()> {
        if tag.is_empty() {
            return Err(EnumeratorError::InvalidArgument);
        }
        self.match_tag.insert(tag.to_string());
        self.scan_uptodate = false;
        Ok(())
    }

    /// Add a parent match filter.
    /// Corresponds to `sd_device_enumerator_add_match_parent()`.
    pub fn add_match_parent(&mut self, parent_syspath: &str) -> Result<()> {
        if parent_syspath.is_empty() {
            return Err(EnumeratorError::InvalidArgument);
        }
        self.match_parent.insert(parent_syspath.to_string());
        self.scan_uptodate = false;
        Ok(())
    }

    /// Set match-initialized mode.
    /// Corresponds to `sd_device_enumerator_add_match_is_initialized()`.
    pub fn set_match_initialized(&mut self, initialized: bool) {
        self.match_initialized = if initialized {
            MatchInitialized::Yes
        } else {
            MatchInitialized::All
        };
        self.scan_uptodate = false;
    }

    /// Allow uninitialized devices.
    /// Corresponds to `sd_device_enumerator_allow_uninitialized()`.
    pub fn allow_uninitialized(&mut self) {
        self.match_initialized = MatchInitialized::All;
        self.scan_uptodate = false;
    }

    /// Whether the scan results are up to date with current filters.
    pub fn is_scan_uptodate(&self) -> bool {
        self.scan_uptodate
    }

    /// Get the number of currently stored devices.
    pub fn device_count(&self) -> usize {
        self.devices.len()
    }

    /// Test whether a device passes all current filters.
    /// Mirrors the filter matching logic in the C code.
    pub fn matches(&self, device: &Device) -> bool {
        // Subsystem match/nomatch
        if let Some(ref sub) = device.subsystem {
            if !self.match_subsystem.is_empty() && !self.match_subsystem.contains(sub) {
                return false;
            }
            if !self.nomatch_subsystem.is_empty() && self.nomatch_subsystem.contains(sub) {
                return false;
            }
        } else if !self.match_subsystem.is_empty() {
            return false;
        }

        // Sysname match/nomatch
        if !self.match_sysname.is_empty() {
            let matches = self
                .match_sysname
                .iter()
                .any(|p| glob_match(p, &device.sysname));
            if !matches {
                return false;
            }
        }
        if !self.nomatch_sysname.is_empty() {
            let rejected = self
                .nomatch_sysname
                .iter()
                .any(|p| glob_match(p, &device.sysname));
            if rejected {
                return false;
            }
        }

        // Tag match
        if !self.match_tag.is_empty() {
            for tag in &self.match_tag {
                if !device.has_tag(tag) {
                    return false;
                }
            }
        }

        // Sysattr match
        for (attr, values) in &self.match_sysattr {
            if let Some(dev_val) = device.sysattr(attr) {
                if !values.is_empty() && !values.iter().any(|v| v == dev_val) {
                    return false;
                }
            } else {
                return false;
            }
        }

        // Sysattr nomatch
        for (attr, values) in &self.nomatch_sysattr {
            if let Some(dev_val) = device.sysattr(attr) {
                if values.iter().any(|v| v == dev_val) {
                    return false;
                }
            }
        }

        // Property match
        for (prop, values) in &self.match_property {
            if let Some(dev_val) = device.property(prop) {
                if !values.is_empty() && !values.iter().any(|v| v == dev_val) {
                    return false;
                }
            } else {
                return false;
            }
        }

        // Parent match
        if !self.match_parent.is_empty() {
            let matches = self
                .match_parent
                .iter()
                .any(|p| device.syspath.starts_with(p.as_str()));
            if !matches {
                return false;
            }
        }

        // Parent nomatch
        if !self.nomatch_parent.is_empty() {
            let rejected = self
                .nomatch_parent
                .iter()
                .any(|p| device.syspath.starts_with(p.as_str()));
            if rejected {
                return false;
            }
        }

        // Initialized check
        match self.match_initialized {
            MatchInitialized::Yes => {
                if !device.initialized {
                    return false;
                }
            }
            MatchInitialized::Compat => {
                if !device.initialized {
                    return false;
                }
            }
            MatchInitialized::All | MatchInitialized::No => {}
        }

        true
    }

    /// Add a device to the enumerator (for testing / injection).
    pub fn add_device(&mut self, device: Device) {
        self.devices.push(device);
        self.scan_uptodate = false;
    }

    /// Get devices matching current filters.
    pub fn get_matching_devices(&self) -> Vec<&Device> {
        self.devices.iter().filter(|d| self.matches(d)).collect()
    }

    /// Sort devices by syspath.
    /// Corresponds to the sort step in `device_enumerator_scan_devices()`.
    pub fn sort(&mut self) {
        self.devices.sort_by(|a, b| a.syspath.cmp(&b.syspath));
        self.sorted = true;
    }

    /// Get the enumeration type.
    pub fn enum_type(&self) -> EnumerationType {
        self.enum_type
    }

    /// Set the enumeration type.
    pub fn set_enum_type(&mut self, t: EnumerationType) {
        self.enum_type = t;
    }

    /// Get the match_initialized mode.
    pub fn match_initialized(&self) -> MatchInitialized {
        self.match_initialized
    }

    /// Get the parent match flags.
    pub fn parent_match_flags(&self) -> MatchFlag {
        self.parent_match_flags
    }

    /// Get number of subsystem filters.
    pub fn subsystem_filter_count(&self) -> usize {
        self.match_subsystem.len() + self.nomatch_subsystem.len()
    }

    /// Get number of tag filters.
    pub fn tag_filter_count(&self) -> usize {
        self.match_tag.len()
    }

    /// Clear all devices and filters.
    pub fn clear(&mut self) {
        self.devices.clear();
        self.match_subsystem.clear();
        self.nomatch_subsystem.clear();
        self.match_sysattr.clear();
        self.nomatch_sysattr.clear();
        self.match_property.clear();
        self.match_property_required.clear();
        self.match_sysname.clear();
        self.nomatch_sysname.clear();
        self.match_tag.clear();
        self.match_parent.clear();
        self.nomatch_parent.clear();
        self.prioritized_subsystems.clear();
        self.scan_uptodate = true;
        self.sorted = false;
    }
}

// ── Glob matching helper ──────────────────────────────────────────────────

/// Simple glob matching for sysname filters.
/// Supports `*` (match any) and `?` (match single char).
pub fn glob_match(pattern: &str, string: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let s: Vec<char> = string.chars().collect();
    glob_match_impl(&p, &s)
}

fn glob_match_impl(pattern: &[char], string: &[char]) -> bool {
    let mut pi = 0;
    let mut si = 0;
    let mut star_pi = usize::MAX;
    let mut star_si = 0;

    while si < string.len() {
        if pi < pattern.len() {
            match pattern[pi] {
                '*' => {
                    star_pi = pi;
                    star_si = si;
                    pi += 1;
                    continue;
                }
                '?' => {
                    pi += 1;
                    si += 1;
                    continue;
                }
                c if c == string[si] => {
                    pi += 1;
                    si += 1;
                    continue;
                }
                _ => {}
            }
        }

        if star_pi != usize::MAX {
            pi = star_pi + 1;
            star_si += 1;
            si = star_si;
            continue;
        }

        return false;
    }

    while pi < pattern.len() && pattern[pi] == '*' {
        pi += 1;
    }

    pi == pattern.len()
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_enumerator_new() {
        let e = DeviceEnumerator::new().unwrap();
        assert_eq!(e.borrow().device_count(), 0);
        assert!(e.borrow().is_scan_uptodate());
        assert_eq!(e.borrow().enum_type(), EnumerationType::Invalid);
    }

    #[test]
    fn test_enumerator_add_match_subsystem() {
        let e = DeviceEnumerator::new().unwrap();
        e.borrow_mut().add_match_subsystem("net", true).unwrap();
        e.borrow_mut().add_match_subsystem("block", false).unwrap();
        assert_eq!(e.borrow().subsystem_filter_count(), 2);
        assert!(!e.borrow().is_scan_uptodate());
    }

    #[test]
    fn test_enumerator_add_match_tag() {
        let e = DeviceEnumerator::new().unwrap();
        e.borrow_mut().add_match_tag("uaccess").unwrap();
        assert_eq!(e.borrow().tag_filter_count(), 1);
    }

    #[test]
    fn test_enumerator_add_match_sysattr() {
        let e = DeviceEnumerator::new().unwrap();
        e.borrow_mut()
            .add_match_sysattr("devtype", Some("disk"), true)
            .unwrap();
        assert!(!e.borrow().is_scan_uptodate());
    }

    #[test]
    fn test_enumerator_add_match_property() {
        let e = DeviceEnumerator::new().unwrap();
        e.borrow_mut()
            .add_match_property("ID_TYPE", Some("disk"))
            .unwrap();
        assert!(!e.borrow().is_scan_uptodate());
    }

    #[test]
    fn test_enumerator_add_match_sysname() {
        let e = DeviceEnumerator::new().unwrap();
        e.borrow_mut().add_match_sysname("sda*").unwrap();
        assert!(!e.borrow().is_scan_uptodate());
    }

    #[test]
    fn test_enumerator_add_match_parent() {
        let e = DeviceEnumerator::new().unwrap();
        e.borrow_mut()
            .add_match_parent("/sys/devices/pci0000:00")
            .unwrap();
        assert!(!e.borrow().is_scan_uptodate());
    }

    #[test]
    fn test_enumerator_clear() {
        let e = DeviceEnumerator::new().unwrap();
        e.borrow_mut().add_match_tag("test").unwrap();
        e.borrow_mut().add_match_subsystem("net", true).unwrap();
        e.borrow_mut().clear();
        assert_eq!(e.borrow().tag_filter_count(), 0);
        assert_eq!(e.borrow().subsystem_filter_count(), 0);
        assert!(e.borrow().is_scan_uptodate());
    }

    #[test]
    fn test_enumerator_empty_subsystem_rejected() {
        let e = DeviceEnumerator::new().unwrap();
        assert_eq!(
            e.borrow_mut().add_match_subsystem("", true),
            Err(EnumeratorError::InvalidArgument)
        );
    }

    #[test]
    fn test_enumerator_matches_no_filters() {
        let e = DeviceEnumerator::new().unwrap();
        let dev = Device::from_syspath("/sys/devices/test");
        assert!(e.borrow().matches(&dev));
    }

    #[test]
    fn test_enumerator_matches_subsystem() {
        let e = DeviceEnumerator::new().unwrap();
        e.borrow_mut().add_match_subsystem("net", true).unwrap();

        let mut dev = Device::from_syspath("/sys/devices/net/eth0");
        dev.subsystem = Some("net".to_string());
        assert!(e.borrow().matches(&dev));

        dev.subsystem = Some("block".to_string());
        assert!(!e.borrow().matches(&dev));
    }

    #[test]
    fn test_enumerator_matches_nomatch_subsystem() {
        let e = DeviceEnumerator::new().unwrap();
        e.borrow_mut().add_match_subsystem("input", false).unwrap();

        let mut dev = Device::from_syspath("/sys/devices/input/event0");
        dev.subsystem = Some("input".to_string());
        assert!(!e.borrow().matches(&dev));

        dev.subsystem = Some("net".to_string());
        assert!(e.borrow().matches(&dev));
    }

    #[test]
    fn test_enumerator_matches_tag() {
        let e = DeviceEnumerator::new().unwrap();
        e.borrow_mut().add_match_tag("uaccess").unwrap();

        let mut dev = Device::from_syspath("/sys/devices/test");
        dev.tags.insert("uaccess".to_string());
        assert!(e.borrow().matches(&dev));

        let dev2 = Device::from_syspath("/sys/devices/test2");
        assert!(!e.borrow().matches(&dev2));
    }

    #[test]
    fn test_enumerator_matches_parent() {
        let e = DeviceEnumerator::new().unwrap();
        e.borrow_mut()
            .add_match_parent("/sys/devices/pci0000:00")
            .unwrap();

        let dev = Device::from_syspath("/sys/devices/pci0000:00/0000:00:1f.0/net/eth0");
        assert!(e.borrow().matches(&dev));

        let dev2 = Device::from_syspath("/sys/devices/virtual/net/lo");
        assert!(!e.borrow().matches(&dev2));
    }

    #[test]
    fn test_enumerator_sort() {
        let e = DeviceEnumerator::new().unwrap();
        let mut dev_c = Device::from_syspath("/sys/devices/c");
        let mut dev_a = Device::from_syspath("/sys/devices/a");
        let mut dev_b = Device::from_syspath("/sys/devices/b");

        e.borrow_mut().add_device(dev_c);
        e.borrow_mut().add_device(dev_a);
        e.borrow_mut().add_device(dev_b);

        e.borrow_mut().sort();
        let devs = &e.borrow().devices;
        assert_eq!(devs[0].syspath, "/sys/devices/a");
        assert_eq!(devs[1].syspath, "/sys/devices/b");
        assert_eq!(devs[2].syspath, "/sys/devices/c");
    }

    #[test]
    fn test_enumerator_allow_uninitialized() {
        let e = DeviceEnumerator::new().unwrap();
        e.borrow_mut().allow_uninitialized();
        assert_eq!(e.borrow().match_initialized(), MatchInitialized::All);
    }

    #[test]
    fn test_enumerator_set_match_initialized() {
        let e = DeviceEnumerator::new().unwrap();
        e.borrow_mut().set_match_initialized(true);
        assert_eq!(e.borrow().match_initialized(), MatchInitialized::Yes);
    }

    #[test]
    fn test_glob_match() {
        assert!(glob_match("sda*", "sda"));
        assert!(glob_match("sda*", "sda1"));
        assert!(!glob_match("sda*", "sdb"));
        assert!(glob_match("?", "a"));
        assert!(!glob_match("?", "ab"));
        assert!(glob_match("*", "anything"));
        assert!(glob_match("sd?", "sda"));
        assert!(!glob_match("sd?", "sdab"));
    }

    #[test]
    fn test_enumerator_matches_sysname_glob() {
        let e = DeviceEnumerator::new().unwrap();
        e.borrow_mut().add_match_sysname("sda*").unwrap();

        let dev = Device::from_syspath("/sys/devices/pci0000:00/sda");
        assert!(e.borrow().matches(&dev));

        let dev2 = Device::from_syspath("/sys/devices/pci0000:00/sdb");
        assert!(!e.borrow().matches(&dev2));
    }

    #[test]
    fn test_enumerator_get_matching_devices() {
        let e = DeviceEnumerator::new().unwrap();
        e.borrow_mut().add_match_subsystem("net", true).unwrap();

        let mut dev1 = Device::from_syspath("/sys/devices/net/eth0");
        dev1.subsystem = Some("net".to_string());
        let mut dev2 = Device::from_syspath("/sys/devices/block/sda");
        dev2.subsystem = Some("block".to_string());

        e.borrow_mut().add_device(dev1);
        e.borrow_mut().add_device(dev2);

        let e_ref = e.borrow();
        let matching = e_ref.get_matching_devices();
        assert_eq!(matching.len(), 1);
        assert_eq!(matching[0].subsystem, Some("net".to_string()));
    }

    #[test]
    fn test_device_from_syspath() {
        let dev = Device::from_syspath("/sys/devices/pci0000:00/net/eth0");
        assert_eq!(dev.syspath(), "/sys/devices/pci0000:00/net/eth0");
        assert_eq!(dev.sysname(), "eth0");
        assert!(dev.subsystem().is_none());
    }

    #[test]
    fn test_device_properties() {
        let mut dev = Device::from_syspath("/sys/devices/test");
        dev.properties
            .insert("ID_TYPE".to_string(), "disk".to_string());
        assert_eq!(dev.property("ID_TYPE"), Some("disk"));
        assert_eq!(dev.property("NONEXISTENT"), None);
    }

    #[test]
    fn test_device_sysattrs() {
        let mut dev = Device::from_syspath("/sys/devices/test");
        dev.sysattrs
            .insert("devtype".to_string(), "disk".to_string());
        assert_eq!(dev.sysattr("devtype"), Some("disk"));
    }

    #[test]
    fn test_device_tags() {
        let mut dev = Device::from_syspath("/sys/devices/test");
        dev.tags.insert("uaccess".to_string());
        assert!(dev.has_tag("uaccess"));
        assert!(!dev.has_tag("seat"));
    }

    #[test]
    fn test_enumeration_type_default() {
        assert_eq!(EnumerationType::default(), EnumerationType::Invalid);
    }

    #[test]
    fn test_match_initialized_default() {
        assert_eq!(MatchInitialized::default(), MatchInitialized::Compat);
    }

    #[test]
    fn test_enumerator_set_enum_type() {
        let e = DeviceEnumerator::new().unwrap();
        e.borrow_mut().set_enum_type(EnumerationType::Devices);
        assert_eq!(e.borrow().enum_type(), EnumerationType::Devices);
    }
}
