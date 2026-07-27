// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/libsystemd/sd-device/device-enumerator.c
//
// Device enumeration — scanning and matching system devices from /sys and /run/udev.
//
// Provides a DeviceEnumerator that scans sysfs directories (/sys/class, /sys/bus,
// /sys/devices), applies match/nomatch filters (subsystem, sysname, tag, property,
// sysattr), and returns sorted results. Sound card control devices are ordered last
// within their card, and md/dm- block devices are sorted after all others.

// ── Imports ────────────────────────────────────────────────────────────────

use crate::ffi::*;
use std::collections::{HashMap, HashSet};
use std::ffi::OsString;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

// ── Enums ─────────────────────────────────────────────────────────────────

/// What kind of enumeration to perform.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceEnumerationType {
    /// Enumerate device nodes.
    Devices,
    /// Enumerate kernel subsystems.
    Subsystems,
    /// Enumerate both devices and subsystems.
    All,
}

/// Controls whether to include devices based on initialization state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchInitializedType {
    /// Only initialized devices (default).
    Yes,
    /// Only uninitialized devices.
    No,
    /// Accept any initialization state.
    All,
    /// Compatibility mode: accept devices without devnode/ifindex or with a db entry.
    Compat,
}

bitflags::bitflags! {
    /// Flags controlling which match criteria to evaluate.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct MatchFlag: u8 {
        const BASIC     = 1 << 0;
        const SYSNAME   = 1 << 1;
        const SUBSYSTEM = 1 << 2;
        const PARENT    = 1 << 3;
        const TAG       = 1 << 4;

        const ALL = (1 << 5) - 1;
    }
}

// ── Device information ─────────────────────────────────────────────────────

/// Information about a single device discovered via sysfs.
#[derive(Debug, Clone)]
pub struct DeviceInfo {
    /// Full sysfs path, e.g. `/sys/devices/pci0000:00/...`
    pub syspath: PathBuf,
    /// Subsystem string (block, net, usb, …).
    pub subsystem: Option<String>,
    /// Kernel device node path, e.g. `/dev/sda`.
    pub devname: Option<String>,
    /// Major:minor device number encoded as `(major << 8) | minor`.
    pub devnum: Option<u64>,
    /// Device properties read from the `uevent` file and elsewhere.
    pub properties: HashMap<String, String>,
    /// Tags associated with this device.
    pub tags: HashSet<String>,
}

impl DeviceInfo {
    /// Extract the sysname (last path component) from the syspath.
    pub fn sysname(&self) -> String {
        self.syspath
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_default()
    }

    /// Build a `DeviceInfo` by reading a sysfs directory.
    ///
    /// Reads the `uevent` and `dev` files under `syspath`.
    pub fn from_syspath(syspath: &Path) -> io::Result<Self> {
        let mut info = Self {
            syspath: syspath.to_path_buf(),
            subsystem: None,
            devname: None,
            devnum: None,
            properties: HashMap::new(),
            tags: HashSet::new(),
        };

        // Parse the uevent file for SUBSYSTEM, DEVNAME, MAJOR, MINOR.
        let uevent_path = syspath.join("uevent");
        if let Ok(content) = fs::read_to_string(&uevent_path) {
            for line in content.lines() {
                let Some((key, value)) = line.split_once('=') else {
                    continue;
                };
                match key {
                    "SUBSYSTEM" => info.subsystem = Some(value.to_string()),
                    "DEVNAME" => info.devname = Some(value.to_string()),
                    "MAJOR" => {
                        if let Ok(major) = value.parse::<u32>() {
                            info.devnum = Some((major as u64) << 8);
                        }
                    }
                    "MINOR" => {
                        if let Ok(minor) = value.parse::<u32>() {
                            let major = info.devnum.unwrap_or(0);
                            info.devnum = Some(major | (minor as u64));
                        }
                    }
                    _ => {
                        info.properties.insert(key.to_string(), value.to_string());
                    }
                }
            }
        }

        // The `dev` file is an authoritative major:minor source.
        let dev_path = syspath.join("dev");
        if let Ok(content) = fs::read_to_string(&dev_path) {
            let parts: Vec<&str> = content.trim().split(':').collect();
            if parts.len() == 2 {
                if let (Ok(major), Ok(minor)) = (parts[0].parse::<u32>(), parts[1].parse::<u32>()) {
                    info.devnum = Some(((major as u64) << 8) | (minor as u64));
                }
            }
        }

        Ok(info)
    }

    /// Convenience constructor for tests — builds a `DeviceInfo` directly.
    #[cfg(test)]
    fn new_test(
        syspath: impl Into<PathBuf>,
        subsystem: Option<&str>,
        devname: Option<&str>,
        devnum: Option<u64>,
    ) -> Self {
        Self {
            syspath: syspath.into(),
            subsystem: subsystem.map(String::from),
            devname: devname.map(String::from),
            devnum,
            properties: HashMap::new(),
            tags: HashSet::new(),
        }
    }
}

// ── Device Enumerator ─────────────────────────────────────────────────────

/// Enumerates system devices by scanning sysfs and applying match filters.
///
/// # Example
///
/// ```ignore
/// let mut en = DeviceEnumerator::new();
/// en.add_match_subsystem("block", true);
/// en.scan_devices()?;
/// for dev in en.iter_devices() {
///     println!("{} -> {:?}", dev.sysname(), dev.devname);
/// }
/// ```
pub struct DeviceEnumerator {
    /// Collected devices keyed by syspath.
    devices: HashMap<PathBuf, DeviceInfo>,
    /// Ordered view — rebuilt after each sort.
    sorted_devices: Vec<PathBuf>,
    sorted: bool,
    scan_uptodate: bool,
    enumeration_type: Option<DeviceEnumerationType>,

    // ── Filters ────────────────────────────────────────────────────────
    match_subsystem: HashSet<String>,
    nomatch_subsystem: HashSet<String>,
    match_sysname: HashSet<String>,
    nomatch_sysname: HashSet<String>,
    match_tag: HashSet<String>,
    match_sysattr: HashMap<String, Option<String>>,
    nomatch_sysattr: HashMap<String, Option<String>>,
    match_property: HashMap<String, String>,
    match_property_required: HashMap<String, String>,
    match_parent: HashSet<PathBuf>,
    prioritized_subsystems: Vec<String>,

    match_initialized: MatchInitializedType,
    parent_match_flags: MatchFlag,
}

impl DeviceEnumerator {
    /// Create a new device enumerator with default settings.
    pub fn new() -> Self {
        Self {
            devices: HashMap::new(),
            sorted_devices: Vec::new(),
            sorted: false,
            scan_uptodate: false,
            enumeration_type: None,

            match_subsystem: HashSet::new(),
            nomatch_subsystem: HashSet::new(),
            match_sysname: HashSet::new(),
            nomatch_sysname: HashSet::new(),
            match_tag: HashSet::new(),
            match_sysattr: HashMap::new(),
            nomatch_sysattr: HashMap::new(),
            match_property: HashMap::new(),
            match_property_required: HashMap::new(),
            match_parent: HashSet::new(),
            prioritized_subsystems: Vec::new(),

            match_initialized: MatchInitializedType::Compat,
            parent_match_flags: MatchFlag::ALL,
        }
    }

    // ── Filter builders ────────────────────────────────────────────────

    /// Add a subsystem match (or nomatch when `match_` is `false`).
    pub fn add_match_subsystem(&mut self, subsystem: &str, match_: bool) {
        if match_ {
            self.match_subsystem.insert(subsystem.to_string());
        } else {
            self.nomatch_subsystem.insert(subsystem.to_string());
        }
        self.scan_uptodate = false;
    }

    /// Add a sysname match (or nomatch when `match_` is `false`).
    pub fn add_match_sysname(&mut self, sysname: &str, match_: bool) {
        if match_ {
            self.match_sysname.insert(sysname.to_string());
        } else {
            self.nomatch_sysname.insert(sysname.to_string());
        }
        self.scan_uptodate = false;
    }

    /// Shorthand: add a sysname positive match.
    pub fn add_nomatch_sysname(&mut self, sysname: &str) {
        self.add_match_sysname(sysname, false);
    }

    /// Add a tag match.
    pub fn add_match_tag(&mut self, tag: &str) {
        self.match_tag.insert(tag.to_string());
        self.scan_uptodate = false;
    }

    /// Add a property match.  At least one property must match for a device to
    /// be included (OR semantics).
    pub fn add_match_property(&mut self, property: &str, value: &str) {
        self.match_property
            .insert(property.to_string(), value.to_string());
        self.scan_uptodate = false;
    }

    /// Add a required property match.  All required properties must match
    /// (AND semantics).
    pub fn add_match_property_required(&mut self, property: &str, value: &str) {
        self.match_property_required
            .insert(property.to_string(), value.to_string());
        self.scan_uptodate = false;
    }

    /// Add a sysattr match (or nomatch).
    pub fn add_match_sysattr(&mut self, sysattr: &str, value: Option<&str>, match_: bool) {
        let map = if match_ {
            &mut self.match_sysattr
        } else {
            &mut self.nomatch_sysattr
        };
        map.insert(sysattr.to_string(), value.map(String::from));
        self.scan_uptodate = false;
    }

    /// Add a parent device match (replaces any existing parent filters).
    pub fn add_match_parent(&mut self, parent_syspath: &Path) {
        self.match_parent.clear();
        self.match_parent.insert(parent_syspath.to_path_buf());
        self.scan_uptodate = false;
    }

    /// Allow uninitialized devices to be included.
    pub fn allow_uninitialized(&mut self) {
        self.match_initialized = MatchInitializedType::All;
        self.scan_uptodate = false;
    }

    /// Include all parent devices when matching by parent.
    pub fn add_all_parents(&mut self) {
        self.parent_match_flags = MatchFlag::empty();
        self.scan_uptodate = false;
    }

    /// Add a prioritized subsystem (sorted first).
    pub fn add_prioritized_subsystem(&mut self, subsystem: &str) {
        if !self.prioritized_subsystems.contains(&subsystem.to_string()) {
            self.prioritized_subsystems.push(subsystem.to_string());
        }
        self.scan_uptodate = false;
    }

    /// Set the match-initialized filter.
    pub fn set_match_initialized(&mut self, ty: MatchInitializedType) {
        self.match_initialized = ty;
        self.scan_uptodate = false;
    }

    // ── Scanning ───────────────────────────────────────────────────────

    /// Scan sysfs for devices and populate the internal device list.
    pub fn scan_devices(&mut self) -> io::Result<()> {
        if self.scan_uptodate && self.enumeration_type == Some(DeviceEnumerationType::Devices) {
            return Ok(());
        }

        self.devices.clear();
        self.sorted = false;
        self.scan_uptodate = false;

        if !self.match_tag.is_empty() {
            self.scan_devices_tags()?;
        } else if !self.match_parent.is_empty() {
            self.scan_devices_children()?;
        } else {
            self.scan_dir("bus", Some("devices"), None)?;
            self.scan_dir("class", None, None)?;
        }

        self.scan_uptodate = true;
        self.enumeration_type = Some(DeviceEnumerationType::Devices);
        Ok(())
    }

    /// Scan for subsystems (modules, buses, drivers).
    pub fn scan_subsystems(&mut self) -> io::Result<()> {
        if self.scan_uptodate && self.enumeration_type == Some(DeviceEnumerationType::Subsystems) {
            return Ok(());
        }

        self.devices.clear();
        self.sorted = false;

        if self.subsystem_matches("module") {
            self.scan_dir_and_add_devices("module", None, None)?;
        }
        if self.subsystem_matches("subsystem") {
            self.scan_dir_and_add_devices("bus", None, None)?;
        }
        if self.subsystem_matches("drivers") {
            self.scan_dir("bus", Some("drivers"), Some("drivers"))?;
        }

        self.scan_uptodate = true;
        self.enumeration_type = Some(DeviceEnumerationType::Subsystems);
        Ok(())
    }

    /// Scan both devices and subsystems.
    pub fn scan_devices_and_subsystems(&mut self) -> io::Result<()> {
        if self.scan_uptodate && self.enumeration_type == Some(DeviceEnumerationType::All) {
            return Ok(());
        }

        self.devices.clear();
        self.sorted = false;

        if !self.match_tag.is_empty() {
            self.scan_devices_tags()?;
        } else if !self.match_parent.is_empty() {
            self.scan_devices_children()?;
        } else {
            self.scan_dir("bus", Some("devices"), None)?;
            self.scan_dir("class", None, None)?;
            if self.subsystem_matches("module") {
                self.scan_dir_and_add_devices("module", None, None)?;
            }
            if self.subsystem_matches("subsystem") {
                self.scan_dir_and_add_devices("bus", None, None)?;
            }
            if self.subsystem_matches("drivers") {
                self.scan_dir("bus", Some("drivers"), Some("drivers"))?;
            }
        }

        self.scan_uptodate = true;
        self.enumeration_type = Some(DeviceEnumerationType::All);
        Ok(())
    }

    // ── Accessors ──────────────────────────────────────────────────────

    /// Return an iterator over the sorted device list.
    pub fn iter_devices(&mut self) -> impl Iterator<Item = &DeviceInfo> {
        self.ensure_sorted();
        self.sorted_devices
            .iter()
            .filter_map(|p| self.devices.get(p))
    }

    /// Return the number of enumerated devices.
    pub fn device_count(&self) -> usize {
        self.devices.len()
    }

    /// Get a specific device by syspath.
    pub fn get_device(&self, syspath: &Path) -> Option<&DeviceInfo> {
        self.devices.get(syspath)
    }

    /// Check whether a device is already in the set.
    pub fn contains(&self, syspath: &Path) -> bool {
        self.devices.contains_key(syspath)
    }

    /// Clear all collected devices (keeps filters).
    pub fn clear_devices(&mut self) {
        self.devices.clear();
        self.sorted_devices.clear();
        self.sorted = false;
        self.scan_uptodate = false;
    }

    /// Clear everything: devices and all filters.
    pub fn clear(&mut self) {
        self.devices.clear();
        self.sorted_devices.clear();
        self.sorted = false;
        self.scan_uptodate = false;
        self.enumeration_type = None;

        self.match_subsystem.clear();
        self.nomatch_subsystem.clear();
        self.match_sysname.clear();
        self.nomatch_sysname.clear();
        self.match_tag.clear();
        self.match_sysattr.clear();
        self.nomatch_sysattr.clear();
        self.match_property.clear();
        self.match_property_required.clear();
        self.match_parent.clear();
        self.prioritized_subsystems.clear();
        self.match_initialized = MatchInitializedType::Compat;
        self.parent_match_flags = MatchFlag::ALL;
    }

    /// Return the list of prioritized subsystems.
    pub fn prioritized_subsystems(&self) -> &[String] {
        &self.prioritized_subsystems
    }

    // ── Internal: scanning helpers ─────────────────────────────────────

    fn scan_dir_and_add_devices(
        &mut self,
        basedir: &str,
        subdir1: Option<&str>,
        subdir2: Option<&str>,
    ) -> io::Result<()> {
        let mut path = PathBuf::from("/sys").join(basedir);
        if let Some(s) = subdir1 {
            path.push(s);
        }
        if let Some(s) = subdir2 {
            path.push(s);
        }

        let entries = match fs::read_dir(&path) {
            Ok(e) => e,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e),
        };

        for entry in entries {
            let entry = entry?;
            let name = entry.file_name();
            let name_str = name.to_string_lossy();

            // Skip dotfiles and non-directory/non-symlink entries.
            if name_str.starts_with('.') {
                continue;
            }

            // Check sysname filter early (cheap string check).
            if !self.sysname_matches(&name_str) {
                continue;
            }

            let child_path = path.join(&name);

            // Follow symlinks to real device path.
            let real_path = match fs::canonicalize(&child_path) {
                Ok(p) => p,
                Err(_) => continue,
            };

            if let Ok(info) = DeviceInfo::from_syspath(&real_path) {
                if self.test_matches(&info, MatchFlag::ALL & !MatchFlag::SYSNAME) {
                    self.devices.insert(real_path, info);
                    self.sorted = false;
                }
            }
        }

        Ok(())
    }

    fn scan_dir(
        &mut self,
        basedir: &str,
        subdir: Option<&str>,
        subsystem: Option<&str>,
    ) -> io::Result<()> {
        let path = PathBuf::from("/sys").join(basedir);

        let entries = match fs::read_dir(&path) {
            Ok(e) => e,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e),
        };

        for entry in entries {
            let entry = entry?;
            let name = entry.file_name();
            let name_str = name.to_string_lossy();

            if name_str.starts_with('.') {
                continue;
            }

            // Check subsystem filter.
            let sub = subsystem.unwrap_or(&name_str);
            if !self.subsystem_matches(sub) {
                continue;
            }

            self.scan_dir_and_add_devices(basedir, Some(&name_str), subdir)?;
        }

        Ok(())
    }

    fn scan_devices_tags(&mut self) -> io::Result<()> {
        for tag in &self.match_tag {
            let tag_dir = PathBuf::from("/run/udev/tags").join(tag);
            let entries = match fs::read_dir(&tag_dir) {
                Ok(e) => e,
                Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
                Err(e) => return Err(e),
            };

            for entry in entries {
                let entry = entry?;
                let name = entry.file_name();
                let name_str = name.to_string_lossy();

                if name_str.starts_with('.') {
                    continue;
                }

                // Try to resolve device from tag symlink name.
                if let Ok(real) = entry.path().canonicalize() {
                    if let Ok(info) = DeviceInfo::from_syspath(&real) {
                        if self.test_matches(&info, MatchFlag::ALL & !MatchFlag::TAG) {
                            self.devices.insert(real, info);
                            self.sorted = false;
                        }
                    }
                }
            }
        }
        Ok(())
    }

    fn scan_devices_children(&mut self) -> io::Result<()> {
        let mut stack: Vec<PathBuf> = Vec::new();

        let parents: Vec<PathBuf> = self.match_parent.iter().cloned().collect();
        for parent in &parents {
            self.parent_add_child(parent, MatchFlag::ALL & !MatchFlag::PARENT);
            self.parent_crawl_children(parent, &mut stack)?;
        }

        while let Some(p) = stack.pop() {
            self.parent_crawl_children(&p, &mut stack)?;
        }

        Ok(())
    }

    fn parent_add_child(&mut self, path: &Path, flags: MatchFlag) {
        if let Ok(info) = DeviceInfo::from_syspath(path) {
            if self.test_matches(&info, flags) {
                self.devices.insert(path.to_path_buf(), info);
                self.sorted = false;
            }
        }
    }

    fn parent_crawl_children(&mut self, path: &Path, stack: &mut Vec<PathBuf>) -> io::Result<()> {
        let entries = match fs::read_dir(path) {
            Ok(e) => e,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e),
        };

        for entry in entries {
            let entry = entry?;
            let name = entry.file_name();
            let name_str = name.to_string_lossy();

            if name_str.starts_with('.') {
                continue;
            }

            if !entry.file_type()?.is_dir() {
                continue;
            }

            let child = path.join(&name);

            if self.sysname_matches(&name_str) {
                self.parent_add_child(
                    &child,
                    MatchFlag::ALL & !(MatchFlag::SYSNAME | MatchFlag::PARENT),
                );
            }

            stack.push(child);
        }

        Ok(())
    }

    // ── Internal: match logic ──────────────────────────────────────────

    /// Test whether a device passes all configured filters.
    fn test_matches(&self, info: &DeviceInfo, flags: MatchFlag) -> bool {
        if flags.contains(MatchFlag::SYSNAME) {
            let sysname = info.sysname();
            if !self.sysname_matches(&sysname) {
                return false;
            }
        }

        if flags.contains(MatchFlag::SUBSYSTEM) {
            let sub = match &info.subsystem {
                Some(s) => s.as_str(),
                None => return false,
            };
            if !self.subsystem_matches(sub) {
                return false;
            }
        }

        if flags.contains(MatchFlag::TAG) && !self.tags_match(info) {
            return false;
        }

        if flags.contains(MatchFlag::PARENT) && !self.parent_matches(info) {
            return false;
        }

        if flags.contains(MatchFlag::BASIC) {
            if !self.properties_match(info, false) {
                return false;
            }
            if !self.properties_match_required(info) {
                return false;
            }
            if !self.sysattrs_match(info) {
                return false;
            }
        }

        true
    }

    /// Full match check (all flags).
    fn matches(&self, info: &DeviceInfo) -> bool {
        self.test_matches(info, MatchFlag::ALL)
    }

    fn sysname_matches(&self, sysname: &str) -> bool {
        // If there are positive matches, at least one must match.
        if !self.match_sysname.is_empty()
            && !self
                .match_sysname
                .iter()
                .any(|s| glob_match_simple(s, sysname))
        {
            return false;
        }
        // None of the nomatch set may match.
        if self
            .nomatch_sysname
            .iter()
            .any(|s| glob_match_simple(s, sysname))
        {
            return false;
        }
        true
    }

    fn subsystem_matches(&self, subsystem: &str) -> bool {
        if !self.match_subsystem.is_empty()
            && !self
                .match_subsystem
                .iter()
                .any(|s| glob_match_simple(s, subsystem))
        {
            return false;
        }
        if self
            .nomatch_subsystem
            .iter()
            .any(|s| glob_match_simple(s, subsystem))
        {
            return false;
        }
        true
    }

    fn tags_match(&self, info: &DeviceInfo) -> bool {
        self.match_tag.iter().all(|t| info.tags.contains(t))
    }

    fn parent_matches(&self, info: &DeviceInfo) -> bool {
        if self.match_parent.is_empty() {
            return true;
        }
        // Check if the device's syspath starts with any parent path.
        self.match_parent
            .iter()
            .any(|parent| info.syspath.starts_with(parent))
    }

    fn properties_match(&self, info: &DeviceInfo, match_all: bool) -> bool {
        let props = if match_all {
            &self.match_property_required
        } else {
            &self.match_property
        };

        if props.is_empty() {
            return true;
        }

        if match_all {
            // AND: all required properties must be present with matching values.
            props.iter().all(|(k, v)| {
                info.properties
                    .get(k)
                    .is_some_and(|pv| glob_match_simple(v, pv))
            })
        } else {
            // OR: at least one property must match.
            props.iter().any(|(k, v)| {
                info.properties
                    .get(k)
                    .is_some_and(|pv| glob_match_simple(v, pv))
            })
        }
    }

    fn properties_match_required(&self, info: &DeviceInfo) -> bool {
        self.match_property_required.iter().all(|(k, v)| {
            info.properties
                .get(k)
                .is_some_and(|pv| glob_match_simple(v, pv))
        })
    }

    fn sysattrs_match(&self, _info: &DeviceInfo) -> bool {
        // Sysattr matching would require reading files under the device's syspath.
        // Stub: return true when no sysattr filters are set.
        self.match_sysattr.is_empty() && self.nomatch_sysattr.is_empty()
    }

    // ── Internal: sorting ──────────────────────────────────────────────

    fn ensure_sorted(&mut self) {
        if self.sorted {
            return;
        }

        let mut paths: Vec<PathBuf> = self.devices.keys().cloned().collect();

        // Sort prioritized subsystems first.
        let mut prioritized = Vec::new();
        let mut rest = Vec::new();

        for path in &paths {
            if let Some(info) = self.devices.get(path) {
                if let Some(sub) = &info.subsystem {
                    if self.prioritized_subsystems.contains(sub) {
                        prioritized.push(path.clone());
                        continue;
                    }
                }
            }
            rest.push(path.clone());
        }

        // Apply device_compare ordering within each group.
        prioritized.sort_by(|a, b| self.device_compare(a, b));
        rest.sort_by(|a, b| self.device_compare(a, b));

        self.sorted_devices = prioritized;
        self.sorted_devices.extend(rest);
        self.sorted = true;
    }

    /// Comparison key for sorting devices.
    ///
    /// Mirrors the C implementation:
    /// 1. Sound card control devices go last within their card.
    /// 2. md/dm- block devices go after everything else.
    /// 3. Lexicographic path comparison as tiebreaker.
    fn device_compare(&self, a: &Path, b: &Path) -> std::cmp::Ordering {
        let a_str = a.to_string_lossy();
        let b_str = b.to_string_lossy();

        // 1. Sound device ordering.
        let ord = self.sound_device_compare(&a_str, &b_str);
        if ord != std::cmp::Ordering::Equal {
            return ord;
        }

        // 2. Late block ordering (md, dm- after others).
        let a_late = devpath_is_late_block(&a_str);
        let b_late = devpath_is_late_block(&b_str);
        match (a_late, b_late) {
            (true, false) => return std::cmp::Ordering::Greater,
            (false, true) => return std::cmp::Ordering::Less,
            _ => {}
        }

        // 3. Path comparison.
        a_str.cmp(&b_str)
    }

    fn sound_device_compare(&self, a: &str, b: &str) -> std::cmp::Ordering {
        // Check if path contains /sound/card
        let Some(idx_a) = a.find("/sound/card") else {
            return std::cmp::Ordering::Equal;
        };
        let Some(idx_b) = b.find("/sound/card") else {
            return std::cmp::Ordering::Equal;
        };

        // Find the slash after "/sound/card..."
        let rest_a = &a[idx_a + "/sound/card".len()..];
        let rest_b = &b[idx_b + "/sound/card".len()..];

        let slash_a = rest_a.find('/');
        let slash_b = rest_b.find('/');

        match (slash_a, slash_b) {
            (Some(sa), Some(sb)) => {
                let prefix_len_a = idx_a + "/sound/card".len() + sa + 1;
                let prefix_len_b = idx_b + "/sound/card".len() + sb + 1;

                if prefix_len_a > a.len() || prefix_len_b > b.len() {
                    return std::cmp::Ordering::Equal;
                }

                // Check if the prefix before the card-specific part matches.
                let max_prefix = prefix_len_a.min(prefix_len_b);
                if a[..max_prefix] != b[..max_prefix] {
                    return std::cmp::Ordering::Equal;
                }

                let a_is_control = a
                    .get(prefix_len_a..)
                    .is_some_and(|r| r.starts_with("controlC"));
                let b_is_control = b
                    .get(prefix_len_b..)
                    .is_some_and(|r| r.starts_with("controlC"));

                a_is_control.cmp(&b_is_control)
            }
            _ => std::cmp::Ordering::Equal,
        }
    }
}

impl Default for DeviceEnumerator {
    fn default() -> Self {
        Self::new()
    }
}

// ── Free functions ─────────────────────────────────────────────────────────

/// Check if a device path refers to a "late" block device (md, dm-).
/// These are sorted after all other devices.
pub fn devpath_is_late_block(devpath: &str) -> bool {
    devpath.contains("/block/md") || devpath.contains("/block/dm-")
}

/// Simple glob match supporting `*` and `?` wildcards.
/// For full fnmatch semantics, use the compare_operator module.
fn glob_match_simple(pattern: &str, s: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = s.chars().collect();
    glob_match_impl(&p, &t)
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

    // Consume trailing stars.
    while pi < pattern.len() && pattern[pi] == '*' {
        pi += 1;
    }

    pi == pattern.len()
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Constructor / Default ──────────────────────────────────────────

    #[test]
    fn test_enumerator_new() {
        let en = DeviceEnumerator::new();
        assert!(en.devices.is_empty());
        assert!(en.match_subsystem.is_empty());
        assert!(en.match_sysname.is_empty());
        assert!(en.match_tag.is_empty());
        assert!(en.match_property.is_empty());
        assert_eq!(en.match_initialized, MatchInitializedType::Compat);
    }

    #[test]
    fn test_enumerator_default() {
        let en = DeviceEnumerator::default();
        assert!(en.devices.is_empty());
    }

    // ── Filter builders ────────────────────────────────────────────────

    #[test]
    fn test_add_match_subsystem() {
        let mut en = DeviceEnumerator::new();
        en.add_match_subsystem("block", true);
        assert!(en.match_subsystem.contains("block"));
        assert!(en.nomatch_subsystem.is_empty());

        en.add_match_subsystem("net", false);
        assert!(en.nomatch_subsystem.contains("net"));
    }

    #[test]
    fn test_add_match_sysname() {
        let mut en = DeviceEnumerator::new();
        en.add_match_sysname("sda", true);
        assert!(en.match_sysname.contains("sda"));

        en.add_nomatch_sysname("loop*");
        assert!(en.nomatch_sysname.contains("loop*"));
    }

    #[test]
    fn test_add_match_tag() {
        let mut en = DeviceEnumerator::new();
        en.add_match_tag("systemd");
        en.add_match_tag("seat");
        assert!(en.match_tag.contains("systemd"));
        assert!(en.match_tag.contains("seat"));
    }

    #[test]
    fn test_add_match_property() {
        let mut en = DeviceEnumerator::new();
        en.add_match_property("ID_TYPE", "disk");
        assert_eq!(en.match_property.get("ID_TYPE"), Some(&"disk".to_string()));
    }

    #[test]
    fn test_add_match_property_required() {
        let mut en = DeviceEnumerator::new();
        en.add_match_property_required("ID_BUS", "usb");
        assert_eq!(
            en.match_property_required.get("ID_BUS"),
            Some(&"usb".to_string())
        );
    }

    #[test]
    fn test_add_match_sysattr() {
        let mut en = DeviceEnumerator::new();
        en.add_match_sysattr("ro", Some("0"), true);
        assert_eq!(en.match_sysattr.get("ro"), Some(&Some("0".to_string())));

        en.add_match_sysattr("removable", None, false);
        assert!(en.nomatch_sysattr.contains_key("removable"));
    }

    #[test]
    fn test_add_match_parent() {
        let mut en = DeviceEnumerator::new();
        en.add_match_parent(Path::new("/sys/devices/pci0000:00"));
        assert!(en
            .match_parent
            .contains(Path::new("/sys/devices/pci0000:00")));

        // Adding another parent replaces the previous one.
        en.add_match_parent(Path::new("/sys/devices/platform"));
        assert!(!en
            .match_parent
            .contains(Path::new("/sys/devices/pci0000:00")));
        assert!(en.match_parent.contains(Path::new("/sys/devices/platform")));
    }

    #[test]
    fn test_allow_uninitialized() {
        let mut en = DeviceEnumerator::new();
        assert_eq!(en.match_initialized, MatchInitializedType::Compat);
        en.allow_uninitialized();
        assert_eq!(en.match_initialized, MatchInitializedType::All);
    }

    #[test]
    fn test_add_prioritized_subsystem() {
        let mut en = DeviceEnumerator::new();
        en.add_prioritized_subsystem("net");
        en.add_prioritized_subsystem("block");
        en.add_prioritized_subsystem("net"); // duplicate, no-op
        assert_eq!(en.prioritized_subsystems(), &["net", "block"]);
    }

    // ── Clear / reset ──────────────────────────────────────────────────

    #[test]
    fn test_clear() {
        let mut en = DeviceEnumerator::new();
        en.add_match_subsystem("block", true);
        en.add_match_tag("systemd");
        en.clear();
        assert!(en.match_subsystem.is_empty());
        assert!(en.match_tag.is_empty());
        assert_eq!(en.match_initialized, MatchInitializedType::Compat);
    }

    // ── DeviceInfo ─────────────────────────────────────────────────────

    #[test]
    fn test_device_info_sysname() {
        let info = DeviceInfo::new_test("/sys/devices/virtual/block/loop0", None, None, None);
        assert_eq!(info.sysname(), "loop0");

        let info = DeviceInfo::new_test("/sys/class/net/eth0", None, None, None);
        assert_eq!(info.sysname(), "eth0");
    }

    #[test]
    fn test_device_info_from_syspath_nonexistent() {
        // Nonexistent path: should succeed with empty info (no uevent file).
        let result = DeviceInfo::from_syspath(Path::new("/nonexistent/path"));
        assert!(result.is_ok());
        let info = result.unwrap();
        assert!(info.subsystem.is_none());
        assert!(info.devname.is_none());
    }

    // ── Match logic ────────────────────────────────────────────────────

    #[test]
    fn test_matches_empty_filters() {
        let en = DeviceEnumerator::new();
        let info = DeviceInfo::new_test(
            "/sys/devices/pci0000:00/block/sda",
            Some("block"),
            Some("/dev/sda"),
            Some((8 << 8) | 0),
        );
        assert!(en.matches(&info));
    }

    #[test]
    fn test_matches_subsystem() {
        let mut en = DeviceEnumerator::new();
        en.add_match_subsystem("block", true);
        let block_dev = DeviceInfo::new_test("/sys/block/sda", Some("block"), None, None);
        assert!(en.matches(&block_dev));

        let net_dev = DeviceInfo::new_test("/sys/class/net/eth0", Some("net"), None, None);
        assert!(!en.matches(&net_dev));
    }

    #[test]
    fn test_matches_nomatch_subsystem() {
        let mut en = DeviceEnumerator::new();
        en.add_match_subsystem("net", false);
        let net_dev = DeviceInfo::new_test("/sys/class/net/eth0", Some("net"), None, None);
        assert!(!en.matches(&net_dev));

        let block_dev = DeviceInfo::new_test("/sys/block/sda", Some("block"), None, None);
        assert!(en.matches(&block_dev));
    }

    #[test]
    fn test_matches_sysname() {
        let mut en = DeviceEnumerator::new();
        en.add_match_sysname("sda", true);
        let info = DeviceInfo::new_test("/sys/block/sda", Some("block"), None, None);
        assert!(en.matches(&info));

        let info2 = DeviceInfo::new_test("/sys/block/sdb", Some("block"), None, None);
        assert!(!en.matches(&info2));
    }

    #[test]
    fn test_matches_sysname_glob() {
        let mut en = DeviceEnumerator::new();
        en.add_match_sysname("sd?", true);
        let info = DeviceInfo::new_test("/sys/block/sda", Some("block"), None, None);
        assert!(en.matches(&info));

        let info2 = DeviceInfo::new_test("/sys/block/nvme0n1", Some("block"), None, None);
        assert!(!en.matches(&info2));
    }

    #[test]
    fn test_matches_nomatch_sysname_glob() {
        let mut en = DeviceEnumerator::new();
        en.add_nomatch_sysname("loop*");
        let loop_dev = DeviceInfo::new_test("/sys/block/loop0", Some("block"), None, None);
        assert!(!en.matches(&loop_dev));

        let sda = DeviceInfo::new_test("/sys/block/sda", Some("block"), None, None);
        assert!(en.matches(&sda));
    }

    #[test]
    fn test_matches_tag() {
        let mut en = DeviceEnumerator::new();
        en.add_match_tag("systemd");
        en.add_match_tag("seat");

        let mut info = DeviceInfo::new_test("/sys/class/net/eth0", Some("net"), None, None);
        info.tags.insert("systemd".to_string());
        info.tags.insert("seat".to_string());
        assert!(en.matches(&info));

        // Missing one tag → no match.
        let mut info2 = DeviceInfo::new_test("/sys/class/net/eth1", Some("net"), None, None);
        info2.tags.insert("systemd".to_string());
        assert!(!en.matches(&info2));
    }

    #[test]
    fn test_matches_property() {
        let mut en = DeviceEnumerator::new();
        en.add_match_property("ID_TYPE", "disk");

        let mut info = DeviceInfo::new_test("/sys/block/sda", Some("block"), None, None);
        info.properties
            .insert("ID_TYPE".to_string(), "disk".to_string());
        assert!(en.matches(&info));

        let mut info2 = DeviceInfo::new_test("/sys/block/sdb", Some("block"), None, None);
        info2
            .properties
            .insert("ID_TYPE".to_string(), "partition".to_string());
        assert!(!en.matches(&info2));
    }

    #[test]
    fn test_matches_property_required() {
        let mut en = DeviceEnumerator::new();
        en.add_match_property_required("ID_BUS", "usb");
        en.add_match_property_required("ID_MODEL", "Flash*");

        // Both required properties present.
        let mut info = DeviceInfo::new_test("/sys/block/sda", Some("block"), None, None);
        info.properties
            .insert("ID_BUS".to_string(), "usb".to_string());
        info.properties
            .insert("ID_MODEL".to_string(), "Flash".to_string());
        assert!(en.matches(&info));

        // Missing one required property.
        let mut info2 = DeviceInfo::new_test("/sys/block/sdb", Some("block"), None, None);
        info2
            .properties
            .insert("ID_BUS".to_string(), "usb".to_string());
        assert!(!en.matches(&info2));
    }

    #[test]
    fn test_matches_parent() {
        let mut en = DeviceEnumerator::new();
        en.add_match_parent(Path::new("/sys/devices/pci0000:00"));

        let child = DeviceInfo::new_test(
            "/sys/devices/pci0000:00/0000:00:1f.2/ata1/host0/target0:0:0/0:0:0:0/block/sda",
            Some("block"),
            None,
            None,
        );
        assert!(en.matches(&child));

        let unrelated = DeviceInfo::new_test(
            "/sys/devices/platform/serial8250/tty/ttyS0",
            None,
            None,
            None,
        );
        assert!(!en.matches(&unrelated));
    }

    // ── devpath_is_late_block ──────────────────────────────────────────

    #[test]
    fn test_devpath_is_late_block() {
        assert!(devpath_is_late_block("/sys/devices/virtual/block/md0"));
        assert!(devpath_is_late_block("/sys/devices/virtual/block/dm-0"));
        assert!(!devpath_is_late_block("/sys/devices/pci0000:00/block/sda"));
        assert!(!devpath_is_late_block("/sys/class/net/eth0"));
    }

    // ── Glob matching ──────────────────────────────────────────────────

    #[test]
    fn test_glob_match_simple() {
        assert!(glob_match_simple("sda", "sda"));
        assert!(!glob_match_simple("sda", "sdb"));
        assert!(glob_match_simple("sd?", "sda"));
        assert!(!glob_match_simple("sd?", "sdaa"));
        assert!(glob_match_simple("loop*", "loop0"));
        assert!(glob_match_simple("loop*", "loop99"));
        assert!(!glob_match_simple("loop*", "nvme0n1"));
        assert!(glob_match_simple("*", "anything"));
        assert!(glob_match_simple("", ""));
        assert!(!glob_match_simple("", "not-empty"));
    }

    // ── Sorting ────────────────────────────────────────────────────────

    #[test]
    fn test_sort_order_late_block() {
        let mut en = DeviceEnumerator::new();

        en.devices.insert(
            PathBuf::from("/sys/devices/block/sda"),
            DeviceInfo::new_test("/sys/devices/block/sda", Some("block"), None, None),
        );
        en.devices.insert(
            PathBuf::from("/sys/devices/block/md0"),
            DeviceInfo::new_test("/sys/devices/block/md0", Some("block"), None, None),
        );
        en.devices.insert(
            PathBuf::from("/sys/devices/block/dm-0"),
            DeviceInfo::new_test("/sys/devices/block/dm-0", Some("block"), None, None),
        );
        en.sorted = false;

        en.ensure_sorted();
        let names: Vec<&str> = en
            .sorted_devices
            .iter()
            .map(|p| p.to_str().unwrap())
            .collect();

        // sda before md0 and dm-0.
        let sda_idx = names.iter().position(|&n| n.contains("sda")).unwrap();
        let md_idx = names.iter().position(|&n| n.contains("md0")).unwrap();
        let dm_idx = names.iter().position(|&n| n.contains("dm-0")).unwrap();
        assert!(sda_idx < md_idx);
        assert!(sda_idx < dm_idx);
    }

    #[test]
    fn test_sort_order_sound_device() {
        let mut en = DeviceEnumerator::new();

        en.devices.insert(
            PathBuf::from("/sys/devices/pci0000:00/sound/card0/pcmC0D0p"),
            DeviceInfo::new_test(
                "/sys/devices/pci0000:00/sound/card0/pcmC0D0p",
                Some("sound"),
                None,
                None,
            ),
        );
        en.devices.insert(
            PathBuf::from("/sys/devices/pci0000:00/sound/card0/controlC0"),
            DeviceInfo::new_test(
                "/sys/devices/pci0000:00/sound/card0/controlC0",
                Some("sound"),
                None,
                None,
            ),
        );

        en.sorted = false;
        en.ensure_sorted();

        let names: Vec<&str> = en
            .sorted_devices
            .iter()
            .map(|p| p.to_str().unwrap())
            .collect();

        let pcm_idx = names.iter().position(|&n| n.contains("pcmC0D0p")).unwrap();
        let ctrl_idx = names.iter().position(|&n| n.contains("controlC0")).unwrap();
        // Control device must come after PCM device.
        assert!(pcm_idx < ctrl_idx);
    }

    // ── EnumerationType ────────────────────────────────────────────────

    #[test]
    fn test_enumeration_type_variants() {
        let mut en = DeviceEnumerator::new();
        assert!(en.enumeration_type.is_none());

        // After scan_devices (which won't find much in a test, but sets the type).
        // Use scan_devices on a nonexistent-based scan to avoid needing real /sys.
        // Instead, directly verify the type tracking.
        en.enumeration_type = Some(DeviceEnumerationType::Devices);
        en.scan_uptodate = true;
        assert!(en.scan_devices().is_ok());
        assert_eq!(en.enumeration_type, Some(DeviceEnumerationType::Devices));
    }

    // ── MatchFlag bitflags ─────────────────────────────────────────────

    #[test]
    fn test_match_flag_all() {
        assert!(MatchFlag::ALL.contains(MatchFlag::BASIC));
        assert!(MatchFlag::ALL.contains(MatchFlag::SYSNAME));
        assert!(MatchFlag::ALL.contains(MatchFlag::SUBSYSTEM));
        assert!(MatchFlag::ALL.contains(MatchFlag::PARENT));
        assert!(MatchFlag::ALL.contains(MatchFlag::TAG));
    }

    #[test]
    fn test_match_flag_empty() {
        let empty = MatchFlag::empty();
        assert!(!empty.contains(MatchFlag::BASIC));
        assert!(!empty.contains(MatchFlag::SYSNAME));
    }

    // ── Device count / contains ────────────────────────────────────────

    #[test]
    fn test_device_count_and_contains() {
        let mut en = DeviceEnumerator::new();
        assert_eq!(en.device_count(), 0);
        assert!(!en.contains(Path::new("/sys/block/sda")));

        en.devices.insert(
            PathBuf::from("/sys/block/sda"),
            DeviceInfo::new_test("/sys/block/sda", Some("block"), None, None),
        );
        assert_eq!(en.device_count(), 1);
        assert!(en.contains(Path::new("/sys/block/sda")));
    }

    // ── Combined filters ───────────────────────────────────────────────

    #[test]
    fn test_combined_subsystem_and_sysname_filters() {
        let mut en = DeviceEnumerator::new();
        en.add_match_subsystem("block", true);
        en.add_match_sysname("sd*", true);

        let block_sda = DeviceInfo::new_test("/sys/block/sda", Some("block"), None, None);
        assert!(en.matches(&block_sda));

        let block_loop = DeviceInfo::new_test("/sys/block/loop0", Some("block"), None, None);
        assert!(!en.matches(&block_loop));

        let net_eth = DeviceInfo::new_test("/sys/class/net/eth0", Some("net"), None, None);
        assert!(!en.matches(&net_eth));
    }

    #[test]
    fn test_combined_subsystem_nomatch_and_property() {
        let mut en = DeviceEnumerator::new();
        en.add_match_subsystem("net", false); // exclude net
        en.add_match_property("ID_TYPE", "disk");

        let mut block_disk = DeviceInfo::new_test("/sys/block/sda", Some("block"), None, None);
        block_disk
            .properties
            .insert("ID_TYPE".to_string(), "disk".to_string());
        assert!(en.matches(&block_disk));

        let mut net_dev = DeviceInfo::new_test("/sys/class/net/eth0", Some("net"), None, None);
        net_dev
            .properties
            .insert("ID_TYPE".to_string(), "disk".to_string());
        // net is excluded by nomatch subsystem.
        assert!(!en.matches(&net_dev));
    }

    #[test]
    fn test_add_all_parents_resets_flags() {
        let mut en = DeviceEnumerator::new();
        assert_eq!(en.parent_match_flags, MatchFlag::ALL);
        en.add_all_parents();
        assert_eq!(en.parent_match_flags, MatchFlag::empty());
    }
}
