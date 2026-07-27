// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/blockdev-list.c, src/shared/blockdev-list.h
//
// Block device listing — enumerate block devices from /sys/dev/block,
// device number sorting, and property extraction.

use crate::ffi::*;
use std::fs::{self, DirEntry};
use std::io;
use std::path::Path;

// ── Constants ─────────────────────────────────────────────────────────────

/// Sentinel value indicating an unknown or unavailable disk sequence number.
pub const DISKSEQ_UNKNOWN: u64 = u64::MAX;

/// Sentinel value indicating an unknown or unavailable device size.
pub const SIZE_UNKNOWN: u64 = u64::MAX;

/// Sector size assumed by the kernel's `size` sysfs attribute.
/// The `size` sysattr is always in multiples of 512, even on 4K sector block devices.
pub const SECTOR_SIZE: u64 = 512;

// ── Errors ────────────────────────────────────────────────────────────────

/// Errors that can occur during block device enumeration.
#[derive(Debug)]
pub enum BlockDevError {
    /// An I/O error occurred reading from sysfs.
    Io(io::Error),
    /// A device property could not be parsed.
    ParseError(String),
    /// The device number string could not be parsed.
    InvalidDeviceNumber(String),
}

impl std::fmt::Display for BlockDevError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BlockDevError::Io(e) => write!(f, "I/O error: {e}"),
            BlockDevError::ParseError(s) => write!(f, "parse error: {s}"),
            BlockDevError::InvalidDeviceNumber(s) => {
                write!(f, "invalid device number: {s}")
            }
        }
    }
}

impl std::error::Error for BlockDevError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            BlockDevError::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for BlockDevError {
    fn from(e: io::Error) -> Self {
        BlockDevError::Io(e)
    }
}

// ── Flags ─────────────────────────────────────────────────────────────────

bitflags::bitflags! {
    /// Flags controlling block device enumeration behaviour.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct BlockDevListFlags: u32 {
        /// Pick up symlinks to block devices too.
        const SHOW_SYMLINKS              = 1 << 0;
        /// Only consider block devices with partition scanning.
        const REQUIRE_PARTITION_SCANNING = 1 << 1;
        /// Ignore ZRAM devices.
        const IGNORE_ZRAM                = 1 << 2;
        /// Only consider block devices with LUKS superblocks.
        const REQUIRE_LUKS               = 1 << 3;
        /// Ignore the block device we are currently booted from.
        const IGNORE_ROOT                = 1 << 4;
        /// Ignore disks of zero size (usually drives without a medium).
        const IGNORE_EMPTY               = 1 << 5;
        /// Fill in model, vendor, subsystem fields.
        const METADATA                   = 1 << 6;
    }
}

// ── Data structures ───────────────────────────────────────────────────────

/// A discovered block device with its attributes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockDevice {
    /// Device node path (e.g. `/dev/sda`).
    pub node: String,
    /// Symlinks pointing to this device node (empty if not requested).
    pub symlinks: Vec<String>,
    /// Disk sequence number, or [`DISKSEQ_UNKNOWN`] if unavailable.
    pub diskseq: u64,
    /// Device size in bytes, or [`SIZE_UNKNOWN`] if unavailable.
    pub size: u64,
    /// Device model string (empty if unavailable or not requested).
    pub model: Option<String>,
    /// Device vendor string (empty if unavailable or not requested).
    pub vendor: Option<String>,
    /// Device subsystem string (empty if unavailable or not requested).
    pub subsystem: Option<String>,
}

impl BlockDevice {
    /// Create a null/default block device with sentinel values.
    pub fn null() -> Self {
        Self {
            node: String::new(),
            symlinks: Vec::new(),
            diskseq: DISKSEQ_UNKNOWN,
            size: SIZE_UNKNOWN,
            model: None,
            vendor: None,
            subsystem: None,
        }
    }
}

impl Default for BlockDevice {
    fn default() -> Self {
        Self::null()
    }
}

// ── Device number helpers ─────────────────────────────────────────────────

/// A parsed `major:minor` device number pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DevNum {
    pub major: u32,
    pub minor: u32,
}

impl DevNum {
    /// Parse a `"major:minor"` string (e.g. `"8:0"`) into a [`DevNum`].
    pub fn from_str_pair(s: &str) -> Result<Self, BlockDevError> {
        let (major_str, rest) = s
            .split_once(':')
            .ok_or_else(|| BlockDevError::InvalidDeviceNumber(s.to_owned()))?;
        let minor_str = rest.split(':').next().unwrap_or(rest);
        let major = major_str
            .parse::<u32>()
            .map_err(|_| BlockDevError::InvalidDeviceNumber(s.to_owned()))?;
        let minor = minor_str
            .parse::<u32>()
            .map_err(|_| BlockDevError::InvalidDeviceNumber(s.to_owned()))?;
        Ok(Self { major, minor })
    }
}

// ── Sysfs helpers ─────────────────────────────────────────────────────────

/// Read a single-line u64 attribute from a sysfs path.
fn read_sysattr_u64(sysfs_dir: &Path, attr: &str) -> Result<Option<u64>, BlockDevError> {
    let path = sysfs_dir.join(attr);
    match fs::read_to_string(&path) {
        Ok(contents) => {
            let trimmed = contents.trim();
            let val = trimmed
                .parse::<u64>()
                .map_err(|_| BlockDevError::ParseError(format!("{path:?}: {trimmed}")))?;
            Ok(Some(val))
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(BlockDevError::Io(e)),
    }
}

/// Read a single-line string attribute from a sysfs path.
fn read_sysattr_string(sysfs_dir: &Path, attr: &str) -> Result<Option<String>, BlockDevError> {
    let path = sysfs_dir.join(attr);
    match fs::read_to_string(&path) {
        Ok(contents) => {
            let trimmed = contents.trim().to_owned();
            if trimmed.is_empty() {
                Ok(None)
            } else {
                Ok(Some(trimmed))
            }
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(BlockDevError::Io(e)),
    }
}

/// Read a uevent file and extract a specific key's value.
fn read_uevent_var(sysfs_dir: &Path, key: &str) -> Result<Option<String>, BlockDevError> {
    let content = match fs::read_to_string(sysfs_dir.join("uevent")) {
        Ok(c) => c,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(BlockDevError::Io(e)),
    };

    for line in content.lines() {
        if let Some(val) = line.strip_prefix(key) {
            if let Some(val) = val.strip_prefix('=') {
                let trimmed = val.trim().to_owned();
                if !trimmed.is_empty() {
                    return Ok(Some(trimmed));
                }
            }
        }
    }
    Ok(None)
}

/// Read the DEVNAME from uevent, falling back to directory name.
fn resolve_devname(sysfs_dir: &Path, dir_name: &str) -> Result<String, BlockDevError> {
    // Try uevent DEVNAME first
    if let Some(devname) = read_uevent_var(sysfs_dir, "DEVNAME")? {
        return Ok(format!("/dev/{devname}"));
    }

    // Fallback: reconstruct from the sysfs directory name (major:minor → /dev/block/major:minor)
    let devnum = DevNum::from_str_pair(dir_name)?;
    Ok(format!("/dev/block/{}:{}", devnum.major, devnum.minor))
}

/// Get the disk sequence number for a device.
fn get_diskseq(sysfs_dir: &Path) -> Option<u64> {
    read_sysattr_u64(sysfs_dir, "diskseq").ok().flatten()
}

/// Check whether a device's sysname starts with the given prefix.
fn sysname_starts_with(sysfs_dir: &Path, prefix: &str) -> Result<bool, BlockDevError> {
    // The sysfs directory name for a block device is "major:minor", but the device
    // name is available from the uevent DEVNAME or the "dm/name" sysattr for dm devices.
    // For zram detection, we check DEVNAME.
    if let Some(devname) = read_uevent_var(sysfs_dir, "DEVNAME")? {
        return Ok(devname.starts_with(prefix));
    }
    Ok(false)
}

/// Read symlinks from /dev/block/ for a given major:minor pair.
fn read_dev_symlinks(major: u32, minor: u32) -> Vec<String> {
    let dev_block_path = Path::new("/dev/block");
    let mut symlinks = Vec::new();

    // Read the directory itself for entries that resolve to the same device
    if let Ok(entries) = fs::read_dir(dev_block_path) {
        for entry in entries.flatten() {
            if let Ok(file_type) = entry.file_type() {
                if file_type.is_symlink() {
                    if let Ok(target) = fs::read_link(entry.path()) {
                        // The target is typically "../major:minor"
                        if let Some(target_name) = target.file_name() {
                            if let Some(target_str) = target_name.to_str() {
                                if let Ok(target_devnum) = DevNum::from_str_pair(target_str) {
                                    if target_devnum.major == major && target_devnum.minor == minor
                                    {
                                        if let Some(name) =
                                            entry.file_name().to_str().map(|s| s.to_owned())
                                        {
                                            if name != format!("{major}:{minor}") {
                                                symlinks.push(format!("/dev/block/{name}"));
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    symlinks.sort();
    symlinks
}

// ── Property extraction ───────────────────────────────────────────────────

/// Try to read a device property, trying `prop1` first, then `prop2` (if given).
fn blockdev_get_prop(
    sysfs_dir: &Path,
    prop1: &str,
    prop2: Option<&str>,
) -> Result<Option<String>, BlockDevError> {
    // In a pure-Rust environment without udev properties, we look at the uevent file
    // and known sysfs attributes. The C version reads udev properties like
    // ID_MODEL_FROM_DATABASE, ID_MODEL etc. We provide analogous sysfs-based lookups.

    // Check uevent vars
    for prop in std::iter::once(prop1).chain(prop2) {
        if let Some(val) = read_uevent_var(sysfs_dir, prop)? {
            if !val.is_empty() {
                return Ok(Some(val));
            }
        }
    }

    Ok(None)
}

/// Get the subsystem for a block device.
///
/// We prefer the explicitly set `ID_BLOCK_SUBSYSTEM` property. If not set,
/// we walk up the parent devices looking for a subsystem that isn't "block".
fn blockdev_get_subsystem(sysfs_dir: &Path) -> Result<Option<String>, BlockDevError> {
    // Try ID_BLOCK_SUBSYSTEM from uevent
    if let Some(subsys) = read_uevent_var(sysfs_dir, "ID_BLOCK_SUBSYSTEM")? {
        if !subsys.is_empty() {
            return Ok(Some(subsys));
        }
    }

    // Walk up parent directories to find a non-"block" subsystem
    let mut current = sysfs_dir.to_path_buf();
    loop {
        current = match current.parent() {
            Some(p) => p.to_path_buf(),
            None => break,
        };

        // The subsystem symlink in sysfs: /sys/class/block/<dev>/subsystem
        let subsys_link = current.join("subsystem");
        if let Ok(target) = fs::read_link(&subsys_link) {
            if let Some(name) = target.file_name() {
                if let Some(name_str) = name.to_str() {
                    if !name_str.is_empty() && name_str != "block" {
                        return Ok(Some(name_str.to_owned()));
                    }
                }
            }
        }
    }

    Ok(None)
}

// ── Partition scanning check ──────────────────────────────────────────────

/// Check whether a block device supports partition scanning.
/// This is determined by the existence of a `partition` subdirectory in sysfs.
fn blockdev_partscan_enabled(sysfs_dir: &Path) -> Result<bool, BlockDevError> {
    // Look for /sys/dev/block/major:minor/partition or the "partscan" uevent flag
    if let Ok(entries) = fs::read_dir(sysfs_dir) {
        for entry in entries.flatten() {
            if let Some(name) = entry.file_name().to_str() {
                if name.starts_with("partition") {
                    return Ok(true);
                }
            }
        }
    }

    // Also check uevent for PARTN variable
    if let Some(partn) = read_uevent_var(sysfs_dir, "PARTN")? {
        if !partn.is_empty() {
            return Ok(true);
        }
    }

    // Check if there's a "partitions" subdirectory or if it has a range attribute
    let range_path = sysfs_dir.join("range");
    if range_path.exists() {
        return Ok(true);
    }

    Ok(false)
}

// ── Main enumeration ──────────────────────────────────────────────────────

/// List block devices from `/sys/dev/block`.
///
/// Enumerates all entries under `/sys/dev/block`, applies the requested
/// filters, and returns the matching devices sorted by device number.
///
/// # Arguments
///
/// * `flags` - Bitflags controlling filtering and metadata collection.
/// * `root_devno` - If [`BlockDevListFlags::IGNORE_ROOT`] is set, this device
///   number will be excluded from results. Pass `None` to skip root filtering.
///
/// # Returns
///
/// A vector of [`BlockDevice`] sorted by device number (major, then minor).
pub fn blockdev_list(
    flags: BlockDevListFlags,
    root_devno: Option<DevNum>,
) -> Result<Vec<BlockDevice>, BlockDevError> {
    let sysfs_block = Path::new("/sys/dev/block");

    let mut devices = Vec::new();

    let entries = fs::read_dir(sysfs_block)?;

    for entry in entries {
        let entry = entry?;
        let dir_name = match entry.file_name().to_str() {
            Some(name) => name.to_owned(),
            None => continue,
        };

        // Parse the device number from the directory name (major:minor)
        let devnum = match DevNum::from_str_pair(&dir_name) {
            Ok(dn) => dn,
            Err(_) => continue, // Skip entries that aren't major:minor
        };

        let sysfs_dir = entry.path();

        // Resolve device node name
        let node = match resolve_devname(&sysfs_dir, &dir_name) {
            Ok(n) => n,
            Err(_) => continue,
        };

        // Filter: ignore root device
        if flags.contains(BlockDevListFlags::IGNORE_ROOT) {
            if let Some(ref root) = root_devno {
                if devnum == *root {
                    continue;
                }
            }
        }

        // Filter: ignore zram devices
        if flags.contains(BlockDevListFlags::IGNORE_ZRAM) {
            match sysname_starts_with(&sysfs_dir, "zram") {
                Ok(true) => continue,
                Err(_) => continue,
                Ok(false) => {}
            }
        }

        // Filter: require partition scanning
        if flags.contains(BlockDevListFlags::REQUIRE_PARTITION_SCANNING) {
            match blockdev_partscan_enabled(&sysfs_dir) {
                Ok(true) => {}
                Ok(false) | Err(_) => continue,
            }
        }

        // Filter: require LUKS — check for ID_FS_TYPE=crypto_LUKS in uevent
        if flags.contains(BlockDevListFlags::REQUIRE_LUKS) {
            match read_uevent_var(&sysfs_dir, "ID_FS_TYPE") {
                Ok(Some(ref fs_type)) if fs_type == "crypto_LUKS" => {}
                _ => continue,
            }
        }

        // Read size (always needed when IGNORE_EMPTY is set or when returning devices)
        let mut size = SIZE_UNKNOWN;
        if flags.contains(BlockDevListFlags::IGNORE_EMPTY) {
            if let Ok(Some(s)) = read_sysattr_u64(&sysfs_dir, "size") {
                size = s.saturating_mul(SECTOR_SIZE);
                if size == 0 {
                    continue; // zero-size device, skip
                }
            }
        }

        // Collect symlinks
        let symlinks = if flags.contains(BlockDevListFlags::SHOW_SYMLINKS) {
            read_dev_symlinks(devnum.major, devnum.minor)
        } else {
            Vec::new()
        };

        // Read metadata
        let mut model = None;
        let mut vendor = None;
        let mut subsystem = None;

        if flags.contains(BlockDevListFlags::METADATA) {
            model = blockdev_get_prop(&sysfs_dir, "ID_MODEL_FROM_DATABASE", Some("ID_MODEL"))
                .ok()
                .flatten();
            vendor = blockdev_get_prop(&sysfs_dir, "ID_VENDOR_FROM_DATABASE", Some("ID_VENDOR"))
                .ok()
                .flatten();
            subsystem = blockdev_get_subsystem(&sysfs_dir).ok().flatten();
        }

        // Get disk sequence number
        let diskseq = get_diskseq(&sysfs_dir).unwrap_or(DISKSEQ_UNKNOWN);

        // If we didn't read size yet (because IGNORE_EMPTY was not set),
        // read it now for the return value.
        if size == SIZE_UNKNOWN {
            if let Ok(Some(s)) = read_sysattr_u64(&sysfs_dir, "size") {
                size = s.saturating_mul(SECTOR_SIZE);
            }
        }

        devices.push(BlockDevice {
            node,
            symlinks,
            diskseq,
            size,
            model,
            vendor,
            subsystem,
        });
    }

    // Sort by device number (major first, then minor)
    devices.sort_by(|a, b| {
        let a_devnum = DevNum::from_str_pair(&a.node.rsplit('/').next().unwrap_or(""))
            .unwrap_or(DevNum { major: 0, minor: 0 });
        let b_devnum = DevNum::from_str_pair(&b.node.rsplit('/').next().unwrap_or(""))
            .unwrap_or(DevNum { major: 0, minor: 0 });
        a_devnum.cmp(&b_devnum)
    });

    Ok(devices)
}

/// Parse a `"major:minor"` device number string from a device node path.
///
/// Extracts the device number from a path like `/dev/sda` by reading
/// the corresponding `/sys/dev/block` entry.
pub fn devnum_from_node(node: &str) -> Result<DevNum, BlockDevError> {
    // Try reading from /sys/dev/block by checking /sys/class/block/<name>
    let dev_name = Path::new(node)
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| BlockDevError::ParseError(format!("cannot extract name from {node}")))?;

    let sysfs_path = Path::new("/sys/class/block").join(dev_name);
    if let Ok(target) = fs::read_link(&sysfs_path) {
        // target is like "../../dev/block/major:minor"
        if let Some(dir_name) = target.file_name() {
            if let Some(dir_str) = dir_name.to_str() {
                return DevNum::from_str_pair(dir_str);
            }
        }
    }

    // Fallback: try /sys/block/<name>/dev
    let dev_attr_path = Path::new("/sys/block").join(dev_name).join("dev");
    if let Ok(contents) = fs::read_to_string(&dev_attr_path) {
        return DevNum::from_str_pair(contents.trim());
    }

    Err(BlockDevError::ParseError(format!(
        "cannot resolve device number for {node}"
    )))
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_devnum_from_str_pair_valid() {
        let dn = DevNum::from_str_pair("8:0").unwrap();
        assert_eq!(dn.major, 8);
        assert_eq!(dn.minor, 0);
    }

    #[test]
    fn test_devnum_from_str_pair_large_numbers() {
        let dn = DevNum::from_str_pair("259:131072").unwrap();
        assert_eq!(dn.major, 259);
        assert_eq!(dn.minor, 131072);
    }

    #[test]
    fn test_devnum_from_str_pair_no_colon() {
        assert!(DevNum::from_str_pair("80").is_err());
    }

    #[test]
    fn test_devnum_from_str_pair_empty() {
        assert!(DevNum::from_str_pair("").is_err());
    }

    #[test]
    fn test_devnum_from_str_pair_non_numeric() {
        assert!(DevNum::from_str_pair("abc:def").is_err());
    }

    #[test]
    fn test_devnum_from_str_pair_multiple_colons() {
        // "8:0:1" should parse major=8, minor=0 (splits on first colon)
        let dn = DevNum::from_str_pair("8:0:1").unwrap();
        assert_eq!(dn.major, 8);
        assert_eq!(dn.minor, 0);
    }

    #[test]
    fn test_devnum_ordering() {
        let a = DevNum::from_str_pair("8:0").unwrap();
        let b = DevNum::from_str_pair("8:1").unwrap();
        let c = DevNum::from_str_pair("259:0").unwrap();

        assert!(a < b);
        assert!(b < c);
        assert_eq!(a.cmp(&a), std::cmp::Ordering::Equal);
    }

    #[test]
    fn test_block_device_null() {
        let dev = BlockDevice::null();
        assert!(dev.node.is_empty());
        assert!(dev.symlinks.is_empty());
        assert_eq!(dev.diskseq, DISKSEQ_UNKNOWN);
        assert_eq!(dev.size, SIZE_UNKNOWN);
        assert!(dev.model.is_none());
        assert!(dev.vendor.is_none());
        assert!(dev.subsystem.is_none());
    }

    #[test]
    fn test_block_device_default() {
        let dev = BlockDevice::default();
        assert_eq!(dev.diskseq, DISKSEQ_UNKNOWN);
        assert_eq!(dev.size, SIZE_UNKNOWN);
    }

    #[test]
    fn test_blockdev_list_flags_empty() {
        let flags = BlockDevListFlags::empty();
        assert!(!flags.contains(BlockDevListFlags::SHOW_SYMLINKS));
        assert!(!flags.contains(BlockDevListFlags::IGNORE_ZRAM));
        assert!(!flags.contains(BlockDevListFlags::IGNORE_EMPTY));
        assert!(!flags.contains(BlockDevListFlags::METADATA));
    }

    #[test]
    fn test_blockdev_list_flags_composition() {
        let flags = BlockDevListFlags::IGNORE_ZRAM
            | BlockDevListFlags::IGNORE_EMPTY
            | BlockDevListFlags::METADATA;
        assert!(flags.contains(BlockDevListFlags::IGNORE_ZRAM));
        assert!(flags.contains(BlockDevListFlags::IGNORE_EMPTY));
        assert!(flags.contains(BlockDevListFlags::METADATA));
        assert!(!flags.contains(BlockDevListFlags::SHOW_SYMLINKS));
        assert!(!flags.contains(BlockDevListFlags::REQUIRE_LUKS));
    }

    #[test]
    fn test_blockdev_list_flags_all_bits() {
        let flags = BlockDevListFlags::all();
        assert!(flags.contains(BlockDevListFlags::SHOW_SYMLINKS));
        assert!(flags.contains(BlockDevListFlags::REQUIRE_PARTITION_SCANNING));
        assert!(flags.contains(BlockDevListFlags::IGNORE_ZRAM));
        assert!(flags.contains(BlockDevListFlags::REQUIRE_LUKS));
        assert!(flags.contains(BlockDevListFlags::IGNORE_ROOT));
        assert!(flags.contains(BlockDevListFlags::IGNORE_EMPTY));
        assert!(flags.contains(BlockDevListFlags::METADATA));
    }

    #[test]
    fn test_blockdev_list_flags_bit_values() {
        assert_eq!(BlockDevListFlags::SHOW_SYMLINKS.bits(), 1);
        assert_eq!(BlockDevListFlags::REQUIRE_PARTITION_SCANNING.bits(), 2);
        assert_eq!(BlockDevListFlags::IGNORE_ZRAM.bits(), 4);
        assert_eq!(BlockDevListFlags::REQUIRE_LUKS.bits(), 8);
        assert_eq!(BlockDevListFlags::IGNORE_ROOT.bits(), 16);
        assert_eq!(BlockDevListFlags::IGNORE_EMPTY.bits(), 32);
        assert_eq!(BlockDevListFlags::METADATA.bits(), 64);
    }

    #[test]
    fn test_block_device_equality() {
        let a = BlockDevice {
            node: "/dev/sda".to_owned(),
            symlinks: vec!["/dev/disk/by-id/xxx".to_owned()],
            diskseq: 42,
            size: 500_000_000_000,
            model: Some("Samsung".to_owned()),
            vendor: Some("Samsung".to_owned()),
            subsystem: Some("block".to_owned()),
        };
        let b = BlockDevice {
            node: "/dev/sda".to_owned(),
            symlinks: vec!["/dev/disk/by-id/xxx".to_owned()],
            diskseq: 42,
            size: 500_000_000_000,
            model: Some("Samsung".to_owned()),
            vendor: Some("Samsung".to_owned()),
            subsystem: Some("block".to_owned()),
        };
        assert_eq!(a, b);
    }

    #[test]
    fn test_block_device_inequality() {
        let a = BlockDevice {
            node: "/dev/sda".to_owned(),
            ..BlockDevice::default()
        };
        let b = BlockDevice {
            node: "/dev/sdb".to_owned(),
            ..BlockDevice::default()
        };
        assert_ne!(a, b);
    }

    #[test]
    fn test_block_device_clone() {
        let a = BlockDevice {
            node: "/dev/sda".to_owned(),
            symlinks: vec!["/dev/disk/by-id/aaa".to_owned()],
            diskseq: 1,
            size: 1024,
            model: Some("Test".to_owned()),
            vendor: None,
            subsystem: Some("virtio".to_owned()),
        };
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn test_sector_size_constant() {
        assert_eq!(SECTOR_SIZE, 512);
    }

    #[test]
    fn test_sentinel_constants() {
        assert_eq!(DISKSEQ_UNKNOWN, u64::MAX);
        assert_eq!(SIZE_UNKNOWN, u64::MAX);
    }

    #[test]
    fn test_read_sysattr_u64_nonexistent() {
        let tmp = tempfile::tempdir().unwrap();
        let result = read_sysattr_u64(tmp.path(), "nonexistent");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), None);
    }

    #[test]
    fn test_read_sysattr_string_nonexistent() {
        let tmp = tempfile::tempdir().unwrap();
        let result = read_sysattr_string(tmp.path(), "nonexistent");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), None);
    }

    #[test]
    fn test_read_sysattr_u64_valid() {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(tmp.path().join("size"), "1024\n").unwrap();
        let result = read_sysattr_u64(tmp.path(), "size").unwrap();
        assert_eq!(result, Some(1024));
    }

    #[test]
    fn test_read_sysattr_string_valid() {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(tmp.path().join("model"), "Samsung SSD\n").unwrap();
        let result = read_sysattr_string(tmp.path(), "model").unwrap();
        assert_eq!(result, Some("Samsung SSD".to_owned()));
    }

    #[test]
    fn test_read_sysattr_string_empty() {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(tmp.path().join("model"), "\n").unwrap();
        let result = read_sysattr_string(tmp.path(), "model").unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn test_blockdev_error_display() {
        let err = BlockDevError::ParseError("bad value".to_owned());
        assert_eq!(format!("{err}"), "parse error: bad value");
    }

    #[test]
    fn test_blockdev_error_io_display() {
        let inner = io::Error::new(io::ErrorKind::NotFound, "not found");
        let err = BlockDevError::Io(inner);
        let msg = format!("{err}");
        assert!(msg.contains("not found"));
    }

    #[test]
    fn test_blockdev_error_debug() {
        let err = BlockDevError::InvalidDeviceNumber("abc".to_owned());
        let debug = format!("{err:?}");
        assert!(debug.contains("InvalidDeviceNumber"));
    }
}
