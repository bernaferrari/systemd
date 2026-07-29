// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/libsystemd/sd-device/device-util.c, src/libsystemd/sd-device/device-util.h
//
// Device utility functions for querying device properties.
//
// Provides safe wrappers for resolving device names, checking device types,
// inspecting subsystems, querying seats, and validating device properties.
// All syscalls (stat, ioctl) are confined to minimal unsafe blocks.

use crate::ffi::*;
use std::ffi::CString;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use systemd_basic_rs::devnum_util::{devnum_major, devnum_minor};

// ── Constants ─────────────────────────────────────────────────────────────

/// Default seat name used when no ID_SEAT property is set.
pub const DEFAULT_SEAT: &str = "seat0";

/// Path returned when a device number is zero (inaccessible).
pub const INACCESSIBLE_DEVICE_PATH: &str = "/dev/inaccessible";

/// Device sysfs base path.
pub const SYSFS_DEV_PATH: &str = "/dev";

// ── Enums ─────────────────────────────────────────────────────────────────

/// Device mode types (block or character).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceMode {
    Block,
    Char,
}

impl DeviceMode {
    /// Extract the `DeviceMode` from a raw `st_mode` value.
    /// Returns `None` if the mode does not represent a device.
    pub fn from_stat_mode(st_mode: u32) -> Option<Self> {
        let ifmt = (st_mode & libc::S_IFMT as u32) as u16;
        match ifmt {
            libc::S_IFBLK => Some(DeviceMode::Block),
            libc::S_IFCHR => Some(DeviceMode::Char),
            _ => None,
        }
    }

    /// Get the mode_t bitmask for this device type.
    pub const fn to_mode_bits(self) -> u32 {
        match self {
            DeviceMode::Block => libc::S_IFBLK as u32,
            DeviceMode::Char => libc::S_IFCHR as u32,
        }
    }
}

impl std::fmt::Display for DeviceMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DeviceMode::Block => write!(f, "block"),
            DeviceMode::Char => write!(f, "char"),
        }
    }
}

/// Device action types reported by udev events.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceAction {
    Add,
    Remove,
    Change,
    Move,
    Online,
    Offline,
    Bind,
    Unbind,
}

impl DeviceAction {
    /// Parse a device action from its string representation.
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "add" => Some(Self::Add),
            "remove" => Some(Self::Remove),
            "change" => Some(Self::Change),
            "move" => Some(Self::Move),
            "online" => Some(Self::Online),
            "offline" => Some(Self::Offline),
            "bind" => Some(Self::Bind),
            "unbind" => Some(Self::Unbind),
            _ => None,
        }
    }

    /// Convert to the canonical string representation.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Add => "add",
            Self::Remove => "remove",
            Self::Change => "change",
            Self::Move => "move",
            Self::Online => "online",
            Self::Offline => "offline",
            Self::Bind => "bind",
            Self::Unbind => "unbind",
        }
    }

    /// Return all possible device actions.
    pub const fn all() -> &'static [DeviceAction] {
        &[
            DeviceAction::Add,
            DeviceAction::Remove,
            DeviceAction::Change,
            DeviceAction::Move,
            DeviceAction::Online,
            DeviceAction::Offline,
            DeviceAction::Bind,
            DeviceAction::Unbind,
        ]
    }
}

impl std::fmt::Display for DeviceAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

// ── Stat helpers ──────────────────────────────────────────────────────────

/// Perform a `stat(2)` call on the given path.
///
/// The unsafe block is minimal: it only wraps the libc `stat` syscall.
fn stat_path(path: &Path) -> io::Result<libc::stat> {
    let c_path = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "path contains NUL byte"))?;

    let mut stat_buf = std::mem::MaybeUninit::<libc::stat>::uninit();

    // SAFETY: c_path is a valid NUL-terminated string, stat_buf is a valid pointer.
    let ret = unsafe { libc::stat(c_path.as_ptr(), stat_buf.as_mut_ptr()) };

    if ret < 0 {
        return Err(io::Error::last_os_error());
    }

    // SAFETY: stat succeeded, so stat_buf is now initialized.
    Ok(unsafe { stat_buf.assume_init() })
}

// ── Device name resolution ────────────────────────────────────────────────

/// Resolve a device path from a device number by scanning `/dev`.
///
/// If `devnum` is zero, returns the inaccessible device path.
pub fn devname_from_devnum(mode: DeviceMode, devnum: u64) -> io::Result<String> {
    if devnum == 0 {
        return Ok(INACCESSIBLE_DEVICE_PATH.to_string());
    }

    let dev_path = Path::new(SYSFS_DEV_PATH);

    for entry in std::fs::read_dir(dev_path)? {
        let entry = entry?;
        let path = entry.path();

        let stat_buf = match stat_path(&path) {
            Ok(s) => s,
            Err(_) => continue,
        };

        let ifmt = (stat_buf.st_mode as u32) & libc::S_IFMT as u32;
        if ifmt == mode.to_mode_bits() && stat_buf.st_rdev as u64 == devnum {
            return Ok(path.to_string_lossy().to_string());
        }
    }

    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "Device not found in /dev",
    ))
}

/// Resolve a device path from a stat structure's `st_rdev` field.
///
/// Returns an error if the stat does not refer to a block or character device.
pub fn devname_from_stat_rdev(st: &libc::stat) -> io::Result<String> {
    let mode = DeviceMode::from_stat_mode(st.st_mode as u32)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "Not a device"))?;

    devname_from_devnum(mode, st.st_rdev as u64)
}

// ── Device type checks ───────────────────────────────────────────────────

/// Check if the given path points to a block device.
pub fn is_block_device<P: AsRef<Path>>(path: P) -> io::Result<bool> {
    let st = stat_path(path.as_ref())?;
    Ok((st.st_mode & libc::S_IFMT) == libc::S_IFBLK)
}

/// Check if the given path points to a character device.
pub fn is_char_device<P: AsRef<Path>>(path: P) -> io::Result<bool> {
    let st = stat_path(path.as_ref())?;
    Ok((st.st_mode & libc::S_IFMT) == libc::S_IFCHR)
}

/// Check if a path refers to any device (block or character).
pub fn is_device<P: AsRef<Path>>(path: P) -> io::Result<bool> {
    let st = stat_path(path.as_ref())?;
    let ifmt = st.st_mode & libc::S_IFMT;
    Ok(ifmt == libc::S_IFBLK || ifmt == libc::S_IFCHR)
}

// ── Subsystem checks ─────────────────────────────────────────────────────

/// Check if a device (given its sysfs path) belongs to a specific subsystem.
///
/// Reads the `subsystem` and `bus` symlinks under the device's sysfs directory.
pub fn device_in_subsystem(device_path: &Path, subsystem: &str) -> io::Result<bool> {
    if !device_path.exists() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("{}: device path does not exist", device_path.display()),
        ));
    }
    for link_name in ["subsystem", "bus"] {
        let link_path = device_path.join(link_name);
        if let Ok(target) = std::fs::read_link(&link_path) {
            if let Some(name) = target.file_name() {
                if name == subsystem {
                    return Ok(true);
                }
            }
        }
    }

    Ok(false)
}

/// Check if a device's subsystem is one of the given candidates.
pub fn device_in_subsystems(device_path: &Path, subsystems: &[&str]) -> io::Result<bool> {
    for subsystem in subsystems {
        if device_in_subsystem(device_path, subsystem)? {
            return Ok(true);
        }
    }
    Ok(false)
}

// ── Device seat ───────────────────────────────────────────────────────────

/// Get the seat name for a device from its sysfs uevent file.
///
/// Reads the `ID_SEAT` property from the uevent file. If the property is
/// absent or empty, returns the default seat (`seat0`).
pub fn device_get_seat(device_path: &Path) -> io::Result<String> {
    let uevent_path = device_path.join("uevent");

    if let Ok(contents) = std::fs::read_to_string(&uevent_path) {
        for line in contents.lines() {
            if let Some(value) = line.strip_prefix("ID_SEAT=") {
                if value.is_empty() {
                    return Ok(DEFAULT_SEAT.to_string());
                }
                return Ok(value.to_string());
            }
        }
    }

    Ok(DEFAULT_SEAT.to_string())
}

/// Extract the `ID_SEAT` value from uevent file content.
///
/// Returns `None` if the property is not found in the content.
pub fn parse_seat_from_uevent(uevent_content: &str) -> Option<String> {
    for line in uevent_content.lines() {
        if let Some(value) = line.strip_prefix("ID_SEAT=") {
            if value.is_empty() {
                return Some(DEFAULT_SEAT.to_string());
            }
            return Some(value.to_string());
        }
    }
    None
}

// ── Device property validation ────────────────────────────────────────────

/// Check whether a device property can be set.
///
/// Returns `false` for kernel-managed properties (ACTION, DEVPATH, SUBSYSTEM,
/// etc.), udevd-managed properties (DEVLINKS, TAGS, etc.), and properties
/// with the `SYNTH_ARG_` prefix.
pub fn device_property_can_set(property: &str) -> bool {
    if property.is_empty() {
        return false;
    }

    // Properties set by kernel / udevd that cannot be changed.
    const READONLY_PROPS: &[&str] = &[
        // Basic properties from netlink events
        "ACTION",
        "SEQNUM",
        "SYNTH_UUID",
        // Basic properties from netlink events and uevent file
        "DEVPATH",
        "DEVPATH_OLD",
        "SUBSYSTEM",
        "DEVTYPE",
        "DRIVER",
        "MODALIAS",
        // Device node
        "DEVNAME",
        "DEVMODE",
        "DEVUID",
        "DEVGID",
        "MAJOR",
        "MINOR",
        // Block device
        "DISKSEQ",
        "PARTN",
        // Network interface
        "IFINDEX",
        "INTERFACE",
        "INTERFACE_OLD",
        // Properties set by udevd
        "DEVLINKS",
        "TAGS",
        "CURRENT_TAGS",
        "USEC_INITIALIZED",
        "UDEV_DATABASE_VERSION",
    ];

    if READONLY_PROPS.contains(&property) {
        return false;
    }

    // SYNTH_ARG_ prefix is reserved (kernel f36776fafbaa0094390dd4e7e3e29805e0b82730)
    if property.starts_with("SYNTH_ARG_") {
        return false;
    }

    true
}

// ── Device sysname helpers ───────────────────────────────────────────────

/// Check if a device sysname starts with any of the given prefixes.
///
/// Returns the matching prefix (if any) and the remaining suffix.
pub fn sysname_starts_with<'a>(sysname: &'a str, prefixes: &[&str]) -> Option<(usize, &'a str)> {
    for (i, prefix) in prefixes.iter().enumerate() {
        if let Some(suffix) = sysname.strip_prefix(prefix) {
            return Some((i, suffix));
        }
    }
    None
}

// ── Device type checks (string-based) ────────────────────────────────────

/// Check if a device type string matches the expected devtype.
///
/// If `devtype` is `None`, returns `true` only when the actual devtype is also absent.
/// If `devtype` is `Some("")`, returns `true` when the actual devtype is absent or empty.
pub fn device_is_devtype(actual_devtype: Option<&str>, expected_devtype: Option<&str>) -> bool {
    match (actual_devtype, expected_devtype) {
        (None, None) => true,
        (Some(_), None) => false,
        (None, Some(_)) => false,
        (Some(actual), Some(expected)) => actual == expected,
    }
}

/// Check if a device matches both the expected subsystem and devtype.
///
/// The subsystem check must pass first; if `devtype` is `None`, only subsystem is checked.
pub fn device_is_subsystem_devtype(
    in_subsystem: bool,
    actual_devtype: Option<&str>,
    expected_devtype: Option<&str>,
) -> bool {
    if !in_subsystem {
        return false;
    }

    match expected_devtype {
        None => true,
        Some(dt) => device_is_devtype(actual_devtype, Some(dt)),
    }
}

// ── Log field construction ───────────────────────────────────────────────

/// Build a log-style key=value string for a device property.
pub fn make_log_field(key: &str, value: &str) -> String {
    format!("{key}={value}")
}

/// Build a formatted device number string in `major:minor` format.
pub fn format_devnum(devnum: u64) -> String {
    format!("{}:{}", devnum_major(devnum), devnum_minor(devnum))
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_device_mode_from_stat_mode() {
        let block_mode = libc::S_IFBLK as u32 | 0o600;
        let char_mode = libc::S_IFCHR as u32 | 0o660;
        let regular_mode = libc::S_IFREG as u32 | 0o644;

        assert_eq!(
            DeviceMode::from_stat_mode(block_mode),
            Some(DeviceMode::Block)
        );
        assert_eq!(
            DeviceMode::from_stat_mode(char_mode),
            Some(DeviceMode::Char)
        );
        assert_eq!(DeviceMode::from_stat_mode(regular_mode), None);
        assert_eq!(DeviceMode::from_stat_mode(0), None);
    }

    #[test]
    fn test_device_mode_to_mode_bits() {
        assert_eq!(DeviceMode::Block.to_mode_bits(), libc::S_IFBLK as u32);
        assert_eq!(DeviceMode::Char.to_mode_bits(), libc::S_IFCHR as u32);
    }

    #[test]
    fn test_device_mode_display() {
        assert_eq!(DeviceMode::Block.to_string(), "block");
        assert_eq!(DeviceMode::Char.to_string(), "char");
    }

    #[test]
    fn test_device_action_from_str() {
        assert_eq!(DeviceAction::from_str("add"), Some(DeviceAction::Add));
        assert_eq!(DeviceAction::from_str("remove"), Some(DeviceAction::Remove));
        assert_eq!(DeviceAction::from_str("change"), Some(DeviceAction::Change));
        assert_eq!(DeviceAction::from_str("move"), Some(DeviceAction::Move));
        assert_eq!(DeviceAction::from_str("online"), Some(DeviceAction::Online));
        assert_eq!(
            DeviceAction::from_str("offline"),
            Some(DeviceAction::Offline)
        );
        assert_eq!(DeviceAction::from_str("bind"), Some(DeviceAction::Bind));
        assert_eq!(DeviceAction::from_str("unbind"), Some(DeviceAction::Unbind));
        assert_eq!(DeviceAction::from_str("unknown"), None);
        assert_eq!(DeviceAction::from_str(""), None);
    }

    #[test]
    fn test_device_action_as_str() {
        assert_eq!(DeviceAction::Add.as_str(), "add");
        assert_eq!(DeviceAction::Remove.as_str(), "remove");
        assert_eq!(DeviceAction::Change.as_str(), "change");
        assert_eq!(DeviceAction::Move.as_str(), "move");
        assert_eq!(DeviceAction::Online.as_str(), "online");
        assert_eq!(DeviceAction::Offline.as_str(), "offline");
        assert_eq!(DeviceAction::Bind.as_str(), "bind");
        assert_eq!(DeviceAction::Unbind.as_str(), "unbind");
    }

    #[test]
    fn test_device_action_roundtrip() {
        for action in DeviceAction::all() {
            let s = action.as_str();
            assert_eq!(DeviceAction::from_str(s), Some(*action));
        }
    }

    #[test]
    fn test_device_action_display() {
        assert_eq!(format!("{}", DeviceAction::Add), "add");
        assert_eq!(format!("{}", DeviceAction::Remove), "remove");
    }

    #[test]
    fn test_device_action_all_count() {
        assert_eq!(DeviceAction::all().len(), 8);
    }

    #[test]
    fn test_device_property_can_set_readonly() {
        // Kernel-managed properties
        assert!(!device_property_can_set("ACTION"));
        assert!(!device_property_can_set("SEQNUM"));
        assert!(!device_property_can_set("SYNTH_UUID"));
        assert!(!device_property_can_set("DEVPATH"));
        assert!(!device_property_can_set("SUBSYSTEM"));
        assert!(!device_property_can_set("DEVTYPE"));
        assert!(!device_property_can_set("DRIVER"));
        assert!(!device_property_can_set("MODALIAS"));
    }

    #[test]
    fn test_device_property_can_set_device_node() {
        assert!(!device_property_can_set("DEVNAME"));
        assert!(!device_property_can_set("DEVMODE"));
        assert!(!device_property_can_set("DEVUID"));
        assert!(!device_property_can_set("DEVGID"));
        assert!(!device_property_can_set("MAJOR"));
        assert!(!device_property_can_set("MINOR"));
    }

    #[test]
    fn test_device_property_can_set_block_net() {
        assert!(!device_property_can_set("DISKSEQ"));
        assert!(!device_property_can_set("PARTN"));
        assert!(!device_property_can_set("IFINDEX"));
        assert!(!device_property_can_set("INTERFACE"));
        assert!(!device_property_can_set("INTERFACE_OLD"));
    }

    #[test]
    fn test_device_property_can_set_udev() {
        assert!(!device_property_can_set("DEVLINKS"));
        assert!(!device_property_can_set("TAGS"));
        assert!(!device_property_can_set("CURRENT_TAGS"));
        assert!(!device_property_can_set("USEC_INITIALIZED"));
        assert!(!device_property_can_set("UDEV_DATABASE_VERSION"));
    }

    #[test]
    fn test_device_property_can_set_synth_arg() {
        assert!(!device_property_can_set("SYNTH_ARG_FOO"));
        assert!(!device_property_can_set("SYNTH_ARG_1"));
        assert!(!device_property_can_set("SYNTH_ARG_"));
        // Not a SYNTH_ARG_ prefix
        assert!(device_property_can_set("SYNTH_ARGX"));
    }

    #[test]
    fn test_device_property_can_set_valid() {
        assert!(device_property_can_set("ID_MODEL"));
        assert!(device_property_can_set("ID_SERIAL"));
        assert!(device_property_can_set("MY_CUSTOM_PROP"));
        assert!(device_property_can_set("TAG"));
        assert!(device_property_can_set("SYSTEMD_WANTS"));
    }

    #[test]
    fn test_device_property_can_set_empty() {
        assert!(!device_property_can_set(""));
    }

    #[test]
    fn test_parse_seat_from_uevent() {
        let content = "ACTION=add\nDEVPATH=/devices/platform\nID_SEAT=seat1\n";
        assert_eq!(parse_seat_from_uevent(content), Some("seat1".to_string()));
    }

    #[test]
    fn test_parse_seat_from_uevent_empty_seat() {
        let content = "ACTION=add\nID_SEAT=\n";
        assert_eq!(
            parse_seat_from_uevent(content),
            Some(DEFAULT_SEAT.to_string())
        );
    }

    #[test]
    fn test_parse_seat_from_uevent_no_seat() {
        let content = "ACTION=add\nDEVPATH=/devices/platform\n";
        assert_eq!(parse_seat_from_uevent(content), None);
    }

    #[test]
    fn test_parse_seat_from_uevent_empty_content() {
        assert_eq!(parse_seat_from_uevent(""), None);
    }

    #[test]
    fn test_sysname_starts_with() {
        assert_eq!(
            sysname_starts_with("sda1", &["sd", "nvme"]),
            Some((0, "a1"))
        );
        assert_eq!(
            sysname_starts_with("nvme0n1p1", &["sd", "nvme"]),
            Some((1, "0n1p1"))
        );
        assert_eq!(sysname_starts_with("sda1", &["xv", "vd"]), None);
        assert_eq!(sysname_starts_with("", &["sd"]), None);
    }

    #[test]
    fn test_sysname_starts_with_empty_prefixes() {
        assert_eq!(sysname_starts_with("sda", &[]), None);
    }

    #[test]
    fn test_sysname_starts_with_exact_match() {
        assert_eq!(sysname_starts_with("sda", &["sda"]), Some((0, "")));
    }

    #[test]
    fn test_device_is_devtype() {
        assert!(device_is_devtype(Some("disk"), Some("disk")));
        assert!(device_is_devtype(None, None));
        assert!(!device_is_devtype(Some("disk"), None));
        assert!(!device_is_devtype(None, Some("disk")));
        assert!(!device_is_devtype(Some("disk"), Some("partition")));
    }

    #[test]
    fn test_device_is_subsystem_devtype() {
        // subsystem matches, devtype matches
        assert!(device_is_subsystem_devtype(
            true,
            Some("disk"),
            Some("disk")
        ));
        // subsystem matches, no devtype expected → true
        assert!(device_is_subsystem_devtype(true, Some("disk"), None));
        // subsystem doesn't match → false regardless
        assert!(!device_is_subsystem_devtype(
            false,
            Some("disk"),
            Some("disk")
        ));
        assert!(!device_is_subsystem_devtype(false, Some("disk"), None));
        // subsystem matches but devtype differs
        assert!(!device_is_subsystem_devtype(
            true,
            Some("partition"),
            Some("disk")
        ));
    }

    #[test]
    fn test_make_log_field() {
        assert_eq!(make_log_field("KEY", "value"), "KEY=value");
        assert_eq!(make_log_field("DEVNUM", "8:0"), "DEVNUM=8:0");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_format_devnum() {
        // Test with a known device number: major=8, minor=0 → (8 << 8) | 0 = 2048
        let devnum = (8u64 << 8) | 0;
        assert_eq!(format_devnum(devnum), "8:0");
    }

    #[test]
    fn test_devname_from_devnum_zero() {
        assert_eq!(
            devname_from_devnum(DeviceMode::Block, 0).unwrap(),
            INACCESSIBLE_DEVICE_PATH
        );
    }

    #[test]
    fn test_constants() {
        assert_eq!(DEFAULT_SEAT, "seat0");
        assert_eq!(INACCESSIBLE_DEVICE_PATH, "/dev/inaccessible");
        assert_eq!(SYSFS_DEV_PATH, "/dev");
    }

    #[test]
    fn test_is_block_device_nonexistent() {
        assert!(is_block_device("/nonexistent/path/to/block/dev").is_err());
    }

    #[test]
    fn test_is_char_device_nonexistent() {
        assert!(is_char_device("/nonexistent/path/to/char/dev").is_err());
    }

    #[test]
    fn test_is_device_nonexistent() {
        assert!(is_device("/nonexistent/path/to/device").is_err());
    }

    #[test]
    fn test_device_get_seat_nonexistent() {
        // Non-existent path → uevent not readable → default seat
        assert_eq!(
            device_get_seat(Path::new("/nonexistent/device")).unwrap(),
            DEFAULT_SEAT
        );
    }

    #[test]
    fn test_device_in_subsystem_nonexistent() {
        assert!(device_in_subsystem(Path::new("/nonexistent/device"), "block").is_err());
    }
}
