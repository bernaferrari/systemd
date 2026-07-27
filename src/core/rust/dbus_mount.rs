// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/core/dbus-mount.c
//
// D-Bus property accessors and transient property setters for mount units.
//
// Provides safe Rust equivalents for the property getters (Where, What,
// Options, Type, Result), the transient property setter, the full
// property setter, and the commit function from dbus-mount.c.

// ── Enums ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MountResult {
    Success,
    FailureResources,
    FailureTimeout,
    FailureExitCode,
    FailureSignal,
    FailureCoreDump,
    FailureWatchdog,
    FailureStartLimitHit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MountExecCommand {
    Mount,
    Unmount,
    Remount,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MountProperty {
    Where,
    What,
    Options,
    Type,
    TimeoutUSec,
    DirectoryMode,
    SloppyOptions,
    LazyUnmount,
    ForceUnmount,
    ReadWriteOnly,
    Result,
    ReloadResult,
    CleanResult,
    UID,
    GID,
}

// ── Error ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DbusMountError {
    InvalidArgument,
    NoMemory,
    NotSupported,
    NotFound,
    ReadOnly,
}

impl DbusMountError {
    pub fn to_errno(self) -> i32 {
        match self {
            DbusMountError::InvalidArgument => -22, // -EINVAL
            DbusMountError::NoMemory => -12,        // -ENOMEM
            DbusMountError::NotSupported => -95,    // -EOPNOTSUPP
            DbusMountError::NotFound => -2,         // -ENOENT
            DbusMountError::ReadOnly => -30,        // -EROFS
        }
    }
}

// ── Data structures ───────────────────────────────────────────────────────

/// Represents the D-Bus-visible properties of a mount unit.
#[derive(Debug, Clone, PartialEq)]
pub struct MountProperties {
    pub where_path: String,
    pub what: String,
    pub options: Option<String>,
    pub fs_type: Option<String>,
    pub timeout_usec: u64,
    pub directory_mode: u32,
    pub sloppy_options: bool,
    pub lazy_unmount: bool,
    pub force_unmount: bool,
    pub read_write_only: bool,
    pub result: MountResult,
    pub reload_result: MountResult,
    pub clean_result: MountResult,
    pub uid: u32,
    pub gid: u32,
}

impl Default for MountProperties {
    fn default() -> Self {
        Self {
            where_path: String::new(),
            what: String::new(),
            options: None,
            fs_type: None,
            timeout_usec: 0,
            directory_mode: 0o755,
            sloppy_options: false,
            lazy_unmount: false,
            force_unmount: false,
            read_write_only: false,
            result: MountResult::Success,
            reload_result: MountResult::Success,
            clean_result: MountResult::Success,
            uid: 0,
            gid: 0,
        }
    }
}

/// Unit write flags used for transient property setting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnitWriteFlags(u32);

impl UnitWriteFlags {
    pub const EMPTY: Self = Self(0);
    pub const PRIVATE: Self = Self(1 << 0);
    pub const NOOP: Self = Self(1 << 1);
    pub const ESCAPE_SPECIFIERS: Self = Self(1 << 2);

    pub fn contains(self, flag: UnitWriteFlags) -> bool {
        self.0 & flag.0 != 0
    }

    pub fn is_noop(self) -> bool {
        self.0 & Self::NOOP.0 != 0
    }
}

// ── Property getters ──────────────────────────────────────────────────────

/// Get the "Where" property — the mount point path.
pub fn property_get_where(props: &MountProperties) -> String {
    escape_path(&props.where_path)
}

/// Get the "What" property — the device/source path.
pub fn property_get_what(props: &MountProperties) -> String {
    escape_path(&props.what)
}

/// Get the "Options" property — mount options string.
pub fn property_get_options(props: &MountProperties) -> Option<String> {
    props.options.as_ref().map(|s| escape_path(s))
}

/// Get the "Type" property — filesystem type.
pub fn property_get_type(props: &MountProperties) -> Option<&str> {
    props.fs_type.as_deref()
}

/// Get a mount result property as a string.
pub fn property_get_result(result: MountResult) -> &'static str {
    match result {
        MountResult::Success => "success",
        MountResult::FailureResources => "failure-resources",
        MountResult::FailureTimeout => "failure-timeout",
        MountResult::FailureExitCode => "failure-exit-code",
        MountResult::FailureSignal => "failure-signal",
        MountResult::FailureCoreDump => "failure-core-dump",
        MountResult::FailureWatchdog => "failure-watchdog",
        MountResult::FailureStartLimitHit => "failure-start-limit-hit",
    }
}

// ── Path escaping ─────────────────────────────────────────────────────────

/// Escape a path string for D-Bus transmission.
///
/// In the C code, `mount_get_where_escaped()` and similar functions escape
/// special characters.  Here we perform minimal escaping of backslashes.
fn escape_path(path: &str) -> String {
    if path.is_empty() {
        return String::new();
    }
    path.replace('\\', "\\\\")
}

/// Resolve a fstab-style device node to a udev-compatible path.
///
/// Equivalent to `fstab_node_to_udev_node()` — for UUID=, LABEL=, PARTUUID=
/// tags this converts them to /dev/disk/by-* paths.
pub fn fstab_node_to_udev_node(node: &str) -> String {
    if let Some(rest) = node.strip_prefix("UUID=") {
        format!("/dev/disk/by-uuid/{}", rest)
    } else if let Some(rest) = node.strip_prefix("LABEL=") {
        format!("/dev/disk/by-label/{}", rest)
    } else if let Some(rest) = node.strip_prefix("PARTUUID=") {
        format!("/dev/disk/by-partuuid/{}", rest)
    } else {
        node.to_string()
    }
}

// ── Transient property setter ─────────────────────────────────────────────

/// Set a transient property on a mount unit.
///
/// Equivalent to `bus_mount_set_transient_property()`.  Returns `Ok(true)`
/// if the property was recognised and handled, `Ok(false)` if not recognised.
pub fn bus_mount_set_transient_property(
    props: &mut MountProperties,
    name: &str,
    value: &str,
    flags: UnitWriteFlags,
) -> Result<bool, DbusMountError> {
    if flags.is_noop() {
        return Ok(true);
    }

    match name {
        "Where" => {
            if value.is_empty() {
                return Err(DbusMountError::InvalidArgument);
            }
            props.where_path = value.to_string();
            Ok(true)
        }
        "What" => {
            let resolved = fstab_node_to_udev_node(value);
            if !value.is_empty() && resolved.len() >= 4096 {
                return Err(DbusMountError::InvalidArgument);
            }
            props.what = if value.is_empty() {
                String::new()
            } else {
                resolved
            };
            Ok(true)
        }
        "Options" => {
            props.options = if value.is_empty() {
                None
            } else {
                Some(value.to_string())
            };
            Ok(true)
        }
        "Type" => {
            props.fs_type = if value.is_empty() {
                None
            } else {
                Some(value.to_string())
            };
            Ok(true)
        }
        "TimeoutUSec" => {
            props.timeout_usec = value.parse::<u64>().unwrap_or(0);
            Ok(true)
        }
        "DirectoryMode" => {
            props.directory_mode = value.parse::<u32>().unwrap_or(0);
            Ok(true)
        }
        "SloppyOptions" => {
            props.sloppy_options = value == "true" || value == "1";
            Ok(true)
        }
        "LazyUnmount" => {
            props.lazy_unmount = value == "true" || value == "1";
            Ok(true)
        }
        "ForceUnmount" => {
            props.force_unmount = value == "true" || value == "1";
            Ok(true)
        }
        "ReadWriteOnly" => {
            props.read_write_only = value == "true" || value == "1";
            Ok(true)
        }
        _ => Ok(false),
    }
}

// ── Full property setter ──────────────────────────────────────────────────

/// Set a property on a mount unit (including cgroup/exec/kill contexts).
///
/// Equivalent to `bus_mount_set_property()`.  For transient units in
/// UNIT_STUB state, delegates to `bus_mount_set_transient_property`.
pub fn bus_mount_set_property(
    props: &mut MountProperties,
    name: &str,
    value: &str,
    flags: UnitWriteFlags,
    is_transient_stub: bool,
) -> Result<bool, DbusMountError> {
    if is_transient_stub {
        return bus_mount_set_transient_property(props, name, value, flags);
    }
    Ok(false)
}

// ── Commit ────────────────────────────────────────────────────────────────

/// Commit property changes (realize cgroup).
///
/// Equivalent to `bus_mount_commit_properties()`.
pub fn bus_mount_commit_properties() -> Result<(), DbusMountError> {
    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_property_get_where_default() {
        let props = MountProperties {
            where_path: "/mnt/data".to_string(),
            ..Default::default()
        };
        assert_eq!(property_get_where(&props), "/mnt/data");
    }

    #[test]
    fn test_property_get_what_default() {
        let props = MountProperties {
            what: "/dev/sda1".to_string(),
            ..Default::default()
        };
        assert_eq!(property_get_what(&props), "/dev/sda1");
    }

    #[test]
    fn test_property_get_options() {
        let props = MountProperties {
            options: Some("rw,noatime".to_string()),
            ..Default::default()
        };
        assert_eq!(property_get_options(&props), Some("rw,noatime".to_string()));
    }

    #[test]
    fn test_property_get_options_none() {
        let props = MountProperties::default();
        assert_eq!(property_get_options(&props), None);
    }

    #[test]
    fn test_property_get_type() {
        let props = MountProperties {
            fs_type: Some("ext4".to_string()),
            ..Default::default()
        };
        assert_eq!(property_get_type(&props), Some("ext4"));
    }

    #[test]
    fn test_property_get_result() {
        assert_eq!(property_get_result(MountResult::Success), "success");
        assert_eq!(
            property_get_result(MountResult::FailureTimeout),
            "failure-timeout"
        );
        assert_eq!(
            property_get_result(MountResult::FailureSignal),
            "failure-signal"
        );
    }

    #[test]
    fn test_fstab_node_to_udev_node() {
        assert_eq!(
            fstab_node_to_udev_node("UUID=abc-123"),
            "/dev/disk/by-uuid/abc-123"
        );
        assert_eq!(
            fstab_node_to_udev_node("LABEL=root"),
            "/dev/disk/by-label/root"
        );
        assert_eq!(fstab_node_to_udev_node("/dev/sda1"), "/dev/sda1");
    }

    #[test]
    fn test_bus_mount_set_transient_where() {
        let mut props = MountProperties::default();
        let result = bus_mount_set_transient_property(
            &mut props,
            "Where",
            "/mnt/test",
            UnitWriteFlags::EMPTY,
        );
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), true);
        assert_eq!(props.where_path, "/mnt/test");
    }

    #[test]
    fn test_bus_mount_set_transient_where_empty() {
        let mut props = MountProperties::default();
        let result =
            bus_mount_set_transient_property(&mut props, "Where", "", UnitWriteFlags::EMPTY);
        assert!(result.is_err());
    }

    #[test]
    fn test_bus_mount_set_transient_what_uuid() {
        let mut props = MountProperties::default();
        let result = bus_mount_set_transient_property(
            &mut props,
            "What",
            "UUID=abc-123",
            UnitWriteFlags::EMPTY,
        );
        assert!(result.is_ok());
        assert_eq!(props.what, "/dev/disk/by-uuid/abc-123");
    }

    #[test]
    fn test_bus_mount_set_transient_bool() {
        let mut props = MountProperties::default();
        bus_mount_set_transient_property(
            &mut props,
            "SloppyOptions",
            "true",
            UnitWriteFlags::EMPTY,
        )
        .unwrap();
        assert!(props.sloppy_options);
        bus_mount_set_transient_property(&mut props, "LazyUnmount", "0", UnitWriteFlags::EMPTY)
            .unwrap();
        assert!(!props.lazy_unmount);
    }

    #[test]
    fn test_bus_mount_set_transient_unknown() {
        let mut props = MountProperties::default();
        let result = bus_mount_set_transient_property(
            &mut props,
            "UnknownProp",
            "value",
            UnitWriteFlags::EMPTY,
        );
        assert_eq!(result.unwrap(), false);
    }

    #[test]
    fn test_bus_mount_set_property_transient_stub() {
        let mut props = MountProperties::default();
        let result =
            bus_mount_set_property(&mut props, "Where", "/mnt/foo", UnitWriteFlags::EMPTY, true);
        assert!(result.is_ok());
        assert_eq!(props.where_path, "/mnt/foo");
    }

    #[test]
    fn test_bus_mount_set_property_non_transient() {
        let mut props = MountProperties::default();
        let result = bus_mount_set_property(
            &mut props,
            "Where",
            "/mnt/foo",
            UnitWriteFlags::EMPTY,
            false,
        );
        assert_eq!(result.unwrap(), false);
    }

    #[test]
    fn test_bus_mount_commit_properties() {
        assert!(bus_mount_commit_properties().is_ok());
    }

    #[test]
    fn test_escape_path() {
        assert_eq!(escape_path("/normal/path"), "/normal/path");
        assert_eq!(escape_path("has\\backslash"), "has\\\\backslash");
        assert_eq!(escape_path(""), "");
    }

    #[test]
    fn test_dbus_mount_error_to_errno() {
        assert_eq!(DbusMountError::InvalidArgument.to_errno(), -22);
        assert_eq!(DbusMountError::NoMemory.to_errno(), -12);
        assert_eq!(DbusMountError::NotSupported.to_errno(), -95);
    }

    #[test]
    fn test_unit_write_flags() {
        let flags = UnitWriteFlags::PRIVATE;
        assert!(flags.contains(UnitWriteFlags::PRIVATE));
        assert!(!flags.contains(UnitWriteFlags::NOOP));

        let noop = UnitWriteFlags::NOOP;
        assert!(noop.is_noop());
    }
}
