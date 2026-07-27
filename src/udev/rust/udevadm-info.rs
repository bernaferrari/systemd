// SPDX-License-Identifier: GPL-2.0-or-later
//
// PORT-SYNC: src/udev/udevadm-info.c
//
// udevadm info — query device information from sysfs or the udev database.
//
// Defines action types, query types, attribute filtering, sysattr sorting,
// device record formatting, and argument validation for the info subcommand.

// ── Constants ─────────────────────────────────────────────────────────────

/// Maximum depth for tree traversal to avoid stack exhaustion.
pub const TREE_DEPTH_MAX: u32 = 64;

// ── Action type ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActionType {
    Query,
    AttributeWalk,
    DeviceIdFile,
    Tree,
    Export,
    CleanupDb,
}

impl ActionType {
    pub fn from_char(c: char) -> Option<ActionType> {
        match c {
            'q' => Some(ActionType::Query),
            'a' => Some(ActionType::AttributeWalk),
            'd' => Some(ActionType::DeviceIdFile),
            't' => Some(ActionType::Tree),
            'e' => Some(ActionType::Export),
            'c' => Some(ActionType::CleanupDb),
            _ => None,
        }
    }
}

// ── Query type ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueryType {
    Name,
    Path,
    Symlink,
    Property,
    All,
}

impl QueryType {
    pub fn from_string(s: &str) -> Option<QueryType> {
        match s {
            "name" => Some(QueryType::Name),
            "path" => Some(QueryType::Path),
            "symlink" => Some(QueryType::Symlink),
            "property" | "env" => Some(QueryType::Property),
            "all" => Some(QueryType::All),
            _ => None,
        }
    }

    pub fn to_string_val(self) -> &'static str {
        match self {
            QueryType::Name => "name",
            QueryType::Path => "path",
            QueryType::Symlink => "symlink",
            QueryType::Property => "property",
            QueryType::All => "all",
        }
    }

    pub fn all_values() -> &'static [QueryType] {
        &[
            QueryType::Name,
            QueryType::Path,
            QueryType::Symlink,
            QueryType::Property,
            QueryType::All,
        ]
    }
}

// ── Attribute filtering ───────────────────────────────────────────────────

/// Attributes that are either displayed separately or hidden entirely.
/// Mirrors `skip_attribute()` in C.
pub const SKIPPED_ATTRIBUTES: &[&str] = &[
    "uevent",
    "dev",
    "modalias",
    "resource",
    "driver",
    "subsystem",
    "module",
];

/// Returns true if the attribute should be skipped during display.
pub fn skip_attribute(name: &str) -> bool {
    SKIPPED_ATTRIBUTES.contains(&name)
}

// ── Sysattr sorting ───────────────────────────────────────────────────────

/// A sysattr name-value pair for sorted display.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SysAttr {
    pub name: String,
    pub value: String,
}

/// Compare two sysattrs by name for sorting.
pub fn sysattr_compare(a: &SysAttr, b: &SysAttr) -> std::cmp::Ordering {
    a.name.cmp(&b.name)
}

// ── Print formatting helpers ──────────────────────────────────────────────

/// Prefix used for parent vs. current device attributes in attribute walk.
pub fn attr_key_prefix(is_parent: bool) -> &'static str {
    if is_parent {
        "ATTRS"
    } else {
        "ATTR"
    }
}

pub fn kernel_key_prefix(is_parent: bool) -> &'static str {
    if is_parent {
        "KERNELS"
    } else {
        "KERNEL"
    }
}

pub fn subsystem_key_prefix(is_parent: bool) -> &'static str {
    if is_parent {
        "SUBSYSTEMS"
    } else {
        "SUBSYSTEM"
    }
}

pub fn driver_key_prefix(is_parent: bool) -> &'static str {
    if is_parent {
        "DRIVERS"
    } else {
        "DRIVER"
    }
}

// ── Record field formatting ───────────────────────────────────────────────

/// Format a dev_t as major:minor string.
pub fn format_devnum(major: u32, minor: u32) -> String {
    format!("{major}:{minor}")
}

/// Determine the device type character ('b' for block, 'c' for character).
pub fn device_type_char(subsystem: Option<&str>) -> char {
    match subsystem {
        Some("block") => 'b',
        _ => 'c',
    }
}

// ── Device path normalization ─────────────────────────────────────────────

/// Normalize a device path argument. If the path already starts with the
/// expected prefix, keep it; otherwise prepend the prefix.
/// Mirrors the path handling in the C parse_argv() for -n/-p options.
pub fn normalize_device_path(arg: &str, prefix: &str) -> String {
    if arg.starts_with(prefix) {
        arg.to_string()
    } else {
        format!("{prefix}{arg}")
    }
}

// ── Validation ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InfoParseError {
    HelpRequested,
    VersionRequested,
    DevicesNotAllowedWithAction,
    DeviceRequired,
    OnlyOneDeviceAllowed,
    ExportWithValueConflict,
    UnknownQueryType(String),
    InvalidOption(String),
}

impl std::fmt::Display for InfoParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InfoParseError::HelpRequested => write!(f, "help requested"),
            InfoParseError::VersionRequested => write!(f, "version requested"),
            InfoParseError::DevicesNotAllowedWithAction => {
                write!(
                    f,
                    "Devices are not allowed with -d/--device-id-of-file and -c/--cleanup-db."
                )
            }
            InfoParseError::DeviceRequired => {
                write!(f, "A device name or path is required")
            }
            InfoParseError::OnlyOneDeviceAllowed => {
                write!(
                    f,
                    "Only one device may be specified with -a/--attribute-walk and -t/--tree"
                )
            }
            InfoParseError::ExportWithValueConflict => {
                write!(
                    f,
                    "-x/--export or -P/--export-prefix cannot be used with --value"
                )
            }
            InfoParseError::UnknownQueryType(q) => {
                write!(f, "Unknown query type '{q}'")
            }
            InfoParseError::InvalidOption(opt) => write!(f, "Invalid option: {opt}"),
        }
    }
}

impl std::error::Error for InfoParseError {}

/// Check whether a device path argument starts with /dev/ or /sys/.
pub fn is_device_path(arg: &str) -> bool {
    arg.starts_with("/dev/") || arg.starts_with("/sys/")
}

/// Strip /dev/ prefix from a device node path.
pub fn strip_dev_prefix(path: &str) -> Option<&str> {
    path.strip_prefix("/dev/")
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::cmp::Ordering;

    #[test]
    fn test_skip_attribute_skipped() {
        assert!(skip_attribute("uevent"));
        assert!(skip_attribute("dev"));
        assert!(skip_attribute("modalias"));
        assert!(skip_attribute("resource"));
        assert!(skip_attribute("driver"));
        assert!(skip_attribute("subsystem"));
        assert!(skip_attribute("module"));
    }

    #[test]
    fn test_skip_attribute_not_skipped() {
        assert!(!skip_attribute("vendor"));
        assert!(!skip_attribute("idVendor"));
        assert!(!skip_attribute("size"));
        assert!(!skip_attribute(""));
    }

    #[test]
    fn test_query_type_roundtrip() {
        for q in QueryType::all_values() {
            assert_eq!(QueryType::from_string(q.to_string_val()), Some(*q));
        }
    }

    #[test]
    fn test_query_type_env_alias() {
        assert_eq!(QueryType::from_string("env"), Some(QueryType::Property));
    }

    #[test]
    fn test_query_type_unknown() {
        assert_eq!(QueryType::from_string("unknown"), None);
    }

    #[test]
    fn test_sysattr_compare() {
        let a = SysAttr {
            name: "aaa".into(),
            value: "1".into(),
        };
        let b = SysAttr {
            name: "bbb".into(),
            value: "2".into(),
        };
        assert_eq!(sysattr_compare(&a, &b), Ordering::Less);
        assert_eq!(sysattr_compare(&b, &a), Ordering::Greater);
        assert_eq!(sysattr_compare(&a, &a), Ordering::Equal);
    }

    #[test]
    fn test_key_prefixes() {
        assert_eq!(attr_key_prefix(false), "ATTR");
        assert_eq!(attr_key_prefix(true), "ATTRS");
        assert_eq!(kernel_key_prefix(false), "KERNEL");
        assert_eq!(kernel_key_prefix(true), "KERNELS");
        assert_eq!(subsystem_key_prefix(false), "SUBSYSTEM");
        assert_eq!(subsystem_key_prefix(true), "SUBSYSTEMS");
        assert_eq!(driver_key_prefix(false), "DRIVER");
        assert_eq!(driver_key_prefix(true), "DRIVERS");
    }

    #[test]
    fn test_format_devnum() {
        assert_eq!(format_devnum(8, 0), "8:0");
        assert_eq!(format_devnum(0, 0), "0:0");
        assert_eq!(format_devnum(252, 1), "252:1");
    }

    #[test]
    fn test_device_type_char() {
        assert_eq!(device_type_char(Some("block")), 'b');
        assert_eq!(device_type_char(Some("net")), 'c');
        assert_eq!(device_type_char(None), 'c');
    }

    #[test]
    fn test_normalize_device_path() {
        assert_eq!(normalize_device_path("sda", "/dev/"), "/dev/sda");
        assert_eq!(normalize_device_path("/dev/sda", "/dev/"), "/dev/sda");
        assert_eq!(
            normalize_device_path("/sys/block/sda", "/sys/"),
            "/sys/block/sda"
        );
        assert_eq!(
            normalize_device_path("block/sda", "/sys/"),
            "/sys/block/sda"
        );
    }

    #[test]
    fn test_is_device_path() {
        assert!(is_device_path("/dev/sda"));
        assert!(is_device_path("/sys/block/sda"));
        assert!(!is_device_path("sda"));
        assert!(!is_device_path("/run/udev"));
    }

    #[test]
    fn test_strip_dev_prefix() {
        assert_eq!(strip_dev_prefix("/dev/sda"), Some("sda"));
        assert_eq!(strip_dev_prefix("/dev/null"), Some("null"));
        assert_eq!(strip_dev_prefix("/sys/block/sda"), None);
        assert_eq!(strip_dev_prefix("sda"), None);
    }
}
