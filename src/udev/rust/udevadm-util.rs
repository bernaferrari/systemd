// SPDX-License-Identifier: GPL-2.0-or-later
//
// PORT-SYNC: src/udev/udevadm-util.c, src/udev/udevadm-util.h
//
// Shared utilities for udevadm subcommands.
//
// Provides device-finding logic, action / resolve-name parsing,
// key-value argument parsing, and rules-file search path handling.

// ── Resolve name timing ──────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolveNameTiming {
    Early,
    Late,
    Never,
}

impl ResolveNameTiming {
    pub fn to_str(self) -> &'static str {
        match self {
            ResolveNameTiming::Early => "early",
            ResolveNameTiming::Late => "late",
            ResolveNameTiming::Never => "never",
        }
    }
}

impl std::str::FromStr for ResolveNameTiming {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "early" => Ok(ResolveNameTiming::Early),
            "late" => Ok(ResolveNameTiming::Late),
            "never" => Ok(ResolveNameTiming::Never),
            _ => Err(()),
        }
    }
}

// ── Device action ─────────────────────────────────────────────────────────

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
    pub fn to_str(self) -> &'static str {
        match self {
            DeviceAction::Add => "add",
            DeviceAction::Remove => "remove",
            DeviceAction::Change => "change",
            DeviceAction::Move => "move",
            DeviceAction::Online => "online",
            DeviceAction::Offline => "offline",
            DeviceAction::Bind => "bind",
            DeviceAction::Unbind => "unbind",
        }
    }

    pub fn all() -> &'static [DeviceAction] {
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

impl std::str::FromStr for DeviceAction {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "add" => Ok(DeviceAction::Add),
            "remove" => Ok(DeviceAction::Remove),
            "change" => Ok(DeviceAction::Change),
            "move" => Ok(DeviceAction::Move),
            "online" => Ok(DeviceAction::Online),
            "offline" => Ok(DeviceAction::Offline),
            "bind" => Ok(DeviceAction::Bind),
            "unbind" => Ok(DeviceAction::Unbind),
            _ => Err(()),
        }
    }
}

// ── Error type ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UtilError {
    InvalidAction(String),
    InvalidResolveName(String),
    InvalidKeyValue(String),
    InvalidKeyName(String),
    DeviceNotFound(String),
    PathNotFound(String),
    NotDeviceUnit(String),
    NotValidUnit(String),
    NoConnection(String),
    PingFailed(String),
    RulesSearchFailed(String),
}

impl std::fmt::Display for UtilError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UtilError::InvalidAction(s) => write!(f, "Invalid action '{s}'"),
            UtilError::InvalidResolveName(s) => {
                write!(
                    f,
                    "--resolve-names= must be early, late, or never. Got: {s}"
                )
            }
            UtilError::InvalidKeyValue(s) => {
                write!(f, "Failed to parse key/value pair '{s}'")
            }
            UtilError::InvalidKeyName(k) => {
                write!(f, "'{k}' is not a valid key name")
            }
            UtilError::DeviceNotFound(id) => {
                write!(f, "Failed to open device '{id}'")
            }
            UtilError::PathNotFound(p) => write!(f, "Path not found: {p}"),
            UtilError::NotDeviceUnit(u) => {
                write!(f, "'{u}' is not a .device unit")
            }
            UtilError::NotValidUnit(u) => {
                write!(f, "'{u}' is not a valid unit name")
            }
            UtilError::NoConnection(msg) => {
                write!(f, "No connection: {msg}")
            }
            UtilError::PingFailed(msg) => write!(f, "Ping failed: {msg}"),
            UtilError::RulesSearchFailed(msg) => {
                write!(f, "Rules search failed: {msg}")
            }
        }
    }
}

impl std::error::Error for UtilError {}

// ── Parse helpers ─────────────────────────────────────────────────────────

/// Parse a device action string. Returns `help` mode if the string is "help".
/// Mirrors `parse_device_action()`.
pub fn parse_device_action(s: &str) -> Result<DeviceAction, UtilError> {
    s.parse()
        .map_err(|()| UtilError::InvalidAction(s.to_string()))
}

/// Parse a resolve-name timing string.
/// Mirrors `parse_resolve_name_timing()`.
pub fn parse_resolve_name_timing(s: &str) -> Result<ResolveNameTiming, UtilError> {
    s.parse()
        .map_err(|()| UtilError::InvalidResolveName(s.to_string()))
}

/// Parse a KEY=VALUE argument, optionally requiring the value.
/// Mirrors `parse_key_value_argument()`.
pub fn parse_key_value_argument(
    s: &str,
    require_value: bool,
) -> Result<(String, String), UtilError> {
    if let Some(eq) = s.find('=') {
        let key = &s[..eq];
        let value = &s[eq + 1..];
        if !is_valid_filename(key) {
            return Err(UtilError::InvalidKeyName(key.to_string()));
        }
        Ok((key.to_string(), value.to_string()))
    } else {
        if require_value {
            return Err(UtilError::InvalidKeyValue(format!(
                "Missing '=' in key/value pair {s}"
            )));
        }
        if !is_valid_filename(s) {
            return Err(UtilError::InvalidKeyName(s.to_string()));
        }
        Ok((s.to_string(), String::new()))
    }
}

// ── Path utilities ────────────────────────────────────────────────────────

/// Determine whether a string looks like a filesystem path.
pub fn is_path(s: &str) -> bool {
    s.starts_with('/')
}

/// Check whether `id` starts with `prefix`; if not, prepend it.
pub fn maybe_prefix(id: &str, prefix: Option<&str>) -> String {
    match prefix {
        Some(p) if !id.starts_with(p) => format!("{p}{id}"),
        _ => id.to_string(),
    }
}

/// Join a prefix and a path component.
pub fn path_join(prefix: &str, suffix: &str) -> String {
    let suffix = suffix.strip_prefix('/').unwrap_or(suffix);
    format!("{prefix}/{suffix}")
}

// ── Filename validation ──────────────────────────────────────────────────

/// Check if a string is a valid filename (non-empty, no '/' or NUL).
/// Mirrors `filename_is_valid()`.
pub fn is_valid_filename(s: &str) -> bool {
    !s.is_empty() && !s.contains('/') && !s.contains('\0') && s != "." && s != ".."
}

// ── Device unit name handling ─────────────────────────────────────────────

/// Check if a string looks like a systemd device unit name (.device suffix).
pub fn is_device_unit_name(s: &str) -> bool {
    s.ends_with(".device")
}

/// Convert a unit name like `sys-devices-block-sda.device` to a syspath.
/// The conversion replaces `-` with `/` and strips the `.device` suffix,
/// then prepends `/`.
pub fn unit_name_to_syspath(unit_name: &str) -> Option<String> {
    let stripped = unit_name.strip_suffix(".device")?;
    if !stripped.starts_with("sys-") && !stripped.starts_with("dev-") {
        return None;
    }
    let path = stripped.replace('-', "/");
    Some(format!("/{path}"))
}

// ── Device finding ────────────────────────────────────────────────────────

/// Resolution strategy for a device identifier.
/// Mirrors the fallback chain in `find_device()`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceIdKind {
    DeviceId,
    Syspath,
    Devpath,
    UnitName,
    Unknown,
}

/// Classify a device identifier string.
pub fn classify_device_id(id: &str) -> DeviceIdKind {
    if id.starts_with("/sys/") {
        DeviceIdKind::Syspath
    } else if id.starts_with("/dev/") {
        DeviceIdKind::Devpath
    } else if is_device_unit_name(id) {
        DeviceIdKind::UnitName
    } else if id.contains('/') {
        DeviceIdKind::Unknown
    } else {
        DeviceIdKind::DeviceId
    }
}

/// Attempt to resolve a device identifier to a syspath.
/// Mirrors the fallback chain: device-id → direct-path → prefixed-path → unit-name.
pub fn resolve_device_syspath(id: &str, prefix: Option<&str>) -> Result<String, UtilError> {
    let kind = classify_device_id(id);
    match kind {
        DeviceIdKind::Syspath => Ok(id.to_string()),
        DeviceIdKind::Devpath => Ok(id.to_string()),
        DeviceIdKind::UnitName => {
            unit_name_to_syspath(id).ok_or_else(|| UtilError::NotDeviceUnit(id.to_string()))
        }
        DeviceIdKind::DeviceId => {
            let prefixed = maybe_prefix(id, prefix);
            if is_path(&prefixed) {
                Ok(prefixed)
            } else {
                Err(UtilError::DeviceNotFound(id.to_string()))
            }
        }
        DeviceIdKind::Unknown => {
            if is_path(id) {
                Err(UtilError::PathNotFound(id.to_string()))
            } else {
                Err(UtilError::DeviceNotFound(id.to_string()))
            }
        }
    }
}

// ── Rules search ──────────────────────────────────────────────────────────

pub const DEFAULT_RULES_DIRS: &[&str] = &[
    "/etc/udev/rules.d",
    "/run/udev/rules.d",
    "/usr/local/lib/udev/rules.d",
    "/usr/lib/udev/rules.d",
    "/lib/udev/rules.d",
];

pub const RULES_SUFFIX: &str = ".rules";

/// Ensure a rules file name ends with `.rules`.
pub fn ensure_rules_suffix(name: &str) -> String {
    if name.ends_with(RULES_SUFFIX) {
        name.to_string()
    } else {
        format!("{name}{RULES_SUFFIX}")
    }
}

/// Check whether a name is a plain filename (not a path) suitable for
/// searching in conf dirs.
pub fn is_plain_rules_name(s: &str) -> bool {
    !s.is_empty() && !s.contains('/') && is_valid_filename(&ensure_rules_suffix(s))
}

// ── Ping ──────────────────────────────────────────────────────────────────

pub const DEFAULT_PING_TIMEOUT_USEC: u64 = 5_000_000;

/// Ping result: whether the udev daemon replied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PingResult {
    NoDaemon,
    Ignored,
    Reply,
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_name_roundtrip() {
        for s in &["early", "late", "never"] {
            let timing: ResolveNameTiming = s.parse().unwrap();
            assert_eq!(timing.to_str(), *s);
        }
        assert!("sometimes".parse::<ResolveNameTiming>().is_err());
    }

    #[test]
    fn test_device_action_roundtrip() {
        for action in DeviceAction::all() {
            assert_eq!(action.to_str().parse(), Ok(*action));
        }
        assert!("explode".parse::<DeviceAction>().is_err());
    }

    #[test]
    fn test_parse_device_action_ok() {
        assert!(parse_device_action("add").is_ok());
        assert!(parse_device_action("change").is_ok());
    }

    #[test]
    fn test_parse_device_action_err() {
        assert!(parse_device_action("bad").is_err());
    }

    #[test]
    fn test_parse_key_value_with_eq() {
        let (k, v) = parse_key_value_argument("KEY=value", false).unwrap();
        assert_eq!(k, "KEY");
        assert_eq!(v, "value");
    }

    #[test]
    fn test_parse_key_value_no_eq_no_require() {
        let (k, v) = parse_key_value_argument("KEY", false).unwrap();
        assert_eq!(k, "KEY");
        assert_eq!(v, "");
    }

    #[test]
    fn test_parse_key_value_no_eq_require() {
        assert!(parse_key_value_argument("KEY", true).is_err());
    }

    #[test]
    fn test_parse_key_value_invalid_key() {
        assert!(parse_key_value_argument("bad/key=val", false).is_err());
    }

    #[test]
    fn test_is_path() {
        assert!(is_path("/sys/devices"));
        assert!(is_path("/dev/sda"));
        assert!(!is_path("sda"));
        assert!(!is_path(""));
    }

    #[test]
    fn test_maybe_prefix() {
        assert_eq!(maybe_prefix("sda", Some("/dev/")), "/dev/sda");
        assert_eq!(maybe_prefix("/dev/sda", Some("/dev/")), "/dev/sda");
        assert_eq!(maybe_prefix("sda", None), "sda");
    }

    #[test]
    fn test_path_join() {
        assert_eq!(path_join("/sys", "block/sda"), "/sys/block/sda");
        assert_eq!(path_join("/sys", "/block/sda"), "/sys/block/sda");
    }

    #[test]
    fn test_is_valid_filename() {
        assert!(is_valid_filename("99-systemd.rules"));
        assert!(!is_valid_filename(""));
        assert!(!is_valid_filename("has/slash"));
        assert!(!is_valid_filename("has\0null"));
        assert!(!is_valid_filename("."));
        assert!(!is_valid_filename(".."));
    }

    #[test]
    fn test_classify_device_id() {
        assert_eq!(classify_device_id("/sys/block/sda"), DeviceIdKind::Syspath);
        assert_eq!(classify_device_id("/dev/sda"), DeviceIdKind::Devpath);
        assert_eq!(
            classify_device_id("sys-devices-block-sda.device"),
            DeviceIdKind::UnitName
        );
        assert_eq!(classify_device_id("n1"), DeviceIdKind::DeviceId);
    }

    #[test]
    fn test_ensure_rules_suffix() {
        assert_eq!(ensure_rules_suffix("99-systemd"), "99-systemd.rules");
        assert_eq!(ensure_rules_suffix("99-systemd.rules"), "99-systemd.rules");
    }

    #[test]
    fn test_is_plain_rules_name() {
        assert!(is_plain_rules_name("99-systemd"));
        assert!(!is_plain_rules_name("/etc/udev/99.rules"));
        assert!(!is_plain_rules_name(""));
    }

    #[test]
    fn test_unit_name_to_syspath() {
        let result = unit_name_to_syspath("sys-devices-block-sda.device");
        assert_eq!(result, Some("/sys/devices/block/sda".to_string()));
        assert!(unit_name_to_syspath("not-a-device").is_none());
    }
}
