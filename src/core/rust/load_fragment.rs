// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/core/load-fragment.c

use std::fmt;

pub const SOURCE_PATH: &str = "src/core/load-fragment.c";
pub const DEFAULT_CONFIRM_CONSOLE: &str = "/dev/console";

pub type Result<T> = std::result::Result<T, LoadFragmentError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoadFragmentError {
    InvalidBoolean(String),
    InvalidInteger(String),
    UnsupportedSocketProtocol(String),
    InvalidUnitName(String),
    MissingFragmentPath,
}

impl fmt::Display for LoadFragmentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidBoolean(value) => write!(f, "invalid boolean: {value}"),
            Self::InvalidInteger(value) => write!(f, "invalid integer: {value}"),
            Self::UnsupportedSocketProtocol(value) => {
                write!(f, "unsupported socket protocol: {value}")
            }
            Self::InvalidUnitName(value) => write!(f, "invalid unit name: {value}"),
            Self::MissingFragmentPath => write!(f, "missing fragment path"),
        }
    }
}

impl std::error::Error for LoadFragmentError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketProtocol {
    UdpLite,
    Sctp,
    Mptcp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnitType {
    Service,
    Socket,
    Target,
    Mount,
    Timer,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnitIdentity {
    pub id: String,
    pub unit_type: UnitType,
    pub fragment_path: String,
}

pub fn parse_socket_protocol(value: &str) -> Result<SocketProtocol> {
    match value {
        "udplite" | "UDPLite" => Ok(SocketProtocol::UdpLite),
        "sctp" | "SCTP" => Ok(SocketProtocol::Sctp),
        "mptcp" | "MPTCP" => Ok(SocketProtocol::Mptcp),
        other => Err(LoadFragmentError::UnsupportedSocketProtocol(other.into())),
    }
}

pub fn parse_crash_chvt(value: &str) -> Result<i32> {
    if let Ok(parsed) = value.parse::<i32>() {
        return Ok(parsed);
    }

    match parse_boolean(value)? {
        true => Ok(0),
        false => Ok(-1),
    }
}

pub fn parse_confirm_spawn(value: Option<&str>) -> Result<Option<String>> {
    let Some(raw) = value else {
        return Ok(Some(DEFAULT_CONFIRM_CONSOLE.to_string()));
    };

    match parse_boolean(raw) {
        Ok(false) => Ok(None),
        Ok(true) => Ok(Some(DEFAULT_CONFIRM_CONSOLE.to_string())),
        Err(_) if is_path(raw) => Ok(Some(raw.to_string())),
        Err(_) => Ok(Some(format!("/dev/{raw}"))),
    }
}

pub fn contains_instance_specifier_superset(value: &str) -> bool {
    let Some(at) = value.find('@') else {
        return false;
    };

    let after_at = &value[at + 1..];
    let dot = after_at.rfind('.').unwrap_or(after_at.len());
    let template = &after_at[..dot];

    if template == "%i" {
        return false;
    }

    let mut percent = false;
    for ch in template.chars() {
        if ch == '%' {
            percent = !percent;
            continue;
        }

        if percent {
            if matches!(ch, 'i' | 'n' | 'N') {
                return true;
            }
            percent = false;
        }
    }

    false
}

pub fn unit_is_likely_recursive_template_dependency(
    unit: &UnitIdentity,
    rendered_name: &str,
    format: &str,
    rendered_fragment_path: &str,
) -> Result<bool> {
    if !unit_name_is_valid(rendered_name) {
        return Ok(false);
    }

    if unit.fragment_path.is_empty() || rendered_fragment_path.is_empty() {
        return Err(LoadFragmentError::MissingFragmentPath);
    }

    if !unit_name_prefix_equal(&unit.id, rendered_name) {
        return Ok(false);
    }

    if unit.unit_type != unit_name_to_type(rendered_name) {
        return Ok(false);
    }

    if unit.fragment_path != rendered_fragment_path {
        return Ok(false);
    }

    Ok(contains_instance_specifier_superset(format))
}

fn parse_boolean(value: &str) -> Result<bool> {
    match value {
        "1" | "yes" | "true" | "on" => Ok(true),
        "0" | "no" | "false" | "off" => Ok(false),
        other => Err(LoadFragmentError::InvalidBoolean(other.into())),
    }
}

fn is_path(value: &str) -> bool {
    value.starts_with('/')
}

fn unit_name_is_valid(value: &str) -> bool {
    let Some((prefix, suffix)) = value.rsplit_once('.') else {
        return false;
    };

    !prefix.is_empty() && !suffix.is_empty() && prefix.contains('@')
}

fn unit_name_prefix_equal(a: &str, b: &str) -> bool {
    unit_prefix(a) == unit_prefix(b)
}

fn unit_prefix(value: &str) -> &str {
    value.split('@').next().unwrap_or(value)
}

fn unit_name_to_type(value: &str) -> UnitType {
    match value.rsplit('.').next() {
        Some("service") => UnitType::Service,
        Some("socket") => UnitType::Socket,
        Some("target") => UnitType::Target,
        Some("mount") => UnitType::Mount,
        Some("timer") => UnitType::Timer,
        _ => UnitType::Other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_unit() -> UnitIdentity {
        UnitIdentity {
            id: "systemd-notify@.service".into(),
            unit_type: UnitType::Service,
            fragment_path: "/usr/lib/systemd/system/systemd-notify@.service".into(),
        }
    }

    #[test]
    fn parses_supported_socket_protocols() {
        assert_eq!(
            parse_socket_protocol("udplite"),
            Ok(SocketProtocol::UdpLite)
        );
        assert_eq!(parse_socket_protocol("sctp"), Ok(SocketProtocol::Sctp));
        assert_eq!(parse_socket_protocol("mptcp"), Ok(SocketProtocol::Mptcp));
    }

    #[test]
    fn rejects_unsupported_socket_protocol() {
        assert!(matches!(
            parse_socket_protocol("tcp"),
            Err(LoadFragmentError::UnsupportedSocketProtocol(_))
        ));
    }

    #[test]
    fn parses_crash_chvt_integer_and_boolean() {
        assert_eq!(parse_crash_chvt("7"), Ok(7));
        assert_eq!(parse_crash_chvt("yes"), Ok(0));
        assert_eq!(parse_crash_chvt("no"), Ok(-1));
    }

    #[test]
    fn parses_confirm_spawn_variants() {
        assert_eq!(parse_confirm_spawn(None), Ok(Some("/dev/console".into())));
        assert_eq!(parse_confirm_spawn(Some("false")), Ok(None));
        assert_eq!(
            parse_confirm_spawn(Some("ttyS0")),
            Ok(Some("/dev/ttyS0".into()))
        );
        assert_eq!(
            parse_confirm_spawn(Some("/dev/ttyUSB0")),
            Ok(Some("/dev/ttyUSB0".into()))
        );
    }

    #[test]
    fn detects_instance_specifier_supersets() {
        assert!(contains_instance_specifier_superset("foo@bar-%i.service"));
        assert!(contains_instance_specifier_superset("foo@%N-extra.service"));
        assert!(!contains_instance_specifier_superset("foo@%i.service"));
        assert!(!contains_instance_specifier_superset("foo.service"));
    }

    #[test]
    fn recursive_dependency_requires_matching_prefix() {
        let unit = sample_unit();
        assert_eq!(
            unit_is_likely_recursive_template_dependency(
                &unit,
                "other@instance.service",
                "systemd-notify@%n.service",
                "/usr/lib/systemd/system/systemd-notify@.service",
            ),
            Ok(false)
        );
    }

    #[test]
    fn recursive_dependency_requires_matching_fragment() {
        let unit = sample_unit();
        assert_eq!(
            unit_is_likely_recursive_template_dependency(
                &unit,
                "systemd-notify@foo.service",
                "systemd-notify@%n.service",
                "/etc/systemd/system/systemd-notify@foo.service",
            ),
            Ok(false)
        );
    }

    #[test]
    fn recursive_dependency_detects_superset_format() {
        let unit = sample_unit();
        assert_eq!(
            unit_is_likely_recursive_template_dependency(
                &unit,
                "systemd-notify@foo.service",
                "systemd-notify@%n.service",
                "/usr/lib/systemd/system/systemd-notify@.service",
            ),
            Ok(true)
        );
    }

    #[test]
    fn recursive_dependency_non_superset_is_safe() {
        let unit = sample_unit();
        assert_eq!(
            unit_is_likely_recursive_template_dependency(
                &unit,
                "systemd-notify@foo.service",
                "systemd-notify@%i.service",
                "/usr/lib/systemd/system/systemd-notify@.service",
            ),
            Ok(false)
        );
    }
}
