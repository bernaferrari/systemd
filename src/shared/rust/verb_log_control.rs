// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/verb-log-control.c
//
// Common log control verb handler (log-level / log-target via D-Bus).

use std::fmt;

use crate::ffi::Errno;

pub const LOG_CONTROL_PATH: &str = "/org/freedesktop/LogControl1";
pub const LOG_CONTROL_INTERFACE: &str = "org.freedesktop.LogControl1";

const LOG_LEVEL_PROPERTY: &str = "LogLevel";
const LOG_TARGET_PROPERTY: &str = "LogTarget";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LogControlKind {
    Level,
    Target,
}

impl LogControlKind {
    fn property_name(self) -> &'static str {
        match self {
            Self::Level => LOG_LEVEL_PROPERTY,
            Self::Target => LOG_TARGET_PROPERTY,
        }
    }

    fn display_name(self) -> &'static str {
        match self {
            Self::Level => "level",
            Self::Target => "target",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BusLocator<'a> {
    pub destination: &'a str,
    pub path: &'static str,
    pub interface: &'static str,
}

impl<'a> BusLocator<'a> {
    fn new(destination: &'a str) -> Self {
        Self {
            destination,
            path: LOG_CONTROL_PATH,
            interface: LOG_CONTROL_INTERFACE,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BusCallError {
    errno: i32,
    message: String,
}

impl BusCallError {
    pub fn new(errno: i32, message: impl Into<String>) -> Self {
        Self {
            errno: normalize_errno(errno),
            message: message.into(),
        }
    }

    pub fn errno(&self) -> i32 {
        self.errno
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerbLogControlError {
    InvalidVerb {
        verb: String,
    },
    InvalidLogLevel {
        value: String,
    },
    BusSet {
        kind: &'static str,
        destination: String,
        value: String,
        source: BusCallError,
    },
    BusGet {
        kind: &'static str,
        destination: String,
        source: BusCallError,
    },
}

impl VerbLogControlError {
    pub fn errno(&self) -> i32 {
        match self {
            Self::InvalidVerb { .. } | Self::InvalidLogLevel { .. } => Errno::EINVAL.to_neg_errno(),
            Self::BusSet { source, .. } | Self::BusGet { source, .. } => source.errno(),
        }
    }
}

impl fmt::Display for VerbLogControlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidVerb { verb } => {
                write!(f, "Unsupported log control verb: {verb}")
            }
            Self::InvalidLogLevel { value } => {
                write!(f, "\"{value}\" is not a valid log level.")
            }
            Self::BusSet {
                kind,
                destination,
                value,
                source,
            } => write!(
                f,
                "Failed to set log {kind} of {destination} to {value}: {}",
                source.message()
            ),
            Self::BusGet {
                kind,
                destination,
                source,
            } => write!(
                f,
                "Failed to get log {kind} of {destination}: {}",
                source.message()
            ),
        }
    }
}

impl std::error::Error for VerbLogControlError {}

pub trait LogControlBus {
    fn set_property_string(
        &mut self,
        locator: &BusLocator<'_>,
        property: &str,
        value: &str,
    ) -> Result<(), BusCallError>;

    fn get_property_string(
        &mut self,
        locator: &BusLocator<'_>,
        property: &str,
    ) -> Result<String, BusCallError>;
}

pub fn is_log_level_verb(verb: &str) -> bool {
    verb.ends_with("log-level")
}

pub fn is_log_target_verb(verb: &str) -> bool {
    verb.ends_with("log-target")
}

pub fn validate_verb(verb: &str) -> bool {
    is_log_level_verb(verb) || is_log_target_verb(verb)
}

pub fn log_control_property_name(verb: &str) -> Result<&'static str, VerbLogControlError> {
    Ok(parse_verb(verb)?.property_name())
}

pub fn log_level_from_string(value: &str) -> Result<i32, Errno> {
    match value {
        "emerg" => Ok(0),
        "alert" => Ok(1),
        "crit" => Ok(2),
        "err" => Ok(3),
        "warning" => Ok(4),
        "notice" => Ok(5),
        "info" => Ok(6),
        "debug" => Ok(7),
        _ => parse_numeric_log_level(value),
    }
}

pub fn log_level_to_string(level: i32) -> Option<&'static str> {
    match level {
        0 => Some("emerg"),
        1 => Some("alert"),
        2 => Some("crit"),
        3 => Some("err"),
        4 => Some("warning"),
        5 => Some("notice"),
        6 => Some("info"),
        7 => Some("debug"),
        _ => None,
    }
}

pub fn verb_log_control_common<B: LogControlBus>(
    bus: &mut B,
    destination: &str,
    verb: &str,
    value: Option<&str>,
) -> Result<Option<String>, VerbLogControlError> {
    let kind = parse_verb(verb)?;
    let locator = BusLocator::new(destination);

    if let Some(value) = value {
        if kind == LogControlKind::Level {
            log_level_from_string(value).map_err(|_| VerbLogControlError::InvalidLogLevel {
                value: value.into(),
            })?;
        }

        bus.set_property_string(&locator, kind.property_name(), value)
            .map_err(|source| VerbLogControlError::BusSet {
                kind: kind.display_name(),
                destination: destination.into(),
                value: value.into(),
                source,
            })?;

        Ok(None)
    } else {
        let current = bus
            .get_property_string(&locator, kind.property_name())
            .map_err(|source| VerbLogControlError::BusGet {
                kind: kind.display_name(),
                destination: destination.into(),
                source,
            })?;

        Ok(Some(current))
    }
}

fn parse_verb(verb: &str) -> Result<LogControlKind, VerbLogControlError> {
    if is_log_level_verb(verb) {
        Ok(LogControlKind::Level)
    } else if is_log_target_verb(verb) {
        Ok(LogControlKind::Target)
    } else {
        Err(VerbLogControlError::InvalidVerb { verb: verb.into() })
    }
}

fn parse_numeric_log_level(value: &str) -> Result<i32, Errno> {
    let digits = value.strip_prefix('+').unwrap_or(value);
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Errno::EINVAL);
    }

    let parsed = digits.parse::<i32>().map_err(|_| Errno::EINVAL)?;
    if (0..=7).contains(&parsed) {
        Ok(parsed)
    } else {
        Err(Errno::EINVAL)
    }
}

fn normalize_errno(errno: i32) -> i32 {
    if errno > 0 { -errno } else { errno }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum Call {
        Set {
            destination: String,
            path: &'static str,
            interface: &'static str,
            property: String,
            value: String,
        },
        Get {
            destination: String,
            path: &'static str,
            interface: &'static str,
            property: String,
        },
    }

    // #[derive(Default)]
    struct MockBus {
        calls: Vec<Call>,
        set_result: Result<(), BusCallError>,
        get_result: Result<String, BusCallError>,
    }

    impl Default for MockBus {
        fn default() -> Self {
            Self {
                calls: Vec::new(),
                set_result: Ok(()),
                get_result: Ok(String::new()),
            }
        }
    }

    impl MockBus {
        fn with_set_result(set_result: Result<(), BusCallError>) -> Self {
            Self {
                set_result,
                get_result: Ok(String::new()),
                ..Self::default()
            }
        }

        fn with_get_result(get_result: Result<String, BusCallError>) -> Self {
            Self {
                set_result: Ok(()),
                get_result,
                ..Self::default()
            }
        }
    }

    impl LogControlBus for MockBus {
        fn set_property_string(
            &mut self,
            locator: &BusLocator<'_>,
            property: &str,
            value: &str,
        ) -> Result<(), BusCallError> {
            self.calls.push(Call::Set {
                destination: locator.destination.into(),
                path: locator.path,
                interface: locator.interface,
                property: property.into(),
                value: value.into(),
            });
            self.set_result.clone()
        }

        fn get_property_string(
            &mut self,
            locator: &BusLocator<'_>,
            property: &str,
        ) -> Result<String, BusCallError> {
            self.calls.push(Call::Get {
                destination: locator.destination.into(),
                path: locator.path,
                interface: locator.interface,
                property: property.into(),
            });
            self.get_result.clone()
        }
    }

    #[test]
    fn recognizes_log_level_verbs() {
        assert!(is_log_level_verb("set-log-level"));
        assert!(is_log_level_verb("get-log-level"));
        assert!(!is_log_level_verb("set-log-target"));
    }

    #[test]
    fn recognizes_log_target_verbs() {
        assert!(is_log_target_verb("set-log-target"));
        assert!(is_log_target_verb("get-log-target"));
        assert!(!is_log_target_verb("set-log-level"));
    }

    #[test]
    fn validates_supported_verbs() {
        assert!(validate_verb("set-log-level"));
        assert!(validate_verb("get-log-target"));
        assert!(!validate_verb("reload"));
    }

    #[test]
    fn resolves_property_names() {
        assert_eq!(
            log_control_property_name("set-log-level"),
            Ok(LOG_LEVEL_PROPERTY)
        );
        assert_eq!(
            log_control_property_name("set-log-target"),
            Ok(LOG_TARGET_PROPERTY)
        );
    }

    #[test]
    fn rejects_invalid_property_name_requests() {
        let error = log_control_property_name("noop").unwrap_err();
        assert_eq!(error.errno(), Errno::EINVAL.to_neg_errno());
        assert_eq!(error.to_string(), "Unsupported log control verb: noop");
    }

    #[test]
    fn parses_named_log_levels_case_sensitively() {
        assert_eq!(log_level_from_string("emerg"), Ok(0));
        assert_eq!(log_level_from_string("debug"), Ok(7));
        assert_eq!(log_level_from_string("Debug"), Err(Errno::EINVAL));
        assert_eq!(log_level_from_string("warn"), Err(Errno::EINVAL));
        assert_eq!(log_level_from_string("error"), Err(Errno::EINVAL));
    }

    #[test]
    fn parses_numeric_log_levels_like_the_c_helper() {
        assert_eq!(log_level_from_string("0"), Ok(0));
        assert_eq!(log_level_from_string("7"), Ok(7));
        assert_eq!(log_level_from_string("+4"), Ok(4));
        assert_eq!(log_level_from_string("8"), Err(Errno::EINVAL));
        assert_eq!(log_level_from_string("-1"), Err(Errno::EINVAL));
    }

    #[test]
    fn converts_log_levels_back_to_names() {
        assert_eq!(log_level_to_string(0), Some("emerg"));
        assert_eq!(log_level_to_string(7), Some("debug"));
        assert_eq!(log_level_to_string(8), None);
    }

    #[test]
    fn sets_log_level_after_validation() {
        let mut bus = MockBus::default();

        let result =
            verb_log_control_common(&mut bus, "org.example.Log", "set-log-level", Some("info"));

        assert_eq!(result, Ok(None));
        assert_eq!(
            bus.calls,
            vec![Call::Set {
                destination: "org.example.Log".into(),
                path: LOG_CONTROL_PATH,
                interface: LOG_CONTROL_INTERFACE,
                property: LOG_LEVEL_PROPERTY.into(),
                value: "info".into(),
            }]
        );
    }

    #[test]
    fn rejects_invalid_log_level_before_talking_to_bus() {
        let mut bus = MockBus::default();

        let error =
            verb_log_control_common(&mut bus, "org.example.Log", "set-log-level", Some("warn"))
                .unwrap_err();

        assert!(bus.calls.is_empty());
        assert_eq!(error.errno(), Errno::EINVAL.to_neg_errno());
        assert_eq!(error.to_string(), "\"warn\" is not a valid log level.");
    }

    #[test]
    fn passes_log_target_strings_through_unchanged() {
        let mut bus = MockBus::default();

        let result = verb_log_control_common(
            &mut bus,
            "org.example.Log",
            "set-log-target",
            Some("surprising"),
        );

        assert_eq!(result, Ok(None));
        assert_eq!(
            bus.calls,
            vec![Call::Set {
                destination: "org.example.Log".into(),
                path: LOG_CONTROL_PATH,
                interface: LOG_CONTROL_INTERFACE,
                property: LOG_TARGET_PROPERTY.into(),
                value: "surprising".into(),
            }]
        );
    }

    #[test]
    fn gets_log_level_property() {
        let mut bus = MockBus::with_get_result(Ok("notice".into()));

        let result = verb_log_control_common(&mut bus, "org.example.Log", "get-log-level", None);

        assert_eq!(result, Ok(Some("notice".into())));
        assert_eq!(
            bus.calls,
            vec![Call::Get {
                destination: "org.example.Log".into(),
                path: LOG_CONTROL_PATH,
                interface: LOG_CONTROL_INTERFACE,
                property: LOG_LEVEL_PROPERTY.into(),
            }]
        );
    }

    #[test]
    fn gets_log_target_property() {
        let mut bus = MockBus::with_get_result(Ok("journal".into()));

        let result = verb_log_control_common(&mut bus, "org.example.Log", "get-log-target", None);

        assert_eq!(result, Ok(Some("journal".into())));
        assert_eq!(
            bus.calls,
            vec![Call::Get {
                destination: "org.example.Log".into(),
                path: LOG_CONTROL_PATH,
                interface: LOG_CONTROL_INTERFACE,
                property: LOG_TARGET_PROPERTY.into(),
            }]
        );
    }

    #[test]
    fn reports_bus_set_errors_with_c_style_message() {
        let mut bus = MockBus::with_set_result(Err(BusCallError::new(-5, "Input/output error")));

        let error =
            verb_log_control_common(&mut bus, "org.example.Log", "set-log-level", Some("debug"))
                .unwrap_err();

        assert_eq!(error.errno(), -5);
        assert_eq!(
            error.to_string(),
            "Failed to set log level of org.example.Log to debug: Input/output error"
        );
    }

    #[test]
    fn reports_bus_get_errors_with_c_style_message() {
        let mut bus = MockBus::with_get_result(Err(BusCallError::new(-13, "Access denied")));

        let error = verb_log_control_common(&mut bus, "org.example.Log", "get-log-target", None)
            .unwrap_err();

        assert_eq!(error.errno(), -13);
        assert_eq!(
            error.to_string(),
            "Failed to get log target of org.example.Log: Access denied"
        );
    }

    #[test]
    fn normalizes_positive_errno_values() {
        let err = BusCallError::new(5, "Input/output error");
        assert_eq!(err.errno(), -5);
    }

    #[test]
    fn rejects_invalid_verbs_before_bus_access() {
        let mut bus = MockBus::default();

        let error =
            verb_log_control_common(&mut bus, "org.example.Log", "rotate-log", None).unwrap_err();

        assert!(bus.calls.is_empty());
        assert_eq!(error.errno(), Errno::EINVAL.to_neg_errno());
        assert_eq!(
            error.to_string(),
            "Unsupported log control verb: rotate-log"
        );
    }
}
