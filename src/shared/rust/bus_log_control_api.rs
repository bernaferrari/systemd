// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/bus-log-control-api.c
//
// D-Bus log control API — bus property getters/setters for LogLevel,
// LogTarget, and SyslogIdentifier. Provides runtime log configuration
// via the org.freedesktop.LogControl1 D-Bus interface.

use std::fmt;
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::RwLock;

// ── Error type ────────────────────────────────────────────────────────────

/// Errors that can arise during bus log control operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BusLogError {
    /// The provided log level string is not recognized.
    InvalidLogLevel(String),
    /// The provided log target string is not recognized.
    InvalidLogTarget(String),
    /// The D-Bus message read failed.
    BusMessageReadFailed(i32),
    /// The D-Bus message append failed.
    BusMessageAppendFailed(i32),
}

impl fmt::Display for BusLogError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BusLogError::InvalidLogLevel(s) => {
                write!(f, "Invalid log level '{s}'")
            }
            BusLogError::InvalidLogTarget(s) => {
                write!(f, "Invalid log target '{s}'")
            }
            BusLogError::BusMessageReadFailed(code) => {
                write!(f, "D-Bus message read failed with code {code}")
            }
            BusLogError::BusMessageAppendFailed(code) => {
                write!(f, "D-Bus message append failed with code {code}")
            }
        }
    }
}

impl std::error::Error for BusLogError {}

// ── Log level constants ───────────────────────────────────────────────────

/// Sentinel value that disables all logging (LOG_NULL).
pub const LOG_NULL: i32 = -1;
/// Emergency (LOG_EMERG = 0).
pub const LOG_EMERG: i32 = 0;
/// Alert (LOG_ALERT = 1).
pub const LOG_ALERT: i32 = 1;
/// Critical (LOG_CRIT = 2).
pub const LOG_CRIT: i32 = 2;
/// Error (LOG_ERR = 3).
pub const LOG_ERR: i32 = 3;
/// Warning (LOG_WARNING = 4).
pub const LOG_WARNING: i32 = 4;
/// Notice (LOG_NOTICE = 5).
pub const LOG_NOTICE: i32 = 5;
/// Informational (LOG_INFO = 6).
pub const LOG_INFO: i32 = 6;
/// Debug (LOG_DEBUG = 7).
pub const LOG_DEBUG: i32 = 7;

// ── Log target enumeration ────────────────────────────────────────────────

/// Where log messages should be directed.
///
/// Matches the C `LogTarget` enum from `src/basic/log.h`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum LogTarget {
    /// Write directly to the console (typically /dev/console).
    Console = 0,
    /// Write to the kernel log buffer.
    Kmsg = 1,
    /// Write to the systemd journal.
    Journal = 2,
    /// Write to the syslog facility.
    Syslog = 3,
    /// Write to console with log prefix.
    ConsolePrefixed = 4,
    /// Write to journal, falling back to kmsg.
    JournalOrKmsg = 5,
    /// Write to syslog, falling back to kmsg.
    SyslogOrKmsg = 6,
    /// Console if stderr is not the journal, otherwise JournalOrKmsg.
    Auto = 7,
    /// Discard all log messages.
    Null = 8,
}

impl LogTarget {
    /// The number of "single" (non-composite) log targets.
    pub const SINGLE_MAX: usize = 4; // Syslog + 1
    /// Total number of valid log targets.
    pub const MAX: usize = 9; // Null + 1
    /// Sentinel for invalid values.
    pub const INVALID: i32 = -22; // -EINVAL

    /// The canonical string names for each variant, in declaration order.
    const NAMES: &[&str] = &[
        "console",
        "kmsg",
        "journal",
        "syslog",
        "console-prefixed",
        "journal-or-kmsg",
        "syslog-or-kmsg",
        "auto",
        "null",
    ];
}

impl fmt::Display for LogTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let idx = *self as usize;
        if idx < LogTarget::NAMES.len() {
            f.write_str(LogTarget::NAMES[idx])
        } else {
            write!(f, "unknown({idx})")
        }
    }
}

// ── Conversion: log level ↔ string ───────────────────────────────────────

/// Convert a numeric log level to its canonical string name.
///
/// Returns `None` for values outside the valid range (including `LOG_NULL`).
pub fn log_level_to_string(level: i32) -> Option<&'static str> {
    match level {
        LOG_EMERG => Some("emerg"),
        LOG_ALERT => Some("alert"),
        LOG_CRIT => Some("crit"),
        LOG_ERR => Some("err"),
        LOG_WARNING => Some("warning"),
        LOG_NOTICE => Some("notice"),
        LOG_INFO => Some("info"),
        LOG_DEBUG => Some("debug"),
        _ => None,
    }
}

/// Parse a log level from its string name or numeric representation.
///
/// Accepts the canonical name, common aliases, or a decimal number ("0"–"7").
pub fn log_level_from_string(s: &str) -> Result<i32, BusLogError> {
    match s.to_ascii_lowercase().as_str() {
        "emerg" | "emergency" | "0" => Ok(LOG_EMERG),
        "alert" | "1" => Ok(LOG_ALERT),
        "crit" | "critical" | "2" => Ok(LOG_CRIT),
        "err" | "error" | "3" => Ok(LOG_ERR),
        "warning" | "warn" | "4" => Ok(LOG_WARNING),
        "notice" | "5" => Ok(LOG_NOTICE),
        "info" | "6" => Ok(LOG_INFO),
        "debug" | "7" => Ok(LOG_DEBUG),
        _ => Err(BusLogError::InvalidLogLevel(s.to_owned())),
    }
}

// ── Conversion: log target ↔ string ──────────────────────────────────────

/// Parse a log target from its string name.
///
/// Accepts canonical names as well as common aliases ("none" → Null, "kernel" → Kmsg).
pub fn log_target_from_string(s: &str) -> Result<LogTarget, BusLogError> {
    match s.to_ascii_lowercase().as_str() {
        "console" => Ok(LogTarget::Console),
        "kmsg" | "kernel" => Ok(LogTarget::Kmsg),
        "journal" => Ok(LogTarget::Journal),
        "syslog" => Ok(LogTarget::Syslog),
        "console-prefixed" => Ok(LogTarget::ConsolePrefixed),
        "journal-or-kmsg" => Ok(LogTarget::JournalOrKmsg),
        "syslog-or-kmsg" => Ok(LogTarget::SyslogOrKmsg),
        "auto" => Ok(LogTarget::Auto),
        "null" | "none" => Ok(LogTarget::Null),
        _ => Err(BusLogError::InvalidLogTarget(s.to_owned())),
    }
}

// ── D-Bus interface constants ────────────────────────────────────────────

/// D-Bus object path for the log control interface.
pub const LOG_CONTROL_PATH: &str = "/org/freedesktop/LogControl1";
/// D-Bus interface name for the log control interface.
pub const LOG_CONTROL_INTERFACE: &str = "org.freedesktop.LogControl1";

/// Describes a single property exposed on the D-Bus interface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BusPropertyEntry {
    /// D-Bus property name (e.g. "LogLevel").
    pub name: &'static str,
    /// D-Bus type signature (e.g. "s").
    pub signature: &'static str,
    /// Whether the property is writable.
    pub writable: bool,
}

/// Returns the vtable of properties for the log control interface.
///
/// Mirrors the C `log_control_vtable[]` from `bus-log-control-api.c`.
pub fn log_control_vtable() -> &'static [BusPropertyEntry] {
    &[
        BusPropertyEntry {
            name: "LogLevel",
            signature: "s",
            writable: true,
        },
        BusPropertyEntry {
            name: "LogTarget",
            signature: "s",
            writable: true,
        },
        BusPropertyEntry {
            name: "SyslogIdentifier",
            signature: "s",
            writable: false,
        },
    ]
}

// ── Log state (thread-safe) ─────────────────────────────────────────────

/// Global log control state, safe for concurrent access.
pub struct LogState {
    max_level: AtomicI32,
    target: RwLock<LogTarget>,
    syslog_identifier: RwLock<String>,
}

impl LogState {
    /// Create a new log state with default values.
    ///
    /// * `max_level` defaults to `LOG_NOTICE` (5), matching systemd convention.
    /// * `target` defaults to `LogTarget::Auto`.
    /// * `syslog_identifier` defaults to `""`.
    pub fn new() -> Self {
        Self {
            max_level: AtomicI32::new(LOG_NOTICE),
            target: RwLock::new(LogTarget::Auto),
            syslog_identifier: RwLock::new(String::new()),
        }
    }

    /// Get the current maximum log level.
    pub fn get_max_level(&self) -> i32 {
        self.max_level.load(Ordering::Relaxed)
    }

    /// Set the maximum log level. Returns the previous level.
    pub fn set_max_level(&self, level: i32) -> i32 {
        self.max_level.swap(level, Ordering::Relaxed)
    }

    /// Get the current log target.
    pub fn get_target(&self) -> LogTarget {
        *self.target.read().unwrap()
    }

    /// Set the log target and return the previous value.
    pub fn set_target(&self, target: LogTarget) -> LogTarget {
        let mut guard = self.target.write().unwrap();
        std::mem::replace(&mut *guard, target)
    }

    /// Get the syslog identifier (program short name).
    pub fn get_syslog_identifier(&self) -> String {
        self.syslog_identifier.read().unwrap().clone()
    }

    /// Set the syslog identifier (program short name).
    pub fn set_syslog_identifier(&self, name: String) {
        *self.syslog_identifier.write().unwrap() = name;
    }
}

impl Default for LogState {
    fn default() -> Self {
        Self::new()
    }
}

// ── Property getter/setter implementations ───────────────────────────────

/// Get the current log level as a string suitable for a D-Bus reply.
///
/// This is the pure-Rust equivalent of `bus_property_get_log_level`.
pub fn bus_property_get_log_level(state: &LogState) -> Result<String, BusLogError> {
    let level = state.get_max_level();
    log_level_to_string(level)
        .map(|s| s.to_owned())
        .ok_or_else(|| BusLogError::BusMessageAppendFailed(-1))
}

/// Set the log level from a D-Bus property value string.
///
/// This is the pure-Rust equivalent of `bus_property_set_log_level`.
pub fn bus_property_set_log_level(state: &LogState, value: &str) -> Result<(), BusLogError> {
    let level = log_level_from_string(value)?;
    state.set_max_level(level);
    Ok(())
}

/// Get the current log target as a string suitable for a D-Bus reply.
///
/// This is the pure-Rust equivalent of `bus_property_get_log_target`.
pub fn bus_property_get_log_target(state: &LogState) -> String {
    state.get_target().to_string()
}

/// Set the log target from a D-Bus property value string.
///
/// This is the pure-Rust equivalent of `bus_property_set_log_target`.
pub fn bus_property_set_log_target(state: &LogState, value: &str) -> Result<(), BusLogError> {
    let target = log_target_from_string(value)?;
    state.set_target(target);
    Ok(())
}

/// Get the syslog identifier string.
///
/// This is the pure-Rust equivalent of `bus_property_get_syslog_identifier`.
pub fn bus_property_get_syslog_identifier(state: &LogState) -> String {
    state.get_syslog_identifier()
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // -- log_level_to_string / log_level_from_string --

    #[test]
    fn test_log_level_to_string_valid() {
        assert_eq!(log_level_to_string(0), Some("emerg"));
        assert_eq!(log_level_to_string(1), Some("alert"));
        assert_eq!(log_level_to_string(2), Some("crit"));
        assert_eq!(log_level_to_string(3), Some("err"));
        assert_eq!(log_level_to_string(4), Some("warning"));
        assert_eq!(log_level_to_string(5), Some("notice"));
        assert_eq!(log_level_to_string(6), Some("info"));
        assert_eq!(log_level_to_string(7), Some("debug"));
    }

    #[test]
    fn test_log_level_to_string_out_of_range() {
        assert!(log_level_to_string(-1).is_none());
        assert!(log_level_to_string(8).is_none());
        assert!(log_level_to_string(100).is_none());
    }

    #[test]
    fn test_log_level_from_string_canonical() {
        assert_eq!(log_level_from_string("emerg"), Ok(0));
        assert_eq!(log_level_from_string("alert"), Ok(1));
        assert_eq!(log_level_from_string("crit"), Ok(2));
        assert_eq!(log_level_from_string("err"), Ok(3));
        assert_eq!(log_level_from_string("warning"), Ok(4));
        assert_eq!(log_level_from_string("notice"), Ok(5));
        assert_eq!(log_level_from_string("info"), Ok(6));
        assert_eq!(log_level_from_string("debug"), Ok(7));
    }

    #[test]
    fn test_log_level_from_string_aliases() {
        assert_eq!(log_level_from_string("emergency"), Ok(0));
        assert_eq!(log_level_from_string("critical"), Ok(2));
        assert_eq!(log_level_from_string("error"), Ok(3));
        assert_eq!(log_level_from_string("warn"), Ok(4));
    }

    #[test]
    fn test_log_level_from_string_numeric() {
        assert_eq!(log_level_from_string("0"), Ok(0));
        assert_eq!(log_level_from_string("7"), Ok(7));
        assert!(log_level_from_string("9").is_err());
    }

    #[test]
    fn test_log_level_from_string_case_insensitive() {
        assert_eq!(log_level_from_string("DEBUG"), Ok(7));
        assert_eq!(log_level_from_string("Warning"), Ok(4));
        assert_eq!(log_level_from_string("InFo"), Ok(6));
    }

    #[test]
    fn test_log_level_from_string_invalid() {
        let result = log_level_from_string("bogus");
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            BusLogError::InvalidLogLevel("bogus".to_owned())
        );
    }

    #[test]
    fn test_log_level_roundtrip() {
        for level in 0..=7 {
            let s = log_level_to_string(level).unwrap();
            assert_eq!(log_level_from_string(s), Ok(level));
        }
    }

    // -- log_target conversions --

    #[test]
    fn test_log_target_from_string_canonical() {
        assert_eq!(log_target_from_string("console"), Ok(LogTarget::Console));
        assert_eq!(log_target_from_string("kmsg"), Ok(LogTarget::Kmsg));
        assert_eq!(log_target_from_string("journal"), Ok(LogTarget::Journal));
        assert_eq!(log_target_from_string("syslog"), Ok(LogTarget::Syslog));
        assert_eq!(
            log_target_from_string("console-prefixed"),
            Ok(LogTarget::ConsolePrefixed)
        );
        assert_eq!(
            log_target_from_string("journal-or-kmsg"),
            Ok(LogTarget::JournalOrKmsg)
        );
        assert_eq!(
            log_target_from_string("syslog-or-kmsg"),
            Ok(LogTarget::SyslogOrKmsg)
        );
        assert_eq!(log_target_from_string("auto"), Ok(LogTarget::Auto));
        assert_eq!(log_target_from_string("null"), Ok(LogTarget::Null));
    }

    #[test]
    fn test_log_target_from_string_aliases() {
        assert_eq!(log_target_from_string("kernel"), Ok(LogTarget::Kmsg));
        assert_eq!(log_target_from_string("none"), Ok(LogTarget::Null));
    }

    #[test]
    fn test_log_target_from_string_invalid() {
        let result = log_target_from_string("foobar");
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            BusLogError::InvalidLogTarget("foobar".to_owned())
        );
    }

    #[test]
    fn test_log_target_display() {
        assert_eq!(LogTarget::Console.to_string(), "console");
        assert_eq!(LogTarget::Auto.to_string(), "auto");
        assert_eq!(LogTarget::Null.to_string(), "null");
    }

    // -- LogState --

    #[test]
    fn test_log_state_default() {
        let state = LogState::new();
        assert_eq!(state.get_max_level(), LOG_NOTICE);
        assert_eq!(state.get_target(), LogTarget::Auto);
        assert_eq!(state.get_syslog_identifier(), "");
    }

    #[test]
    fn test_log_state_set_max_level() {
        let state = LogState::new();
        let prev = state.set_max_level(LOG_DEBUG);
        assert_eq!(prev, LOG_NOTICE);
        assert_eq!(state.get_max_level(), LOG_DEBUG);
    }

    #[test]
    fn test_log_state_set_target() {
        let state = LogState::new();
        let prev = state.set_target(LogTarget::Journal);
        assert_eq!(prev, LogTarget::Auto);
        assert_eq!(state.get_target(), LogTarget::Journal);
    }

    #[test]
    fn test_log_state_set_syslog_identifier() {
        let state = LogState::new();
        state.set_syslog_identifier("mydaemon".to_owned());
        assert_eq!(state.get_syslog_identifier(), "mydaemon");
    }

    // -- Bus property getters/setters --

    #[test]
    fn test_bus_property_get_log_level() {
        let state = LogState::new();
        state.set_max_level(LOG_INFO);
        assert_eq!(bus_property_get_log_level(&state).unwrap(), "info");
    }

    #[test]
    fn test_bus_property_get_log_level_null() {
        let state = LogState::new();
        state.set_max_level(LOG_NULL);
        assert!(bus_property_get_log_level(&state).is_err());
    }

    #[test]
    fn test_bus_property_set_log_level() {
        let state = LogState::new();
        assert!(bus_property_set_log_level(&state, "debug").is_ok());
        assert_eq!(state.get_max_level(), LOG_DEBUG);
    }

    #[test]
    fn test_bus_property_set_log_level_invalid() {
        let state = LogState::new();
        let result = bus_property_set_log_level(&state, "nope");
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            BusLogError::InvalidLogLevel("nope".to_owned())
        );
        // Level should not have changed
        assert_eq!(state.get_max_level(), LOG_NOTICE);
    }

    #[test]
    fn test_bus_property_get_log_target() {
        let state = LogState::new();
        assert_eq!(bus_property_get_log_target(&state), "auto");
        state.set_target(LogTarget::Kmsg);
        assert_eq!(bus_property_get_log_target(&state), "kmsg");
    }

    #[test]
    fn test_bus_property_set_log_target() {
        let state = LogState::new();
        assert!(bus_property_set_log_target(&state, "journal").is_ok());
        assert_eq!(state.get_target(), LogTarget::Journal);
    }

    #[test]
    fn test_bus_property_set_log_target_invalid() {
        let state = LogState::new();
        let result = bus_property_set_log_target(&state, "nope");
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            BusLogError::InvalidLogTarget("nope".to_owned())
        );
    }

    #[test]
    fn test_bus_property_get_syslog_identifier() {
        let state = LogState::new();
        state.set_syslog_identifier("systemd".to_owned());
        assert_eq!(bus_property_get_syslog_identifier(&state), "systemd");
    }

    // -- vtable --

    #[test]
    fn test_log_control_vtable() {
        let vtable = log_control_vtable();
        assert_eq!(vtable.len(), 3);

        assert_eq!(vtable[0].name, "LogLevel");
        assert_eq!(vtable[0].signature, "s");
        assert!(vtable[0].writable);

        assert_eq!(vtable[1].name, "LogTarget");
        assert_eq!(vtable[1].signature, "s");
        assert!(vtable[1].writable);

        assert_eq!(vtable[2].name, "SyslogIdentifier");
        assert_eq!(vtable[2].signature, "s");
        assert!(!vtable[2].writable);
    }

    // -- BusLogError display --

    #[test]
    fn test_bus_log_error_display() {
        let err = BusLogError::InvalidLogLevel("foo".to_owned());
        assert_eq!(format!("{err}"), "Invalid log level 'foo'");

        let err = BusLogError::InvalidLogTarget("bar".to_owned());
        assert_eq!(format!("{err}"), "Invalid log target 'bar'");

        let err = BusLogError::BusMessageReadFailed(-5);
        assert_eq!(format!("{err}"), "D-Bus message read failed with code -5");

        let err = BusLogError::BusMessageAppendFailed(-3);
        assert_eq!(format!("{err}"), "D-Bus message append failed with code -3");
    }

    // -- Constants --

    #[test]
    fn test_log_constants() {
        assert_eq!(LOG_NULL, -1);
        assert_eq!(LOG_EMERG, 0);
        assert_eq!(LOG_ALERT, 1);
        assert_eq!(LOG_CRIT, 2);
        assert_eq!(LOG_ERR, 3);
        assert_eq!(LOG_WARNING, 4);
        assert_eq!(LOG_NOTICE, 5);
        assert_eq!(LOG_INFO, 6);
        assert_eq!(LOG_DEBUG, 7);
    }

    #[test]
    fn test_log_target_constants() {
        assert_eq!(LogTarget::SINGLE_MAX, 4);
        assert_eq!(LogTarget::MAX, 9);
        assert_eq!(LogTarget::INVALID, -22);
    }
}
