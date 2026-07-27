// SPDX-License-Identifier: GPL-2.0-or-later
//
// PORT-SYNC: src/udev/udevadm-control.c
//
// udevadm control — send control commands to the udev daemon.
//
// Defines the control command types, argument parsing validation,
// property assignment parsing, and command composition logic used
// to control udevd via varlink or the legacy control socket.

// ── Constants ─────────────────────────────────────────────────────────────

/// Default timeout for waiting for a daemon response (60 seconds).
pub const DEFAULT_TIMEOUT_USEC: u64 = 60_000_000;

/// Long-option values that don't map to a short character.
pub const ARG_PING: i32 = 0x100;
pub const ARG_TRACE: i32 = 0x101;
pub const ARG_REVERT: i32 = 0x102;
pub const ARG_LOAD_CREDENTIALS: i32 = 0x103;

// ── Control commands ──────────────────────────────────────────────────────

/// Control commands that can be sent to udevd.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlArgs {
    pub env: Vec<String>,
    pub timeout_usec: u64,
    pub ping: bool,
    pub reload: bool,
    pub exit: bool,
    pub max_children: i64,
    pub log_level: i32,
    pub start_exec_queue: Option<bool>,
    pub trace: i64,
    pub revert: bool,
    pub load_credentials: bool,
}

impl Default for ControlArgs {
    fn default() -> Self {
        Self {
            env: Vec::new(),
            timeout_usec: DEFAULT_TIMEOUT_USEC,
            ping: false,
            reload: false,
            exit: false,
            max_children: -1,
            log_level: -1,
            start_exec_queue: None,
            trace: -1,
            revert: false,
            load_credentials: false,
        }
    }
}

impl ControlArgs {
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns true if any control command has been specified.
    /// Mirrors `arg_has_control_commands()` in C.
    pub fn has_control_commands(&self) -> bool {
        self.exit
            || self.log_level >= 0
            || self.start_exec_queue.is_some()
            || self.reload
            || !self.env.is_empty()
            || self.max_children >= 0
            || self.ping
            || self.trace >= 0
            || self.revert
    }
}

// ── Validation ────────────────────────────────────────────────────────────

/// Errors from control argument parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlParseError {
    HelpRequested,
    VersionRequested,
    NoControlCommand,
    ExtraneousArgument(String),
    InvalidLogLevel(String),
    InvalidMaxChildren(String),
    InvalidTraceValue(String),
    InvalidTimeout(String),
    InvalidPropertyFormat(String),
}

impl std::fmt::Display for ControlParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ControlParseError::HelpRequested => write!(f, "help requested"),
            ControlParseError::VersionRequested => write!(f, "version requested"),
            ControlParseError::NoControlCommand => {
                write!(f, "No control command option is specified.")
            }
            ControlParseError::ExtraneousArgument(arg) => {
                write!(f, "Extraneous argument: {arg}")
            }
            ControlParseError::InvalidLogLevel(s) => {
                write!(f, "Failed to parse log level '{s}'")
            }
            ControlParseError::InvalidMaxChildren(s) => {
                write!(f, "Failed to parse maximum number of children '{s}'")
            }
            ControlParseError::InvalidTraceValue(s) => {
                write!(f, "Failed to parse --trace value '{s}'")
            }
            ControlParseError::InvalidTimeout(s) => {
                write!(f, "Failed to parse timeout value '{s}'")
            }
            ControlParseError::InvalidPropertyFormat(s) => {
                write!(f, "expect <KEY>=<value> instead of '{s}'")
            }
        }
    }
}

impl std::error::Error for ControlParseError {}

/// Validate that a property string contains '='.
pub fn validate_property_assignment(s: &str) -> Result<(), ControlParseError> {
    if s.contains('=') {
        Ok(())
    } else {
        Err(ControlParseError::InvalidPropertyFormat(s.to_string()))
    }
}

/// Validate a log level string. Returns the numeric level or an error.
pub fn parse_log_level(s: &str) -> Result<i32, ControlParseError> {
    match s {
        "emerg" => Ok(0),
        "alert" => Ok(1),
        "crit" => Ok(2),
        "err" | "error" => Ok(3),
        "warning" | "warn" => Ok(4),
        "notice" => Ok(5),
        "info" => Ok(6),
        "debug" => Ok(7),
        digits => digits
            .parse::<i32>()
            .ok()
            .filter(|&l| (0..=7).contains(&l))
            .ok_or_else(|| ControlParseError::InvalidLogLevel(s.to_string())),
    }
}

/// Validate that max_children is a non-negative integer.
pub fn parse_max_children(s: &str) -> Result<u32, ControlParseError> {
    s.parse::<u32>()
        .map_err(|_| ControlParseError::InvalidMaxChildren(s.to_string()))
}

/// Parse a boolean argument for --trace.
pub fn parse_trace_value(s: &str) -> Result<bool, ControlParseError> {
    match s {
        "true" | "yes" | "1" | "on" => Ok(true),
        "false" | "no" | "0" | "off" => Ok(false),
        _ => Err(ControlParseError::InvalidTraceValue(s.to_string())),
    }
}

// ── Credential table ──────────────────────────────────────────────────────

/// Credential pick-up definition for --load-credentials.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PickUpCredential {
    pub prefix: &'static str,
    pub target_dir: &'static str,
    pub suffix: &'static str,
}

/// Returns the credential pick-up table used by --load-credentials.
pub fn credential_table() -> [PickUpCredential; 2] {
    [
        PickUpCredential {
            prefix: "udev.conf.",
            target_dir: "/run/udev/udev.conf.d/",
            suffix: ".conf",
        },
        PickUpCredential {
            prefix: "udev.rules.",
            target_dir: "/run/udev/rules.d/",
            suffix: ".rules",
        },
    ]
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_control_args_default() {
        let args = ControlArgs::new();
        assert!(args.env.is_empty());
        assert!(!args.ping);
        assert!(!args.reload);
        assert!(!args.exit);
        assert!(!args.revert);
        assert!(!args.load_credentials);
        assert_eq!(args.max_children, -1);
        assert_eq!(args.log_level, -1);
        assert!(args.start_exec_queue.is_none());
        assert_eq!(args.trace, -1);
    }

    #[test]
    fn test_has_control_commands_empty() {
        let args = ControlArgs::new();
        assert!(!args.has_control_commands());
    }

    #[test]
    fn test_has_control_commands_with_exit() {
        let args = ControlArgs {
            exit: true,
            ..Default::default()
        };
        assert!(args.has_control_commands());
    }

    #[test]
    fn test_has_control_commands_with_env() {
        let args = ControlArgs {
            env: vec!["KEY=value".to_string()],
            ..Default::default()
        };
        assert!(args.has_control_commands());
    }

    #[test]
    fn test_has_control_commands_with_log_level() {
        let args = ControlArgs {
            log_level: 6,
            ..Default::default()
        };
        assert!(args.has_control_commands());
    }

    #[test]
    fn test_validate_property_assignment_valid() {
        assert!(validate_property_assignment("KEY=value").is_ok());
        assert!(validate_property_assignment("PATH=/usr/bin").is_ok());
        assert!(validate_property_assignment("A=").is_ok());
    }

    #[test]
    fn test_validate_property_assignment_invalid() {
        assert!(validate_property_assignment("NOEQUALS").is_err());
    }

    #[test]
    fn test_parse_log_level_textual() {
        assert_eq!(parse_log_level("emerg"), Ok(0));
        assert_eq!(parse_log_level("debug"), Ok(7));
        assert_eq!(parse_log_level("info"), Ok(6));
        assert_eq!(parse_log_level("err"), Ok(3));
        assert_eq!(parse_log_level("error"), Ok(3));
        assert_eq!(parse_log_level("warning"), Ok(4));
    }

    #[test]
    fn test_parse_log_level_numeric() {
        assert_eq!(parse_log_level("0"), Ok(0));
        assert_eq!(parse_log_level("7"), Ok(7));
        assert_eq!(parse_log_level("4"), Ok(4));
        assert!(parse_log_level("8").is_err());
        assert!(parse_log_level("-1").is_err());
        assert!(parse_log_level("invalid").is_err());
    }

    #[test]
    fn test_parse_max_children() {
        assert_eq!(parse_max_children("0"), Ok(0));
        assert_eq!(parse_max_children("128"), Ok(128));
        assert_eq!(parse_max_children("4294967295"), Ok(u32::MAX));
        assert!(parse_max_children("-1").is_err());
        assert!(parse_max_children("abc").is_err());
    }

    #[test]
    fn test_parse_trace_value() {
        assert_eq!(parse_trace_value("true"), Ok(true));
        assert_eq!(parse_trace_value("yes"), Ok(true));
        assert_eq!(parse_trace_value("1"), Ok(true));
        assert_eq!(parse_trace_value("on"), Ok(true));
        assert_eq!(parse_trace_value("false"), Ok(false));
        assert_eq!(parse_trace_value("no"), Ok(false));
        assert_eq!(parse_trace_value("0"), Ok(false));
        assert_eq!(parse_trace_value("off"), Ok(false));
        assert!(parse_trace_value("maybe").is_err());
    }

    #[test]
    fn test_credential_table() {
        let table = credential_table();
        assert_eq!(table.len(), 2);
        assert_eq!(table[0].prefix, "udev.conf.");
        assert_eq!(table[0].suffix, ".conf");
        assert_eq!(table[1].prefix, "udev.rules.");
        assert_eq!(table[1].suffix, ".rules");
    }
}
