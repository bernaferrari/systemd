// SPDX-License-Identifier: GPL-2.0-or-later
//
// PORT-SYNC: src/udev/udevadm-settle.c
//
// udevadm settle — wait for pending udev events to complete.
//
// Defines argument parsing, timeout handling, deprecation warning logic,
// and queue-empty checking for the settle subcommand.

// ── Constants ─────────────────────────────────────────────────────────────

/// Default settle timeout (120 seconds in microseconds).
pub const DEFAULT_TIMEOUT_USEC: u64 = 120_000_000;

/// Minimum ping timeout (5 seconds in microseconds).
pub const MIN_PING_TIMEOUT_USEC: u64 = 5_000_000;

/// Deprecated options that are no longer supported.
pub const DEPRECATED_OPTIONS: &[(char, &str)] =
    &[('s', "seq-start"), ('e', "seq-end"), ('q', "quiet")];

// ── Parsed arguments ──────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettleArgs {
    pub timeout_usec: u64,
    pub exit_if_exists: Option<String>,
}

impl Default for SettleArgs {
    fn default() -> Self {
        Self {
            timeout_usec: DEFAULT_TIMEOUT_USEC,
            exit_if_exists: None,
        }
    }
}

impl SettleArgs {
    pub fn new() -> Self {
        Self::default()
    }
}

// ── Validation ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SettleParseError {
    HelpRequested,
    VersionRequested,
    DeprecatedOption(char),
    InvalidTimeout(String),
    InvalidPath(String),
    InvalidOption(String),
}

impl std::fmt::Display for SettleParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SettleParseError::HelpRequested => write!(f, "help requested"),
            SettleParseError::VersionRequested => write!(f, "version requested"),
            SettleParseError::DeprecatedOption(c) => {
                write!(f, "Option -{c} no longer supported.")
            }
            SettleParseError::InvalidTimeout(s) => {
                write!(f, "Failed to parse timeout value '{s}'")
            }
            SettleParseError::InvalidPath(s) => {
                write!(f, "Invalid path: {s}")
            }
            SettleParseError::InvalidOption(opt) => write!(f, "Invalid option: {opt}"),
        }
    }
}

impl std::error::Error for SettleParseError {}

/// Check if a character is a deprecated option.
pub fn is_deprecated_option(c: char) -> bool {
    DEPRECATED_OPTIONS.iter().any(|(ch, _)| *ch == c)
}

/// Get the long name for a deprecated option.
pub fn deprecated_option_name(c: char) -> Option<&'static str> {
    DEPRECATED_OPTIONS
        .iter()
        .find(|(ch, _)| *ch == c)
        .map(|(_, name)| *name)
}

/// Validate that a path is not empty and looks like a filesystem path.
pub fn validate_path(s: &str) -> Result<(), SettleParseError> {
    if s.is_empty() || s.contains('\0') {
        Err(SettleParseError::InvalidPath(s.to_string()))
    } else {
        Ok(())
    }
}

// ── Settle check logic ────────────────────────────────────────────────────

/// Represents the result of checking whether the udev queue is settled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SettleCheckResult {
    /// Queue is empty, settled.
    Settled,
    /// Queue is not empty, still processing.
    NotSettled,
    /// File exists (exit-if-exists condition met).
    FileExists,
    /// Error checking the queue.
    CheckError(i32),
}

/// Evaluate settle conditions given the existence check and queue status.
/// Mirrors the check() function in C.
pub fn evaluate_settle(
    exit_if_exists: Option<&str>,
    file_exists: Option<bool>,
    queue_empty: Option<bool>,
) -> SettleCheckResult {
    if let Some(_path) = exit_if_exists {
        match file_exists {
            Some(true) => return SettleCheckResult::FileExists,
            Some(false) => {}
            None => return SettleCheckResult::CheckError(-1),
        }
    }

    match queue_empty {
        Some(true) => SettleCheckResult::Settled,
        Some(false) => SettleCheckResult::NotSettled,
        None => SettleCheckResult::CheckError(-1),
    }
}

// ── Deprecation warning ───────────────────────────────────────────────────

/// The systemd-udev-settle.service unit name.
pub const SETTLE_SERVICE_NAME: &str = "systemd-udev-settle.service";

/// Build the deprecation log message for when the settle service is invoked.
pub fn deprecation_message(offending_units: &[&str]) -> String {
    if offending_units.is_empty() {
        format!("{SETTLE_SERVICE_NAME} is deprecated.")
    } else {
        let joined = offending_units.join(", ");
        format!(
            "{SETTLE_SERVICE_NAME} is deprecated. \
             Please fix {joined} not to pull it in."
        )
    }
}

// ── Ping timeout calculation ──────────────────────────────────────────────

/// Calculate the ping timeout: at least MIN_PING_TIMEOUT_USEC, or the
/// settle timeout if larger.
pub fn ping_timeout(settle_timeout_usec: u64) -> u64 {
    settle_timeout_usec.max(MIN_PING_TIMEOUT_USEC)
}

// ── Help text ─────────────────────────────────────────────────────────────

pub fn help_text(program_name: &str) -> String {
    format!(
        "{program_name} settle [OPTIONS]\n\n\
         Wait for pending udev events.\n\n\
         -h --help                 Show this help\n\
         -V --version              Show package version\n\
         -t --timeout=SEC          Maximum time to wait for events\n\
         -E --exit-if-exists=FILE  Stop waiting if file exists\n"
    )
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_settle_args_default() {
        let args = SettleArgs::new();
        assert_eq!(args.timeout_usec, DEFAULT_TIMEOUT_USEC);
        assert!(args.exit_if_exists.is_none());
    }

    #[test]
    fn test_is_deprecated_option() {
        assert!(is_deprecated_option('s'));
        assert!(is_deprecated_option('e'));
        assert!(is_deprecated_option('q'));
        assert!(!is_deprecated_option('t'));
        assert!(!is_deprecated_option('h'));
    }

    #[test]
    fn test_deprecated_option_name() {
        assert_eq!(deprecated_option_name('s'), Some("seq-start"));
        assert_eq!(deprecated_option_name('e'), Some("seq-end"));
        assert_eq!(deprecated_option_name('q'), Some("quiet"));
        assert_eq!(deprecated_option_name('t'), None);
    }

    #[test]
    fn test_validate_path_valid() {
        assert!(validate_path("/run/udev/queue").is_ok());
        assert!(validate_path("/tmp/test").is_ok());
    }

    #[test]
    fn test_validate_path_invalid() {
        assert!(validate_path("").is_err());
        assert!(validate_path("has\0null").is_err());
    }

    #[test]
    fn test_evaluate_settle_no_conditions() {
        let result = evaluate_settle(None, None, Some(true));
        assert_eq!(result, SettleCheckResult::Settled);
    }

    #[test]
    fn test_evaluate_settle_queue_not_empty() {
        let result = evaluate_settle(None, None, Some(false));
        assert_eq!(result, SettleCheckResult::NotSettled);
    }

    #[test]
    fn test_evaluate_settle_file_exists() {
        let result = evaluate_settle(Some("/tmp/test"), Some(true), Some(false));
        assert_eq!(result, SettleCheckResult::FileExists);
    }

    #[test]
    fn test_evaluate_settle_file_not_exists_queue_empty() {
        let result = evaluate_settle(Some("/tmp/test"), Some(false), Some(true));
        assert_eq!(result, SettleCheckResult::Settled);
    }

    #[test]
    fn test_deprecation_message_no_units() {
        let msg = deprecation_message(&[]);
        assert!(msg.contains("deprecated"));
        assert!(!msg.contains("Please fix"));
    }

    #[test]
    fn test_deprecation_message_with_units() {
        let msg = deprecation_message(&["unit-a.service", "unit-b.service"]);
        assert!(msg.contains("deprecated"));
        assert!(msg.contains("unit-a.service"));
        assert!(msg.contains("unit-b.service"));
        assert!(msg.contains("Please fix"));
    }

    #[test]
    fn test_ping_timeout() {
        assert_eq!(ping_timeout(1000), MIN_PING_TIMEOUT_USEC);
        assert_eq!(
            ping_timeout(MIN_PING_TIMEOUT_USEC + 1000),
            MIN_PING_TIMEOUT_USEC + 1000
        );
        assert_eq!(ping_timeout(u64::MAX), u64::MAX);
    }

    #[test]
    fn test_help_text() {
        let help = help_text("udevadm");
        assert!(help.contains("--timeout"));
        assert!(help.contains("--exit-if-exists"));
        assert!(help.contains("--help"));
    }
}
