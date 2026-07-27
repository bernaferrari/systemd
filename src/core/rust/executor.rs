// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/core/executor.c
//
// Process sandboxing and execution entry point.
//
// The sd-executor binary is spawned by the manager for each service
// invocation. It deserializes its configuration from a passed FD,
// sets up the execution environment, and invokes the target process.
// This module provides the argument parsing, log configuration,
// and the executor state machine.

// ── Constants ─────────────────────────────────────────────────────────────

/// Exit code for success.
pub const EXIT_SUCCESS: i32 = 0;
/// Exit code for generic failure.
pub const EXIT_FAILURE: i32 = 1;

// ── Log target enum ───────────────────────────────────────────────────────

/// Logging target destinations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogTarget {
    Console,
    Journal,
    JournalOrKmsg,
    Kmsg,
    Null,
}

static LOG_TARGET_TABLE: &[&str] = &["console", "journal", "journal-or-kmsg", "kmsg", "null"];

impl LogTarget {
    /// Parse a log target from a string.
    pub fn from_string(s: &str) -> Result<Self, i32> {
        LOG_TARGET_TABLE
            .iter()
            .position(|t| t.eq_ignore_ascii_case(s))
            .map(|idx| match idx {
                0 => LogTarget::Console,
                1 => LogTarget::Journal,
                2 => LogTarget::JournalOrKmsg,
                3 => LogTarget::Kmsg,
                4 => LogTarget::Null,
                _ => unreachable!(),
            })
            .ok_or(-22)
    }

    /// Convert to string representation.
    pub fn to_string_val(self) -> &'static str {
        LOG_TARGET_TABLE[self as usize]
    }
}

// ── Log level enum ────────────────────────────────────────────────────────

/// Logging severity levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LogLevel {
    Emerg = 0,
    Alert = 1,
    Crit = 2,
    Err = 3,
    Warning = 4,
    Notice = 5,
    Info = 6,
    Debug = 7,
}

static LOG_LEVEL_TABLE: &[&str] = &[
    "emerg", "alert", "crit", "err", "warning", "notice", "info", "debug",
];

impl LogLevel {
    /// Parse a log level from a string.
    pub fn from_string(s: &str) -> Result<Self, i32> {
        LOG_LEVEL_TABLE
            .iter()
            .position(|t| t.eq_ignore_ascii_case(s))
            .map(|idx| match idx {
                0 => LogLevel::Emerg,
                1 => LogLevel::Alert,
                2 => LogLevel::Crit,
                3 => LogLevel::Err,
                4 => LogLevel::Warning,
                5 => LogLevel::Notice,
                6 => LogLevel::Info,
                7 => LogLevel::Debug,
                _ => unreachable!(),
            })
            .ok_or(-22)
    }

    /// Convert to string representation.
    pub fn to_string_val(self) -> &'static str {
        LOG_LEVEL_TABLE[self as usize]
    }

    /// Parse from a numeric log level string.
    pub fn from_number(n: i32) -> Result<Self, i32> {
        match n {
            0 => Ok(LogLevel::Emerg),
            1 => Ok(LogLevel::Alert),
            2 => Ok(LogLevel::Crit),
            3 => Ok(LogLevel::Err),
            4 => Ok(LogLevel::Warning),
            5 => Ok(LogLevel::Notice),
            6 => Ok(LogLevel::Info),
            7 => Ok(LogLevel::Debug),
            _ => Err(-22),
        }
    }
}

// ── Parse boolean from string ─────────────────────────────────────────────

/// Parse a boolean value from a string representation.
///
/// Mirrors the systemd `parse_boolean()` function.
pub fn parse_boolean(s: &str) -> Result<bool, i32> {
    match s {
        "1" | "yes" | "true" | "on" => Ok(true),
        "0" | "no" | "false" | "off" => Ok(false),
        _ => Err(-22),
    }
}

// ── Executor options ──────────────────────────────────────────────────────

/// Parsed executor configuration from command-line arguments.
///
/// Port of the static variables and getopt parsing in executor.c.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutorOptions {
    /// Log level configuration.
    pub log_level: Option<LogLevel>,
    /// Log target configuration.
    pub log_target: Option<LogTarget>,
    /// Whether to highlight log messages with color.
    pub log_color: Option<bool>,
    /// Whether to include code location in log messages.
    pub log_location: Option<bool>,
    /// Whether to prefix messages with current time.
    pub log_time: Option<bool>,
    /// Serialization file descriptor for receiving execution configuration.
    pub deserialize_fd: Option<i32>,
}

impl ExecutorOptions {
    /// Create default options with nothing set.
    pub fn new() -> Self {
        Self {
            log_level: None,
            log_target: None,
            log_color: None,
            log_location: None,
            log_time: None,
            deserialize_fd: None,
        }
    }
}

impl Default for ExecutorOptions {
    fn default() -> Self {
        Self::new()
    }
}

// ── Parse argument result ─────────────────────────────────────────────────

/// Result of argument parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseResult {
    /// Parsing succeeded, work to do.
    Ok(ExecutorOptions),
    /// Help was requested (-h/--help).
    Help,
    /// Version was requested (--version).
    Version,
}

// ── Parse FD from string ──────────────────────────────────────────────────

/// Parse a file descriptor number from a string.
pub fn parse_fd(s: &str) -> Result<i32, i32> {
    let fd: i32 = s.parse().map_err(|_| -22)?;
    if fd < 0 {
        return Err(-22);
    }
    Ok(fd)
}

// ── Parse argv ────────────────────────────────────────────────────────────

/// Parse executor command-line arguments.
///
/// Port of `parse_argv()` from executor.c.
/// Accepts a slice of argument strings (typically starting with the program name).
pub fn parse_argv(args: &[&str]) -> Result<ParseResult, i32> {
    let mut opts = ExecutorOptions::new();

    if args.is_empty() {
        return Err(-22);
    }

    let mut i = 1; // skip argv[0]
    while i < args.len() {
        let arg = args[i];

        if arg == "-h" || arg == "--help" {
            return Ok(ParseResult::Help);
        }

        if arg == "--version" {
            return Ok(ParseResult::Version);
        }

        if arg == "--log-level" {
            i += 1;
            if i >= args.len() {
                return Err(-22);
            }
            opts.log_level = Some(LogLevel::from_string(args[i])?);
        } else if arg == "--log-target" {
            i += 1;
            if i >= args.len() {
                return Err(-22);
            }
            opts.log_target = Some(LogTarget::from_string(args[i])?);
        } else if arg == "--log-color" {
            i += 1;
            if i >= args.len() {
                return Err(-22);
            }
            opts.log_color = Some(parse_boolean(args[i])?);
        } else if arg == "--log-location" {
            i += 1;
            if i >= args.len() {
                return Err(-22);
            }
            opts.log_location = Some(parse_boolean(args[i])?);
        } else if arg == "--log-time" {
            i += 1;
            if i >= args.len() {
                return Err(-22);
            }
            opts.log_time = Some(parse_boolean(args[i])?);
        } else if arg == "--deserialize" {
            i += 1;
            if i >= args.len() {
                return Err(-22);
            }
            opts.deserialize_fd = Some(parse_fd(args[i])?);
        } else if arg.starts_with('-') {
            return Err(-22);
        }

        i += 1;
    }

    // Must have a serialization FD to do any work (mirrors C behavior)
    if opts.deserialize_fd.is_none() {
        return Err(-22);
    }

    Ok(ParseResult::Ok(opts))
}

// ── Help text ─────────────────────────────────────────────────────────────

/// Returns the help text for the executor binary.
///
/// Port of `help()` from executor.c.
pub fn help_text() -> &'static str {
    "sd-executor [OPTIONS...]\n\n\
     Sandbox and execute processes.\n\n\
       -h --help                Show this help and exit\n\
          --version             Print version string and exit\n\
          --log-target=TARGET   Set log target (console, journal,\n\
                                                journal-or-kmsg,\n\
                                                kmsg, null)\n\
          --log-level=LEVEL     Set log level (debug, info, notice,\n\
                                               warning, err, crit,\n\
                                               alert, emerg)\n\
          --log-color=BOOL      Highlight important messages\n\
          --log-location=BOOL   Include code location in messages\n\
          --log-time=BOOL       Prefix messages with current time\n\
          --deserialize=FD      Deserialize process config from FD\n"
}

// ── Executor phases ───────────────────────────────────────────────────────

/// Phases of executor execution, mirroring the flow in `run()`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutorPhase {
    /// Parse command-line arguments.
    ParseArgs,
    /// Open and configure logging.
    OpenLog,
    /// Clear ambient capabilities.
    ClearCapabilities,
    /// Collect passed file descriptors.
    CollectFds,
    /// Initialize MAC (SELinux/SMACK) lazily.
    InitMac,
    /// Deserialize invocation from serialization FD.
    Deserialize,
    /// Invoke the target process.
    Invoke,
    /// Execution complete.
    Done,
}

/// State machine tracking the executor lifecycle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Executor {
    pub phase: ExecutorPhase,
    pub options: Option<ExecutorOptions>,
    pub exit_status: i32,
}

impl Executor {
    /// Create a new executor at the initial phase.
    pub fn new() -> Self {
        Self {
            phase: ExecutorPhase::ParseArgs,
            options: None,
            exit_status: EXIT_SUCCESS,
        }
    }

    /// Advance to the next phase.
    pub fn advance(&mut self) {
        self.phase = match self.phase {
            ExecutorPhase::ParseArgs => ExecutorPhase::OpenLog,
            ExecutorPhase::OpenLog => ExecutorPhase::ClearCapabilities,
            ExecutorPhase::ClearCapabilities => ExecutorPhase::CollectFds,
            ExecutorPhase::CollectFds => ExecutorPhase::InitMac,
            ExecutorPhase::InitMac => ExecutorPhase::Deserialize,
            ExecutorPhase::Deserialize => ExecutorPhase::Invoke,
            ExecutorPhase::Invoke => ExecutorPhase::Done,
            ExecutorPhase::Done => ExecutorPhase::Done,
        };
    }

    /// Check if execution is complete.
    pub fn is_done(&self) -> bool {
        self.phase == ExecutorPhase::Done
    }
}

impl Default for Executor {
    fn default() -> Self {
        Self::new()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_boolean_valid() {
        assert_eq!(parse_boolean("1"), Ok(true));
        assert_eq!(parse_boolean("yes"), Ok(true));
        assert_eq!(parse_boolean("true"), Ok(true));
        assert_eq!(parse_boolean("on"), Ok(true));
        assert_eq!(parse_boolean("0"), Ok(false));
        assert_eq!(parse_boolean("no"), Ok(false));
        assert_eq!(parse_boolean("false"), Ok(false));
        assert_eq!(parse_boolean("off"), Ok(false));
    }

    #[test]
    fn test_parse_boolean_invalid() {
        assert!(parse_boolean("maybe").is_err());
        assert!(parse_boolean("").is_err());
        assert!(parse_boolean("2").is_err());
    }

    #[test]
    fn test_log_level_roundtrip() {
        let all = [
            LogLevel::Emerg,
            LogLevel::Alert,
            LogLevel::Crit,
            LogLevel::Err,
            LogLevel::Warning,
            LogLevel::Notice,
            LogLevel::Info,
            LogLevel::Debug,
        ];
        for variant in &all {
            let s = variant.to_string_val();
            let back = LogLevel::from_string(s).unwrap();
            assert_eq!(back, *variant);
        }
    }

    #[test]
    fn test_log_level_from_number() {
        assert_eq!(LogLevel::from_number(0), Ok(LogLevel::Emerg));
        assert_eq!(LogLevel::from_number(7), Ok(LogLevel::Debug));
        assert!(LogLevel::from_number(8).is_err());
        assert!(LogLevel::from_number(-1).is_err());
    }

    #[test]
    fn test_log_target_roundtrip() {
        let all = [
            LogTarget::Console,
            LogTarget::Journal,
            LogTarget::JournalOrKmsg,
            LogTarget::Kmsg,
            LogTarget::Null,
        ];
        for variant in &all {
            let s = variant.to_string_val();
            let back = LogTarget::from_string(s).unwrap();
            assert_eq!(back, *variant);
        }
    }

    #[test]
    fn test_parse_argv_help() {
        let result = parse_argv(&["sd-executor", "-h"]).unwrap();
        assert_eq!(result, ParseResult::Help);
    }

    #[test]
    fn test_parse_argv_version() {
        let result = parse_argv(&["sd-executor", "--version"]).unwrap();
        assert_eq!(result, ParseResult::Version);
    }

    #[test]
    fn test_parse_argv_full_options() {
        let result = parse_argv(&[
            "sd-executor",
            "--log-level",
            "debug",
            "--log-target",
            "journal",
            "--log-color",
            "yes",
            "--log-location",
            "false",
            "--log-time",
            "on",
            "--deserialize",
            "5",
        ])
        .unwrap();
        match result {
            ParseResult::Ok(opts) => {
                assert_eq!(opts.log_level, Some(LogLevel::Debug));
                assert_eq!(opts.log_target, Some(LogTarget::Journal));
                assert_eq!(opts.log_color, Some(true));
                assert_eq!(opts.log_location, Some(false));
                assert_eq!(opts.log_time, Some(true));
                assert_eq!(opts.deserialize_fd, Some(5));
            }
            _ => panic!("expected Ok"),
        }
    }

    #[test]
    fn test_parse_argv_no_deserialize_fd() {
        // Without --deserialize, parsing should fail
        assert!(parse_argv(&["sd-executor"]).is_err());
    }

    #[test]
    fn test_parse_argv_unknown_option() {
        assert!(parse_argv(&["sd-executor", "--bogus"]).is_err());
    }

    #[test]
    fn test_parse_argv_empty() {
        assert!(parse_argv(&[]).is_err());
    }

    #[test]
    fn test_parse_fd_valid() {
        assert_eq!(parse_fd("0"), Ok(0));
        assert_eq!(parse_fd("3"), Ok(3));
        assert_eq!(parse_fd("1024"), Ok(1024));
    }

    #[test]
    fn test_parse_fd_invalid() {
        assert!(parse_fd("-1").is_err());
        assert!(parse_fd("abc").is_err());
        assert!(parse_fd("").is_err());
    }

    #[test]
    fn test_help_text_contents() {
        let text = help_text();
        assert!(text.contains("sd-executor"));
        assert!(text.contains("--deserialize"));
        assert!(text.contains("--help"));
        assert!(text.contains("--log-level"));
    }

    #[test]
    fn test_executor_state_machine() {
        let mut exec = Executor::new();
        assert_eq!(exec.phase, ExecutorPhase::ParseArgs);
        assert!(!exec.is_done());

        exec.advance();
        assert_eq!(exec.phase, ExecutorPhase::OpenLog);

        exec.advance();
        assert_eq!(exec.phase, ExecutorPhase::ClearCapabilities);

        exec.advance();
        assert_eq!(exec.phase, ExecutorPhase::CollectFds);

        exec.advance();
        assert_eq!(exec.phase, ExecutorPhase::InitMac);

        exec.advance();
        assert_eq!(exec.phase, ExecutorPhase::Deserialize);

        exec.advance();
        assert_eq!(exec.phase, ExecutorPhase::Invoke);

        exec.advance();
        assert_eq!(exec.phase, ExecutorPhase::Done);
        assert!(exec.is_done());

        // advancing past Done stays at Done
        exec.advance();
        assert_eq!(exec.phase, ExecutorPhase::Done);
    }

    #[test]
    fn test_executor_default() {
        let exec = Executor::default();
        assert_eq!(exec.phase, ExecutorPhase::ParseArgs);
        assert_eq!(exec.exit_status, EXIT_SUCCESS);
    }
}
