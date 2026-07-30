// SPDX-License-Identifier: LGPL-2.1-or-later
#![deny(unsafe_op_in_unsafe_fn)]
//
// PORT-SYNC: src/run/run.c
//
// Run command in transient scope or service.
//
// Runs the specified command in a transient systemd scope or service unit.
// Supports PTY mode, pipe mode, timer/path/socket triggers, and various
// execution options.

// ── Constants ─────────────────────────────────────────────────────────────

/// Timer property names recognized by run.
pub const TIMER_PROPERTIES: &[&str] = &[
    "OnActiveSec",
    "OnBootSec",
    "OnStartupSec",
    "OnUnitActiveSec",
    "OnUnitInactiveSec",
    "OnCalendar",
];

/// Default service type.
pub const DEFAULT_SERVICE_TYPE: &str = "exec";

/// Default job mode.
pub const DEFAULT_JOB_MODE: JobMode = JobMode::Fail;

pub use systemd_basic_rs::unit_def::{
    JobMode, ParseJobModeError, job_mode_from_string, job_mode_to_string,
};

// ── Enums ─────────────────────────────────────────────────────────────────

/// How stdio is connected to the child.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StdioFlags(u32);

impl StdioFlags {
    pub const NONE: StdioFlags = StdioFlags(0);
    pub const PTY: StdioFlags = StdioFlags(1 << 0);
    pub const DIRECT: StdioFlags = StdioFlags(1 << 1);
    pub const AUTO: StdioFlags = StdioFlags(StdioFlags::PTY.0 | StdioFlags::DIRECT.0);
}

/// Bus transport mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BusTransport {
    Local,
    Remote,
    Machine,
    Capsule,
}

/// Runtime scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeScope {
    System,
    User,
}

// ── Structs ───────────────────────────────────────────────────────────────

/// Parsed arguments for the run command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunConfig {
    /// Whether running as scope.
    pub scope: bool,
    /// Whether to remain after exit.
    pub remain_after_exit: bool,
    /// Whether to wait for service to stop.
    pub wait: bool,
    /// Unit name override.
    pub unit: Option<String>,
    /// Slice to run in.
    pub slice: Option<String>,
    /// Whether to inherit slice.
    pub slice_inherit: bool,
    /// Working directory.
    pub working_directory: Option<String>,
    /// Root directory.
    pub root_directory: Option<String>,
    /// Service type.
    pub service_type: Option<String>,
    /// User to run as.
    pub exec_user: Option<String>,
    /// Group to run as.
    pub exec_group: Option<String>,
    /// Nice level.
    pub nice: Option<i32>,
    /// Stdio mode flags.
    pub stdio: StdioFlags,
    /// PTY late mode.
    pub pty_late: bool,
    /// Quiet mode.
    pub quiet: bool,
    /// Verbose mode.
    pub verbose: bool,
    /// Aggressive GC.
    pub aggressive_gc: bool,
    /// Transport mode.
    pub transport: BusTransport,
    /// Runtime scope.
    pub runtime_scope: RuntimeScope,
    /// Job mode.
    pub job_mode: JobMode,
    /// Command line to execute.
    pub cmdline: Vec<String>,
    /// Properties to set.
    pub properties: Vec<String>,
    /// Environment variables.
    pub environment: Vec<String>,
    /// Timer properties.
    pub timer_properties: Vec<String>,
    /// Whether a timer trigger is set.
    pub with_timer: bool,
    /// Background color.
    pub background: Option<String>,
}

// ── Error type ────────────────────────────────────────────────────────────

/// Errors from run operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunError {
    /// Invalid argument combination.
    InvalidArgument(String),
    /// Command line required but missing.
    CommandLineRequired,
    /// Timer property without timer options.
    TimerPropertyWithoutTimer,
    /// Scope not compatible with trigger.
    ScopeWithTrigger,
    /// Stdio not compatible with trigger or scope.
    StdioIncompatible,
    /// Remote execution not supported.
    RemoteNotSupported(String),
    /// Nice value parse failure.
    InvalidNice(String),
    /// Calendar spec parse failure.
    InvalidCalendar(String),
    /// Environment variable parse failure.
    InvalidEnvironment(String),
}

impl std::fmt::Display for RunError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RunError::InvalidArgument(msg) => write!(f, "{}", msg),
            RunError::CommandLineRequired => {
                write!(f, "Command line to execute required.")
            }
            RunError::TimerPropertyWithoutTimer => {
                write!(
                    f,
                    "--timer-property= has no effect without any other timer options."
                )
            }
            RunError::ScopeWithTrigger => {
                write!(
                    f,
                    "Path, socket or timer options are not supported in --scope mode."
                )
            }
            RunError::StdioIncompatible => {
                write!(
                    f,
                    "--pty/--pty-late/--pipe is not compatible in trigger or --scope mode."
                )
            }
            RunError::RemoteNotSupported(msg) => write!(f, "{}", msg),
            RunError::InvalidNice(s) => write!(f, "Failed to parse nice value: {}", s),
            RunError::InvalidCalendar(s) => {
                write!(f, "Failed to parse calendar event: {}", s)
            }
            RunError::InvalidEnvironment(s) => {
                write!(f, "Cannot assign environment variable {}", s)
            }
        }
    }
}

impl std::error::Error for RunError {}

// ── Helper functions ──────────────────────────────────────────────────────

/// Check if a property string is a timer trigger.
pub fn is_timer_property(property: &str) -> bool {
    TIMER_PROPERTIES
        .iter()
        .any(|p| property.starts_with(&format!("{}=", p)))
}

/// Determine stdio mode based on TTY availability.
pub fn resolve_stdio_auto(
    stdin_is_tty: bool,
    stdout_is_tty: bool,
    stderr_is_tty: bool,
) -> StdioFlags {
    if stdin_is_tty && stdout_is_tty && stderr_is_tty {
        StdioFlags::PTY
    } else {
        StdioFlags::DIRECT
    }
}

/// Validate that trigger units are not conflicting.
pub fn validate_trigger_compatibility(
    has_path: bool,
    has_socket: bool,
    has_timer: bool,
) -> Result<(), RunError> {
    let count = has_path as usize + has_socket as usize + has_timer as usize;
    if count > 1 {
        return Err(RunError::InvalidArgument(
            "Only single trigger (path, socket, timer) unit can be created.".to_string(),
        ));
    }
    Ok(())
}

/// Check if becoming root based on scope and user.
pub fn become_root(runtime_scope: RuntimeScope, exec_user: Option<&str>) -> bool {
    if runtime_scope != RuntimeScope::System {
        return false;
    }
    match exec_user {
        None => true,
        Some(user) => user == "root" || user == "0",
    }
}

/// Parse a timer property from a key-value argument.
pub fn parse_timer_property(name: &str, value: &str) -> String {
    format!("{}={}", name, value)
}

/// Result of parsing `--job-mode`, whose `help` value is handled by the CLI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobModeArgument {
    /// A valid C job mode.
    Mode(JobMode),
    /// The C command's `--job-mode=help` meta-value.
    Help,
}

/// Find the final `--job-mode` option in command-line arguments.
///
/// This recognizes both GNU long-option spellings and stops at `--`, matching
/// the boundary between systemd-run options and the invoked command. The
/// special `help` value is not a [`JobMode`]; callers render the table and
/// exit successfully when it is returned.
pub fn parse_job_mode_option(args: &[&str]) -> Result<Option<JobModeArgument>, RunError> {
    let mut parsed = None;
    let mut index = 0;

    while let Some(argument) = args.get(index) {
        if *argument == "--" {
            break;
        }

        let value = if let Some(value) = argument.strip_prefix("--job-mode=") {
            value
        } else if *argument == "--job-mode" {
            index += 1;
            args.get(index).copied().ok_or_else(|| {
                RunError::InvalidArgument("Option --job-mode requires an argument.".to_string())
            })?
        } else {
            index += 1;
            continue;
        };

        if value == "help" {
            return Ok(Some(JobModeArgument::Help));
        }

        let mode = job_mode_from_string(value)
            .ok_or_else(|| RunError::InvalidArgument(format!("Invalid job mode: {value}")))?;
        parsed = Some(JobModeArgument::Mode(mode));
        index += 1;
    }

    Ok(parsed)
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_timer_property() {
        assert!(is_timer_property("OnActiveSec=5"));
        assert!(is_timer_property("OnCalendar=*-*-*"));
        assert!(is_timer_property("OnBootSec=10"));
        assert!(!is_timer_property("Description=test"));
        assert!(!is_timer_property("RemainAfterExit=yes"));
    }

    #[test]
    fn test_resolve_stdio_auto_all_tty() {
        assert_eq!(resolve_stdio_auto(true, true, true), StdioFlags::PTY);
    }

    #[test]
    fn test_resolve_stdio_auto_no_tty() {
        assert_eq!(resolve_stdio_auto(false, false, false), StdioFlags::DIRECT);
    }

    #[test]
    fn test_resolve_stdio_auto_mixed() {
        assert_eq!(resolve_stdio_auto(true, false, true), StdioFlags::DIRECT);
    }

    #[test]
    fn test_validate_trigger_compatibility_none() {
        assert!(validate_trigger_compatibility(false, false, false).is_ok());
    }

    #[test]
    fn test_validate_trigger_compatibility_single() {
        assert!(validate_trigger_compatibility(true, false, false).is_ok());
        assert!(validate_trigger_compatibility(false, true, false).is_ok());
        assert!(validate_trigger_compatibility(false, false, true).is_ok());
    }

    #[test]
    fn test_validate_trigger_compatibility_multiple() {
        assert!(validate_trigger_compatibility(true, true, false).is_err());
        assert!(validate_trigger_compatibility(true, false, true).is_err());
        assert!(validate_trigger_compatibility(false, true, true).is_err());
        assert!(validate_trigger_compatibility(true, true, true).is_err());
    }

    #[test]
    fn test_become_root_system_no_user() {
        assert!(become_root(RuntimeScope::System, None));
    }

    #[test]
    fn test_become_root_system_root_user() {
        assert!(become_root(RuntimeScope::System, Some("root")));
        assert!(become_root(RuntimeScope::System, Some("0")));
    }

    #[test]
    fn test_become_root_system_other_user() {
        assert!(!become_root(RuntimeScope::System, Some("nobody")));
    }

    #[test]
    fn test_become_root_user_scope() {
        assert!(!become_root(RuntimeScope::User, None));
    }

    #[test]
    fn test_parse_timer_property() {
        assert_eq!(parse_timer_property("OnActiveSec", "5"), "OnActiveSec=5");
        assert_eq!(
            parse_timer_property("OnCalendar", "*-*-*"),
            "OnCalendar=*-*-*"
        );
    }

    #[test]
    fn test_job_mode_option() {
        assert_eq!(DEFAULT_JOB_MODE, JobMode::Fail);
        assert_eq!(
            parse_job_mode_option(&["--job-mode", "lenient"]),
            Ok(Some(JobModeArgument::Mode(JobMode::Lenient)))
        );
        assert_eq!(
            parse_job_mode_option(&["--job-mode=replace-irreversibly"]),
            Ok(Some(JobModeArgument::Mode(JobMode::ReplaceIrreversibly)))
        );
        assert_eq!(
            parse_job_mode_option(&["--job-mode=fail", "--job-mode", "triggering"]),
            Ok(Some(JobModeArgument::Mode(JobMode::Triggering)))
        );
        assert_eq!(
            parse_job_mode_option(&["--job-mode=help"]),
            Ok(Some(JobModeArgument::Help))
        );
        assert_eq!(
            parse_job_mode_option(&["--", "--job-mode=replace"]),
            Ok(None)
        );
    }

    #[test]
    fn test_job_mode_option_rejects_invalid_input() {
        assert_eq!(
            parse_job_mode_option(&["--job-mode=quiet"]),
            Err(RunError::InvalidArgument(
                "Invalid job mode: quiet".to_string()
            ))
        );
        assert_eq!(
            parse_job_mode_option(&["--job-mode"]),
            Err(RunError::InvalidArgument(
                "Option --job-mode requires an argument.".to_string()
            ))
        );
    }

    #[test]
    fn test_error_display() {
        assert!(format!("{}", RunError::CommandLineRequired).contains("Command line"));
    }
}
