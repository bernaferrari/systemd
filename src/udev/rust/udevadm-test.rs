// SPDX-License-Identifier: GPL-2.0-or-later
//
// PORT-SYNC: src/udev/udevadm-test.c
//
// udevadm test — simulate a udev event run for debugging.
//
// Defines argument parsing, resolve-name timing, JSON output flags,
// and verbose-mode logic for the test subcommand.

// ── Constants ─────────────────────────────────────────────────────────────

pub const DEFAULT_ACTION: &str = "add";

// ── Resolve name timing ──────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolveNameTiming {
    Early,
    Late,
    Never,
}

impl ResolveNameTiming {
    pub fn from_str(s: &str) -> Option<ResolveNameTiming> {
        match s {
            "early" => Some(ResolveNameTiming::Early),
            "late" => Some(ResolveNameTiming::Late),
            "never" => Some(ResolveNameTiming::Never),
            _ => None,
        }
    }

    pub fn to_str(self) -> &'static str {
        match self {
            ResolveNameTiming::Early => "early",
            ResolveNameTiming::Late => "late",
            ResolveNameTiming::Never => "never",
        }
    }

    pub fn all() -> &'static [ResolveNameTiming] {
        &[
            ResolveNameTiming::Early,
            ResolveNameTiming::Late,
            ResolveNameTiming::Never,
        ]
    }
}

// ── JSON format flags ────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JsonFormat {
    Off,
    Pretty,
    Short,
}

impl JsonFormat {
    pub fn from_str(s: &str) -> Option<JsonFormat> {
        match s {
            "off" => Some(JsonFormat::Off),
            "pretty" => Some(JsonFormat::Pretty),
            "short" => Some(JsonFormat::Short),
            _ => None,
        }
    }

    pub fn to_str(self) -> &'static str {
        match self {
            JsonFormat::Off => "off",
            JsonFormat::Pretty => "pretty",
            JsonFormat::Short => "short",
        }
    }

    pub fn is_enabled(self) -> bool {
        self != JsonFormat::Off
    }
}

// ── Parsed arguments ──────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TestArgs {
    pub action: String,
    pub resolve_name_timing: ResolveNameTiming,
    pub syspath: String,
    pub extra_rules_dirs: Vec<String>,
    pub verbose: bool,
    pub json_format: JsonFormat,
}

impl Default for TestArgs {
    fn default() -> Self {
        Self {
            action: DEFAULT_ACTION.to_string(),
            resolve_name_timing: ResolveNameTiming::Early,
            syspath: String::new(),
            extra_rules_dirs: Vec::new(),
            verbose: false,
            json_format: JsonFormat::Off,
        }
    }
}

// ── Error type ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TestError {
    HelpRequested,
    VersionRequested,
    InvalidOption(String),
    InvalidAction(String),
    InvalidResolveName(String),
    InvalidJson(String),
    InvalidPath(String),
    SyspathMissing,
}

impl std::fmt::Display for TestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TestError::HelpRequested => write!(f, "help requested"),
            TestError::VersionRequested => write!(f, "version requested"),
            TestError::InvalidOption(opt) => write!(f, "Invalid option: {opt}"),
            TestError::InvalidAction(s) => write!(f, "Invalid action '{s}'"),
            TestError::InvalidResolveName(s) => {
                write!(
                    f,
                    "--resolve-names= must be 'early', 'late', or 'never'. Got: {s}"
                )
            }
            TestError::InvalidJson(s) => {
                write!(f, "Invalid JSON format '{s}', expected pretty|short|off")
            }
            TestError::InvalidPath(s) => write!(f, "Invalid path: {s}"),
            TestError::SyspathMissing => write!(f, "syspath parameter missing"),
        }
    }
}

impl std::error::Error for TestError {}

// ── Validation ────────────────────────────────────────────────────────────

pub fn validate_action(action: &str) -> Result<&str, TestError> {
    if action.is_empty() {
        return Err(TestError::InvalidAction(String::new()));
    }
    let lower = action.to_lowercase();
    if [
        "add", "remove", "change", "move", "online", "offline", "bind", "unbind",
    ]
    .contains(&lower.as_str())
    {
        Ok(action)
    } else {
        Err(TestError::InvalidAction(action.to_string()))
    }
}

pub fn validate_resolve_name(s: &str) -> Result<ResolveNameTiming, TestError> {
    ResolveNameTiming::from_str(s).ok_or_else(|| TestError::InvalidResolveName(s.to_string()))
}

pub fn validate_json_format(s: &str) -> Result<JsonFormat, TestError> {
    JsonFormat::from_str(s).ok_or_else(|| TestError::InvalidJson(s.to_string()))
}

pub fn validate_syspath(syspath: &str) -> Result<(), TestError> {
    if syspath.is_empty() {
        Err(TestError::SyspathMissing)
    } else {
        Ok(())
    }
}

pub fn validate_path_arg(p: &str) -> Result<String, TestError> {
    if p.is_empty() || p.contains('\0') {
        Err(TestError::InvalidPath(p.to_string()))
    } else {
        Ok(p.to_string())
    }
}

// ── Maybe insert empty line ───────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogTarget {
    Console,
    ConsolePrefixed,
    Auto,
    Journal,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    Debug,
    Info,
    Warning,
    Error,
}

/// Determine whether to insert an empty line before a section of output.
/// Mirrors `maybe_insert_empty_line()` in the C source.
pub fn should_insert_empty_line(
    max_level: LogLevel,
    target: LogTarget,
    stderr_is_journal: bool,
) -> bool {
    if matches!(max_level, LogLevel::Debug) {
        return false;
    }
    match target {
        LogTarget::Console | LogTarget::ConsolePrefixed => true,
        LogTarget::Auto if !stderr_is_journal => true,
        _ => false,
    }
}

// ── Help text ─────────────────────────────────────────────────────────────

pub fn help_text(program_name: &str) -> String {
    format!(
        "{program_name} test [OPTIONS] DEVPATH\n\n\
         Test an event run.\n\n\
         -h --help                            Show this help\n\
         -V --version                         Show package version\n\
         -a --action=ACTION|help              Set action string\n\
         -N --resolve-names=early|late|never  When to resolve names\n\
         -D --extra-rules-dir=DIR             Also load rules from the directory\n\
         -v --verbose                         Show verbose logs\n\
            --json=pretty|short|off           Generate JSON output\n"
    )
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_name_roundtrip() {
        for timing in ResolveNameTiming::all() {
            assert_eq!(ResolveNameTiming::from_str(timing.to_str()), Some(*timing));
        }
    }

    #[test]
    fn test_resolve_name_unknown() {
        assert_eq!(ResolveNameTiming::from_str("bad"), None);
    }

    #[test]
    fn test_json_format_roundtrip() {
        assert_eq!(JsonFormat::from_str("off"), Some(JsonFormat::Off));
        assert_eq!(JsonFormat::from_str("pretty"), Some(JsonFormat::Pretty));
        assert_eq!(JsonFormat::from_str("short"), Some(JsonFormat::Short));
        assert_eq!(JsonFormat::from_str("bad"), None);
    }

    #[test]
    fn test_json_is_enabled() {
        assert!(!JsonFormat::Off.is_enabled());
        assert!(JsonFormat::Pretty.is_enabled());
        assert!(JsonFormat::Short.is_enabled());
    }

    #[test]
    fn test_validate_action_ok() {
        assert!(validate_action("add").is_ok());
        assert!(validate_action("remove").is_ok());
        assert!(validate_action("change").is_ok());
    }

    #[test]
    fn test_validate_action_invalid() {
        assert!(validate_action("").is_err());
        assert!(validate_action("bogus").is_err());
    }

    #[test]
    fn test_validate_resolve_name_ok() {
        assert_eq!(validate_resolve_name("early"), Ok(ResolveNameTiming::Early));
        assert_eq!(validate_resolve_name("late"), Ok(ResolveNameTiming::Late));
        assert_eq!(validate_resolve_name("never"), Ok(ResolveNameTiming::Never));
    }

    #[test]
    fn test_validate_resolve_name_err() {
        assert!(validate_resolve_name("sometimes").is_err());
    }

    #[test]
    fn test_validate_syspath() {
        assert!(validate_syspath("/sys/devices/test").is_ok());
        assert!(validate_syspath("").is_err());
    }

    #[test]
    fn test_validate_path_arg() {
        assert!(validate_path_arg("/etc/udev/rules.d").is_ok());
        assert!(validate_path_arg("").is_err());
        assert!(validate_path_arg("has\0null").is_err());
    }

    #[test]
    fn test_should_insert_empty_line() {
        assert!(!should_insert_empty_line(
            LogLevel::Debug,
            LogTarget::Console,
            false
        ));
        assert!(should_insert_empty_line(
            LogLevel::Info,
            LogTarget::Console,
            false
        ));
        assert!(!should_insert_empty_line(
            LogLevel::Info,
            LogTarget::Journal,
            false
        ));
        assert!(should_insert_empty_line(
            LogLevel::Info,
            LogTarget::Auto,
            false
        ));
        assert!(!should_insert_empty_line(
            LogLevel::Info,
            LogTarget::Auto,
            true
        ));
    }

    #[test]
    fn test_help_text() {
        let help = help_text("udevadm");
        assert!(help.contains("--resolve-names"));
        assert!(help.contains("--verbose"));
        assert!(help.contains("--json"));
    }

    #[test]
    fn test_default_args() {
        let args = TestArgs::default();
        assert_eq!(args.action, "add");
        assert_eq!(args.resolve_name_timing, ResolveNameTiming::Early);
        assert!(!args.verbose);
        assert_eq!(args.json_format, JsonFormat::Off);
        assert!(args.extra_rules_dirs.is_empty());
    }
}
