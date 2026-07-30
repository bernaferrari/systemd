// SPDX-License-Identifier: GPL-2.0-or-later
//
// PORT-SYNC: src/udev/udevadm.c
//
// udevadm — top-level entry point, verb dispatch, and help/version output.
//
// Defines the verb table, argument parsing for global options (--debug,
// --help, --version), version string, and the main dispatch logic.

// ── Constants ─────────────────────────────────────────────────────────────

pub const PROJECT_VERSION: &str = "256";

// ── Verb table ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verb {
    Cat,
    Info,
    Trigger,
    Settle,
    Control,
    Monitor,
    Hwdb,
    Test,
    TestBuiltin,
    Wait,
    Lock,
    Verify,
    Version,
    Help,
}

impl Verb {
    #[expect(
        clippy::should_implement_trait,
        reason = "the C-facing parser intentionally returns Option, preserving its established unknown-verb contract"
    )]
    pub fn from_str(s: &str) -> Option<Verb> {
        match s {
            "cat" => Some(Verb::Cat),
            "info" => Some(Verb::Info),
            "trigger" => Some(Verb::Trigger),
            "settle" => Some(Verb::Settle),
            "control" => Some(Verb::Control),
            "monitor" => Some(Verb::Monitor),
            "hwdb" => Some(Verb::Hwdb),
            "test" => Some(Verb::Test),
            "test-builtin" => Some(Verb::TestBuiltin),
            "wait" => Some(Verb::Wait),
            "lock" => Some(Verb::Lock),
            "verify" => Some(Verb::Verify),
            "version" => Some(Verb::Version),
            "help" => Some(Verb::Help),
            _ => None,
        }
    }

    pub fn to_str(self) -> &'static str {
        match self {
            Verb::Cat => "cat",
            Verb::Info => "info",
            Verb::Trigger => "trigger",
            Verb::Settle => "settle",
            Verb::Control => "control",
            Verb::Monitor => "monitor",
            Verb::Hwdb => "hwdb",
            Verb::Test => "test",
            Verb::TestBuiltin => "test-builtin",
            Verb::Wait => "wait",
            Verb::Lock => "lock",
            Verb::Verify => "verify",
            Verb::Version => "version",
            Verb::Help => "help",
        }
    }

    pub fn all_verbs() -> &'static [Verb] {
        &[
            Verb::Cat,
            Verb::Info,
            Verb::Trigger,
            Verb::Settle,
            Verb::Control,
            Verb::Monitor,
            Verb::Hwdb,
            Verb::Test,
            Verb::TestBuiltin,
            Verb::Wait,
            Verb::Lock,
            Verb::Verify,
            Verb::Version,
            Verb::Help,
        ]
    }

    pub fn description(self) -> &'static str {
        match self {
            Verb::Info => "Query sysfs or the udev database",
            Verb::Trigger => "Request events from the kernel",
            Verb::Settle => "Wait for pending udev events",
            Verb::Control => "Control the udev daemon",
            Verb::Monitor => "Listen to kernel and udev events",
            Verb::Test => "Test an event run",
            Verb::TestBuiltin => "Test a built-in command",
            Verb::Verify => "Verify udev rules files",
            Verb::Cat => "Show udev rules files",
            Verb::Wait => "Wait for device or device symlink",
            Verb::Lock => "Lock a block device",
            Verb::Hwdb => "Manage the hardware database",
            Verb::Version => "Show package version",
            Verb::Help => "Show this help",
        }
    }
}

// ── Global options ────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct GlobalOptions {
    pub debug: bool,
}

// ── Error type ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UdevadmError {
    HelpRequested,
    VersionRequested,
    InvalidOption(String),
    UnknownVerb(String),
    DebugRequested,
}

impl std::fmt::Display for UdevadmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UdevadmError::HelpRequested => write!(f, "help requested"),
            UdevadmError::VersionRequested => write!(f, "version requested"),
            UdevadmError::InvalidOption(opt) => write!(f, "Invalid option: {opt}"),
            UdevadmError::UnknownVerb(v) => write!(f, "Unknown verb '{v}'"),
            UdevadmError::DebugRequested => write!(f, "debug requested"),
        }
    }
}

impl std::error::Error for UdevadmError {}

// ── Parsed global result ──────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ParsedGlobal {
    pub options: GlobalOptions,
    pub verb: Option<Verb>,
}

// ── Dispatch ──────────────────────────────────────────────────────────────

/// Resolve a verb string, handling the special "udevd" invocation.
/// Mirrors the `invoked_as()` check in the C `run()`.
pub fn resolve_invocation(argv0: &str) -> Option<InvocationMode> {
    if argv0.ends_with("udevd") {
        let basename = argv0.rsplit('/').next().unwrap_or(argv0);
        if basename == "udevd" {
            return Some(InvocationMode::Daemon);
        }
    }
    None
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvocationMode {
    Daemon,
    Udevadm,
}

/// Parse a single global option character.
pub fn parse_global_option(c: char) -> Result<GlobalOptionAction, UdevadmError> {
    match c {
        'd' => Ok(GlobalOptionAction::Debug),
        'h' => Err(UdevadmError::HelpRequested),
        'V' => Err(UdevadmError::VersionRequested),
        '?' => Err(UdevadmError::InvalidOption("?".to_string())),
        _ => Err(UdevadmError::InvalidOption(c.to_string())),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GlobalOptionAction {
    Debug,
}

// ── Help and version ──────────────────────────────────────────────────────

pub fn version_text() -> String {
    PROJECT_VERSION.to_string()
}

pub fn help_text(program_name: &str) -> String {
    let mut out = format!(
        "{program_name} [--help] [--version] [--debug] COMMAND [COMMAND OPTIONS]\n\n\
         Send control commands or test the device manager.\n\n\
         Commands:\n"
    );
    for verb in Verb::all_verbs() {
        if !matches!(verb, Verb::Help | Verb::Version) {
            out.push_str(&format!(
                "  {:<12}  {}\n",
                verb.to_str(),
                verb.description()
            ));
        }
    }
    out
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verb_roundtrip() {
        for verb in Verb::all_verbs() {
            assert_eq!(Verb::from_str(verb.to_str()), Some(*verb));
        }
    }

    #[test]
    fn test_verb_unknown() {
        assert_eq!(Verb::from_str("explode"), None);
    }

    #[test]
    fn test_verb_description() {
        assert!(!Verb::Info.description().is_empty());
        assert!(!Verb::Trigger.description().is_empty());
    }

    #[test]
    fn test_verb_test_builtin_hyphen() {
        assert_eq!(Verb::from_str("test-builtin"), Some(Verb::TestBuiltin));
        assert_eq!(Verb::TestBuiltin.to_str(), "test-builtin");
    }

    #[test]
    fn test_parse_global_option_debug() {
        assert_eq!(parse_global_option('d'), Ok(GlobalOptionAction::Debug));
    }

    #[test]
    fn test_parse_global_option_help() {
        assert!(matches!(
            parse_global_option('h'),
            Err(UdevadmError::HelpRequested)
        ));
    }

    #[test]
    fn test_parse_global_option_version() {
        assert!(matches!(
            parse_global_option('V'),
            Err(UdevadmError::VersionRequested)
        ));
    }

    #[test]
    fn test_parse_global_option_unknown() {
        assert!(matches!(
            parse_global_option('z'),
            Err(UdevadmError::InvalidOption(_))
        ));
    }

    #[test]
    fn test_resolve_invocation_udevd() {
        assert_eq!(
            resolve_invocation("/usr/lib/systemd/udevd"),
            Some(InvocationMode::Daemon)
        );
        assert_eq!(resolve_invocation("udevd"), Some(InvocationMode::Daemon));
    }

    #[test]
    fn test_resolve_invocation_udevadm() {
        assert_eq!(resolve_invocation("udevadm"), None);
        assert_eq!(resolve_invocation("/usr/bin/udevadm"), None);
    }

    #[test]
    fn test_version_text() {
        assert_eq!(version_text(), PROJECT_VERSION);
    }

    #[test]
    fn test_help_text() {
        let help = help_text("udevadm");
        assert!(help.contains("info"));
        assert!(help.contains("trigger"));
        assert!(help.contains("Commands"));
    }
}
