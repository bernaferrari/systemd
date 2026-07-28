// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/service-util.c, src/shared/service-util.h
//
// Service command-line argument parsing utilities.
//
// Provides argument parsing for service programs that support --help,
// --version, --bus-introspect, --system, and --user flags, matching
// the behaviour of the C `service_parse_argv` function.

use crate::ffi::*;
use std::fmt;

// ── Constants ─────────────────────────────────────────────────────────────

/// POSIX error code for invalid argument.
const EINVAL: i32 = 22;

// ── Enums ─────────────────────────────────────────────────────────────────

/// Scope in which a service runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeScope {
    System,
    User,
}

/// Bitflags controlling which optional features are available.
bitflags::bitflags! {
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct HelpFlags: u32 {
        const BUS_INTROSPECT = 1 << 0;
        const RUNTIME_SCOPE  = 1 << 1;
    }
}

/// Result of parsing service command-line arguments.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ServiceAction {
    /// Continue normal execution.
    Continue,
    /// Show help text and exit.
    ShowHelp(String),
    /// Show version information and exit.
    ShowVersion,
    /// Write D-Bus XML introspection data to the given path.
    BusIntrospect(String),
}

/// Error type for service argument parsing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServiceParseError {
    /// An unrecognised option was encountered.
    InvalidOption,
    /// A positional argument was found where none are expected.
    UnexpectedArgument,
    /// --system/--user was used but the service does not support runtime scope.
    ScopeNotSupported,
}

impl fmt::Display for ServiceParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ServiceParseError::InvalidOption => write!(f, "Unrecognised option"),
            ServiceParseError::UnexpectedArgument => {
                write!(f, "This program takes no positional arguments")
            }
            ServiceParseError::ScopeNotSupported => {
                write!(
                    f,
                    "This service cannot be run in --system or --user mode, refusing"
                )
            }
        }
    }
}

impl std::error::Error for ServiceParseError {}

// ── Argument definition ───────────────────────────────────────────────────

/// A single option definition for the parser.
#[derive(Clone, Debug)]
struct ArgDef {
    short: Option<char>,
    long: &'static str,
    has_value: bool,
}

const OPTIONS: &[ArgDef] = &[
    ArgDef {
        short: Some('h'),
        long: "help",
        has_value: false,
    },
    ArgDef {
        short: None,
        long: "version",
        has_value: false,
    },
    ArgDef {
        short: None,
        long: "bus-introspect",
        has_value: true,
    },
    ArgDef {
        short: None,
        long: "system",
        has_value: false,
    },
    ArgDef {
        short: None,
        long: "user",
        has_value: false,
    },
];

/// Token produced by the option lexer.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Token {
    Help,
    Version,
    BusIntrospect(String),
    System,
    User,
}

/// Lex a single argument into a token.
///
/// Supports `-h`, `--help`, `--version`, `--system`, `--user`,
/// `--bus-introspect=PATH`, and `--bus-introspect PATH` forms.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ConsumedNext {
    Yes,
    No,
}

fn lex_token(arg: &str, next: Option<&str>) -> Result<(Token, ConsumedNext), ServiceParseError> {
    // Short option: -h
    if arg == "-h" {
        return Ok((Token::Help, ConsumedNext::No));
    }

    // Only handle long options from here on
    if !arg.starts_with("--") {
        return Err(ServiceParseError::InvalidOption);
    }

    let body = &arg[2..];

    if body == "help" {
        return Ok((Token::Help, ConsumedNext::No));
    }
    if body == "version" {
        return Ok((Token::Version, ConsumedNext::No));
    }
    if body == "system" {
        return Ok((Token::System, ConsumedNext::No));
    }
    if body == "user" {
        return Ok((Token::User, ConsumedNext::No));
    }

    // --bus-introspect=PATH  (inline value)
    if let Some(value) = body.strip_prefix("bus-introspect=") {
        if value.is_empty() {
            return Err(ServiceParseError::InvalidOption);
        }
        return Ok((Token::BusIntrospect(value.to_string()), ConsumedNext::No));
    }

    // --bus-introspect PATH  (value in next arg)
    if body == "bus-introspect" {
        let value = next.ok_or(ServiceParseError::InvalidOption)?;
        if value.is_empty() {
            return Err(ServiceParseError::InvalidOption);
        }
        return Ok((Token::BusIntrospect(value.to_string()), ConsumedNext::Yes));
    }

    Err(ServiceParseError::InvalidOption)
}

// ── Help text generation ──────────────────────────────────────────────────

/// Build the help text for a service program.
///
/// Mirrors the C `help()` function, including optional sections for
/// bus-introspect and runtime-scope depending on `flags`.
pub fn build_help_text(
    program_path: &str,
    service: &str,
    description: &str,
    flags: HelpFlags,
) -> String {
    let mut lines = String::new();

    lines.push_str(program_path);
    lines.push_str(" [OPTIONS...]\n\n");
    lines.push_str(description);
    lines.push_str("\n\nThis program takes no positional arguments.\n\n");
    lines.push_str("Options:\n");
    lines.push_str("  -h --help                 Show this help\n");
    lines.push_str("     --version              Show package version\n");

    if flags.contains(HelpFlags::BUS_INTROSPECT) {
        lines.push_str("     --bus-introspect=PATH  Write D-Bus XML introspection data\n");
    }
    if flags.contains(HelpFlags::RUNTIME_SCOPE) {
        lines.push_str("     --system               Start service in system mode\n");
        lines.push_str("     --user                 Start service in user mode\n");
    }

    lines.push_str("\nSee the ");
    lines.push_str(service);
    lines.push_str("(8) man page for details.\n");

    lines
}

// ── Main parser ───────────────────────────────────────────────────────────

/// Parse service command-line arguments.
///
/// Returns `Ok(ServiceAction)` describing what the caller should do next.
///
/// * `args`            – slice of argument strings (program name excluded).
/// * `service`         – service name (e.g. `"systemd-logind"`), used in help text.
/// * `description`     – one-line description for help output.
/// * `flags`           – which optional features are available.
/// * `runtime_scope`   – optional mutable reference to store `--system`/`--user`.
pub fn service_parse_argv(
    args: &[&str],
    service: &str,
    description: &str,
    flags: HelpFlags,
    runtime_scope: Option<&mut RuntimeScope>,
) -> Result<ServiceAction, ServiceParseError> {
    let allow_introspect = flags.contains(HelpFlags::BUS_INTROSPECT);
    let allow_scope = flags.contains(HelpFlags::RUNTIME_SCOPE);
    let help_flags = flags;
    let mut runtime_scope = runtime_scope;

    let mut i = 0;
    while i < args.len() {
        let arg = args[i];
        let next = args.get(i + 1).copied();

        // Stop at "--" separator; anything after is a positional arg
        if arg == "--" {
            i += 1;
            break;
        }

        // Positional argument (doesn't start with '-')
        if !arg.starts_with('-') {
            return Err(ServiceParseError::UnexpectedArgument);
        }

        match lex_token(arg, next) {
            Ok((Token::Help, _consumed_next)) => {
                let help_text = build_help_text(
                    // Use arg[0] as program path if available, else service name
                    args.first().copied().unwrap_or(service),
                    service,
                    description,
                    help_flags,
                );
                return Ok(ServiceAction::ShowHelp(help_text));
            }
            Ok((Token::Version, _)) => {
                return Ok(ServiceAction::ShowVersion);
            }
            Ok((Token::BusIntrospect(path), ConsumedNext::Yes)) => {
                if !allow_introspect {
                    return Err(ServiceParseError::InvalidOption);
                }
                i += 1; // skip the value arg we consumed
                return Ok(ServiceAction::BusIntrospect(path));
            }
            Ok((Token::BusIntrospect(path), ConsumedNext::No)) => {
                if !allow_introspect {
                    return Err(ServiceParseError::InvalidOption);
                }
                return Ok(ServiceAction::BusIntrospect(path));
            }
            Ok((Token::System, _)) => {
                if !allow_scope {
                    return Err(ServiceParseError::ScopeNotSupported);
                }
                if let Some(scope) = runtime_scope.as_mut() {
                    **scope = RuntimeScope::System;
                } else {
                    return Err(ServiceParseError::ScopeNotSupported);
                }
            }
            Ok((Token::User, _)) => {
                if !allow_scope {
                    return Err(ServiceParseError::ScopeNotSupported);
                }
                if let Some(scope) = runtime_scope.as_mut() {
                    **scope = RuntimeScope::User;
                } else {
                    return Err(ServiceParseError::ScopeNotSupported);
                }
            }
            Err(e) => return Err(e),
        }

        i += 1;
    }

    // Check for unexpected positional arguments after the loop
    if i < args.len() {
        return Err(ServiceParseError::UnexpectedArgument);
    }

    Ok(ServiceAction::Continue)
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn all_flags() -> HelpFlags {
        HelpFlags::BUS_INTROSPECT | HelpFlags::RUNTIME_SCOPE
    }

    #[test]
    fn test_empty_args_continue() {
        let result = service_parse_argv(&[], "systemd-test", "A test service", all_flags(), None);
        assert_eq!(result.unwrap(), ServiceAction::Continue);
    }

    #[test]
    fn test_help_short() {
        let result =
            service_parse_argv(&["-h"], "systemd-test", "A test service", all_flags(), None);
        match result.unwrap() {
            ServiceAction::ShowHelp(text) => {
                assert!(text.contains("Show this help"));
                assert!(text.contains("systemd-test"));
            }
            other => panic!("Expected ShowHelp, got {:?}", other),
        }
    }

    #[test]
    fn test_help_long() {
        let result = service_parse_argv(
            &["--help"],
            "systemd-test",
            "A test service",
            all_flags(),
            None,
        );
        match result.unwrap() {
            ServiceAction::ShowHelp(text) => {
                assert!(text.contains("Options:"));
            }
            other => panic!("Expected ShowHelp, got {:?}", other),
        }
    }

    #[test]
    fn test_version() {
        let result = service_parse_argv(
            &["--version"],
            "systemd-test",
            "A test service",
            all_flags(),
            None,
        );
        assert_eq!(result.unwrap(), ServiceAction::ShowVersion);
    }

    #[test]
    fn test_system_scope() {
        let mut scope = RuntimeScope::User;
        let result = service_parse_argv(
            &["--system"],
            "systemd-test",
            "A test service",
            HelpFlags::RUNTIME_SCOPE,
            Some(&mut scope),
        );
        assert_eq!(result.unwrap(), ServiceAction::Continue);
        assert_eq!(scope, RuntimeScope::System);
    }

    #[test]
    fn test_user_scope() {
        let mut scope = RuntimeScope::System;
        let result = service_parse_argv(
            &["--user"],
            "systemd-test",
            "A test service",
            HelpFlags::RUNTIME_SCOPE,
            Some(&mut scope),
        );
        assert_eq!(result.unwrap(), ServiceAction::Continue);
        assert_eq!(scope, RuntimeScope::User);
    }

    #[test]
    fn test_scope_without_flag_rejected() {
        let mut scope = RuntimeScope::System;
        let result = service_parse_argv(
            &["--system"],
            "systemd-test",
            "A test service",
            HelpFlags::empty(),
            Some(&mut scope),
        );
        assert_eq!(result.unwrap_err(), ServiceParseError::ScopeNotSupported);
    }

    #[test]
    fn test_scope_without_mut_ref_rejected() {
        let result = service_parse_argv(
            &["--user"],
            "systemd-test",
            "A test service",
            HelpFlags::RUNTIME_SCOPE,
            None,
        );
        assert_eq!(result.unwrap_err(), ServiceParseError::ScopeNotSupported);
    }

    #[test]
    fn test_bus_introspect_inline_value() {
        let result = service_parse_argv(
            &["--bus-introspect=/tmp/out.xml"],
            "systemd-test",
            "A test service",
            HelpFlags::BUS_INTROSPECT,
            None,
        );
        assert_eq!(
            result.unwrap(),
            ServiceAction::BusIntrospect("/tmp/out.xml".to_string())
        );
    }

    #[test]
    fn test_bus_introspect_separate_value() {
        let result = service_parse_argv(
            &["--bus-introspect", "/tmp/out.xml"],
            "systemd-test",
            "A test service",
            HelpFlags::BUS_INTROSPECT,
            None,
        );
        assert_eq!(
            result.unwrap(),
            ServiceAction::BusIntrospect("/tmp/out.xml".to_string())
        );
    }

    #[test]
    fn test_bus_introspect_without_flag_rejected() {
        let result = service_parse_argv(
            &["--bus-introspect=/tmp/out.xml"],
            "systemd-test",
            "A test service",
            HelpFlags::empty(),
            None,
        );
        assert_eq!(result.unwrap_err(), ServiceParseError::InvalidOption);
    }

    #[test]
    fn test_unknown_option_rejected() {
        let result = service_parse_argv(
            &["--nope"],
            "systemd-test",
            "A test service",
            all_flags(),
            None,
        );
        assert_eq!(result.unwrap_err(), ServiceParseError::InvalidOption);
    }

    #[test]
    fn test_positional_argument_rejected() {
        let result = service_parse_argv(
            &["foobar"],
            "systemd-test",
            "A test service",
            all_flags(),
            None,
        );
        assert_eq!(result.unwrap_err(), ServiceParseError::UnexpectedArgument);
    }

    #[test]
    fn test_help_text_includes_introspect_when_flag_set() {
        let text = build_help_text("prog", "systemd-test", "desc", HelpFlags::BUS_INTROSPECT);
        assert!(text.contains("bus-introspect=PATH"));
    }

    #[test]
    fn test_help_text_excludes_introspect_when_flag_unset() {
        let text = build_help_text("prog", "systemd-test", "desc", HelpFlags::empty());
        assert!(!text.contains("bus-introspect"));
    }

    #[test]
    fn test_help_text_includes_scope_when_flag_set() {
        let text = build_help_text("prog", "systemd-test", "desc", HelpFlags::RUNTIME_SCOPE);
        assert!(text.contains("--system"));
        assert!(text.contains("--user"));
    }

    #[test]
    fn test_help_text_excludes_scope_when_flag_unset() {
        let text = build_help_text("prog", "systemd-test", "desc", HelpFlags::empty());
        // "system" should not appear as a flag option
        assert!(!text.contains("--system"));
        assert!(!text.contains("--user"));
    }

    #[test]
    fn test_double_dash_stops_parsing() {
        let result = service_parse_argv(
            &["--", "positional"],
            "systemd-test",
            "A test service",
            all_flags(),
            None,
        );
        assert_eq!(result.unwrap_err(), ServiceParseError::UnexpectedArgument);
    }

    #[test]
    fn test_combined_scope_and_continue() {
        let mut scope = RuntimeScope::System;
        let result = service_parse_argv(
            &["--user"],
            "systemd-test",
            "A test service",
            HelpFlags::RUNTIME_SCOPE,
            Some(&mut scope),
        );
        assert_eq!(result.unwrap(), ServiceAction::Continue);
        assert_eq!(scope, RuntimeScope::User);
    }

    #[test]
    fn test_lex_token_invalid_short() {
        assert_eq!(
            lex_token("-x", None).unwrap_err(),
            ServiceParseError::InvalidOption
        );
    }

    #[test]
    fn test_lex_token_unknown_long() {
        assert_eq!(
            lex_token("--nope", None).unwrap_err(),
            ServiceParseError::InvalidOption
        );
    }

    #[test]
    fn test_error_display_messages() {
        assert!(
            ServiceParseError::InvalidOption
                .to_string()
                .contains("Unrecognised")
        );
        assert!(
            ServiceParseError::UnexpectedArgument
                .to_string()
                .contains("no positional")
        );
        assert!(
            ServiceParseError::ScopeNotSupported
                .to_string()
                .contains("refusing")
        );
    }
}
