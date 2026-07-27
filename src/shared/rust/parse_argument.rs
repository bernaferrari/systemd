// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/parse-argument.c, src/shared/parse-argument.h
//
// Command-line argument parsing utilities.
//
// Provides parsers for boolean, tristate, JSON format, path, signal,
// machine, and background color arguments used across systemd tools.
// All functions in this file correspond to their C counterparts and
// follow idiomatic Rust error-handling conventions.

use std::fmt;

// ── Error type ─────────────────────────────────────────────────────────────

/// Errors produced by argument parsing functions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseArgumentError {
    /// The input could not be parsed as a boolean value.
    InvalidBoolean(String),
    /// The input could not be parsed as a tristate (auto/true/false) value.
    InvalidTristate(String),
    /// The JSON format string is not one of pretty/short/off/help.
    InvalidJsonFormat(String),
    /// The path could not be normalised or made absolute.
    InvalidPath(String),
    /// The signal name or number could not be resolved.
    InvalidSignal(String),
    /// The machine specifier is not a valid hostname or host:container pair.
    InvalidMachine(String),
    /// The background argument is not a valid ANSI color code.
    InvalidBackground(String),
}

impl fmt::Display for ParseArgumentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidBoolean(s) => write!(f, "Failed to parse boolean argument: {s}"),
            Self::InvalidTristate(s) => write!(f, "Failed to parse tristate argument: {s}"),
            Self::InvalidJsonFormat(s) => write!(f, "Unknown --json= argument: {s}"),
            Self::InvalidPath(s) => write!(f, "Failed to parse path and make it absolute: {s}"),
            Self::InvalidSignal(s) => write!(f, "Failed to parse signal string: {s}"),
            Self::InvalidMachine(s) => write!(f, "Invalid --machine= argument: {s}"),
            Self::InvalidBackground(s) => write!(f, "Invalid --background= argument: {s}"),
        }
    }
}

impl std::error::Error for ParseArgumentError {}

// ── JSON format ────────────────────────────────────────────────────────────

/// JSON output format modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JsonFormat {
    Pretty,
    Short,
    Off,
}

/// Result of parsing a `--json=` argument.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JsonParseResult {
    /// A known format was selected.
    Format(JsonFormat),
    /// The user asked for `--json=help`; the caller should print the list and exit.
    Help,
}

// ── Signal parsing result ──────────────────────────────────────────────────

/// Result of parsing a `--signal` argument.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignalParseResult {
    /// A valid signal number was resolved.
    Signal(i32),
    /// The user asked for `--signal=help`; the caller should list signal names and exit.
    Help,
    /// The user asked for `--signal=list`; the caller should print a signal table and exit.
    List,
}

// ── Bus transport ──────────────────────────────────────────────────────────

/// D-Bus transport mode used when connecting to a machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BusTransport {
    Local,
    Remote,
    Machine,
    Execution,
}

// ── Machine info ───────────────────────────────────────────────────────────

/// Validated machine specifier returned by [`parse_machine_argument`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachineInfo {
    pub host: String,
    pub transport: BusTransport,
}

// ── Boolean parsing ────────────────────────────────────────────────────────

/// Parse an optional boolean argument.
///
/// Mirrors the C `parse_boolean_argument`: when `value` is `None` the option
/// flag is considered present without an explicit operand and defaults to
/// `true`.  When `value` is `Some(s)`, the string is interpreted as a boolean.
pub fn parse_boolean_argument(value: Option<&str>) -> Result<bool, ParseArgumentError> {
    match value {
        None => Ok(true),
        Some(s) => parse_boolean_str(s),
    }
}

/// Interpret a string as a boolean value (1/yes/true/on → true,
/// 0/no/false/off → false).
fn parse_boolean_str(s: &str) -> Result<bool, ParseArgumentError> {
    match s {
        "1" | "yes" | "true" | "on" => Ok(true),
        "0" | "no" | "false" | "off" => Ok(false),
        _ => Err(ParseArgumentError::InvalidBoolean(s.to_owned())),
    }
}

// ── Tristate parsing ───────────────────────────────────────────────────────

/// Parse a tristate argument that accepts "auto" in addition to boolean values.
///
/// Returns `Ok(None)` for `"auto"`, `Ok(Some(true/false))` for booleans.
pub fn parse_tristate_argument_with_auto(value: &str) -> Result<Option<bool>, ParseArgumentError> {
    match value {
        "auto" => Ok(None),
        _ => parse_boolean_argument(Some(value)).map(Some),
    }
}

// ── JSON format parsing ────────────────────────────────────────────────────

/// Parse a `--json=` argument value.
///
/// Returns [`JsonParseResult::Help`] when the value is `"help"`, which tells
/// the caller to display the available options and exit.
pub fn parse_json_argument(value: &str) -> Result<JsonParseResult, ParseArgumentError> {
    match value {
        "pretty" => Ok(JsonParseResult::Format(JsonFormat::Pretty)),
        "short" => Ok(JsonParseResult::Format(JsonFormat::Short)),
        "off" => Ok(JsonParseResult::Format(JsonFormat::Off)),
        "help" => Ok(JsonParseResult::Help),
        _ => Err(ParseArgumentError::InvalidJsonFormat(value.to_owned())),
    }
}

// ── Path parsing ───────────────────────────────────────────────────────────

/// Parse and normalise a path argument.
///
/// Makes the path absolute (prepending `cwd` when the path is relative),
/// simplifies `.` and `..` components, and optionally suppresses the root
/// path (`"/"`) by returning `None`.
///
/// When `path` is empty the result is `Ok(None)`, mirroring the C behaviour
/// of clearing the previous argument pointer.
pub fn parse_path_argument(
    path: &str,
    suppress_root: bool,
    cwd: &str,
) -> Result<Option<String>, ParseArgumentError> {
    if path.is_empty() {
        return Ok(None);
    }

    let absolute = if path.starts_with('/') {
        path.to_owned()
    } else {
        let mut base = cwd.to_owned();
        if !base.ends_with('/') {
            base.push('/');
        }
        base.push_str(path);
        base
    };

    let simplified = path_simplify(&absolute);

    if suppress_root && (simplified == "/" || simplified.is_empty()) {
        return Ok(None);
    }

    Ok(Some(simplified))
}

// ── Signal parsing ─────────────────────────────────────────────────────────

/// Linux signal table (name without "SIG" prefix, number).
static LINUX_SIGNALS: &[(&str, i32)] = &[
    ("HUP", 1),
    ("INT", 2),
    ("QUIT", 3),
    ("ILL", 4),
    ("TRAP", 5),
    ("ABRT", 6),
    ("BUS", 7),
    ("FPE", 8),
    ("KILL", 9),
    ("USR1", 10),
    ("SEGV", 11),
    ("USR2", 12),
    ("PIPE", 13),
    ("ALRM", 14),
    ("TERM", 15),
    ("STKFLT", 16),
    ("CHLD", 17),
    ("CONT", 18),
    ("STOP", 19),
    ("TSTP", 20),
    ("TTIN", 21),
    ("TTOU", 22),
    ("URG", 23),
    ("XCPU", 24),
    ("XFSZ", 25),
    ("VTALRM", 26),
    ("PROF", 27),
    ("WINCH", 28),
    ("IO", 29),
    ("PWR", 30),
    ("SYS", 31),
];

/// Parse a signal argument.
///
/// Recognises `"help"` and `"list"` as special values, numeric strings
/// (`"15"`), and signal names with or without the `"SIG"` prefix
/// (`"TERM"` or `"SIGTERM"`).
pub fn parse_signal_argument(s: &str) -> Result<SignalParseResult, ParseArgumentError> {
    if s == "help" {
        return Ok(SignalParseResult::Help);
    }
    if s == "list" {
        return Ok(SignalParseResult::List);
    }

    // Try numeric first.
    if let Ok(n) = s.parse::<i32>() {
        if n > 0 {
            return Ok(SignalParseResult::Signal(n));
        }
    }

    // Try name lookup (strip optional "SIG" prefix).
    let name = if s.len() > 3 && s[..3].eq_ignore_ascii_case("SIG") {
        &s[3..]
    } else {
        s
    };
    for &(signal_name, num) in LINUX_SIGNALS {
        if name.eq_ignore_ascii_case(signal_name) {
            return Ok(SignalParseResult::Signal(num));
        }
    }

    Err(ParseArgumentError::InvalidSignal(s.to_owned()))
}

// ── Machine parsing ────────────────────────────────────────────────────────

/// Parse a `--machine=` argument.
///
/// Validates the machine specifier as either a plain hostname or a
/// `host:container` pair.  On success, returns a [`MachineInfo`] with the
/// validated host string and a [`BusTransport::Machine`] transport.
pub fn parse_machine_argument(s: &str) -> Result<MachineInfo, ParseArgumentError> {
    if !is_valid_machine_spec(s) {
        return Err(ParseArgumentError::InvalidMachine(s.to_owned()));
    }

    Ok(MachineInfo {
        host: s.to_owned(),
        transport: BusTransport::Machine,
    })
}

// ── Background color parsing ───────────────────────────────────────────────

/// Parse a `--background=` argument.
///
/// The argument must either be empty or look like a valid ANSI SGR color code
/// (semicolon-separated decimal numbers such as `"1;31"` or `"38;5;196"`).
/// Returns the validated string on success.
pub fn parse_background_argument(s: &str) -> Result<String, ParseArgumentError> {
    if !s.is_empty() && !looks_like_ansi_color_code(s) {
        return Err(ParseArgumentError::InvalidBackground(s.to_owned()));
    }
    Ok(s.to_owned())
}

// ── Helper functions ───────────────────────────────────────────────────────

/// Simplify a path by collapsing `//`, `.`, and `..` components.
///
/// Does not touch the filesystem — purely lexical normalisation.
fn path_simplify(path: &str) -> String {
    let is_absolute = path.starts_with('/');
    let mut components: Vec<&str> = Vec::new();

    for part in path.split('/') {
        match part {
            "" | "." => continue,
            ".." => {
                if let Some(last) = components.last() {
                    if *last != ".." {
                        components.pop();
                        continue;
                    }
                }
                if !is_absolute {
                    components.push("..");
                }
            }
            _ => components.push(part),
        }
    }

    let result = if is_absolute {
        if components.is_empty() {
            "/".to_owned()
        } else {
            format!("/{}", components.join("/"))
        }
    } else if components.is_empty() {
        ".".to_owned()
    } else {
        components.join("/")
    };

    result
}

/// Check whether a string looks like an ANSI SGR color code.
///
/// Valid examples: `"31"`, `"1;31"`, `"38;5;196"`, `"48;2;255;128;0"`.
fn looks_like_ansi_color_code(s: &str) -> bool {
    s.split(';').all(|part| part.parse::<u32>().is_ok())
}

/// Check whether a string is a valid machine specifier.
///
/// Accepts a plain hostname or a `host:container` pair.  Each label must be
/// non-empty, at most 64 characters, start/end with an alphanumeric
/// character, and contain only ASCII alphanumerics, hyphens, or dots.
fn is_valid_machine_spec(s: &str) -> bool {
    if s.is_empty() || s.len() > 255 {
        return false;
    }

    if let Some((host, container)) = s.split_once(':') {
        is_valid_hostname_label(host) && is_valid_hostname_label(container)
    } else {
        is_valid_hostname_label(s)
    }
}

/// Validate a single hostname label.
fn is_valid_hostname_label(s: &str) -> bool {
    if s.is_empty() || s.len() > 64 {
        return false;
    }
    let bytes = s.as_bytes();
    let first = bytes[0];
    let last = bytes[bytes.len() - 1];
    if !first.is_ascii_alphanumeric() || !last.is_ascii_alphanumeric() {
        return false;
    }
    bytes
        .iter()
        .all(|&b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // -- boolean -----------------------------------------------------------

    #[test]
    fn test_parse_boolean_none_is_true() {
        assert_eq!(parse_boolean_argument(None), Ok(true));
    }

    #[test]
    fn test_parse_boolean_true_values() {
        for s in &["1", "yes", "true", "on"] {
            assert_eq!(
                parse_boolean_argument(Some(s)),
                Ok(true),
                "expected true for {s}"
            );
        }
    }

    #[test]
    fn test_parse_boolean_false_values() {
        for s in &["0", "no", "false", "off"] {
            assert_eq!(
                parse_boolean_argument(Some(s)),
                Ok(false),
                "expected false for {s}"
            );
        }
    }

    #[test]
    fn test_parse_boolean_invalid() {
        let err = parse_boolean_argument(Some("maybe")).unwrap_err();
        assert!(matches!(err, ParseArgumentError::InvalidBoolean(ref s) if s == "maybe"));
    }

    // -- tristate ----------------------------------------------------------

    #[test]
    fn test_parse_tristate_auto() {
        assert_eq!(parse_tristate_argument_with_auto("auto"), Ok(None));
    }

    #[test]
    fn test_parse_tristate_boolean_passthrough() {
        assert_eq!(parse_tristate_argument_with_auto("yes"), Ok(Some(true)));
        assert_eq!(parse_tristate_argument_with_auto("no"), Ok(Some(false)));
    }

    #[test]
    fn test_parse_tristate_invalid() {
        let err = parse_tristate_argument_with_auto("maybe").unwrap_err();
        assert!(matches!(err, ParseArgumentError::InvalidBoolean(_)));
    }

    // -- JSON format -------------------------------------------------------

    #[test]
    fn test_parse_json_formats() {
        assert_eq!(
            parse_json_argument("pretty"),
            Ok(JsonParseResult::Format(JsonFormat::Pretty))
        );
        assert_eq!(
            parse_json_argument("short"),
            Ok(JsonParseResult::Format(JsonFormat::Short))
        );
        assert_eq!(
            parse_json_argument("off"),
            Ok(JsonParseResult::Format(JsonFormat::Off))
        );
    }

    #[test]
    fn test_parse_json_help() {
        assert_eq!(parse_json_argument("help"), Ok(JsonParseResult::Help));
    }

    #[test]
    fn test_parse_json_invalid() {
        let err = parse_json_argument("xml").unwrap_err();
        assert!(matches!(err, ParseArgumentError::InvalidJsonFormat(ref s) if s == "xml"));
    }

    // -- path --------------------------------------------------------------

    #[test]
    fn test_parse_path_empty() {
        assert_eq!(parse_path_argument("", false, "/home"), Ok(None));
    }

    #[test]
    fn test_parse_path_absolute_unchanged() {
        assert_eq!(
            parse_path_argument("/usr/bin", false, "/home"),
            Ok(Some("/usr/bin".to_owned()))
        );
    }

    #[test]
    fn test_parse_path_relative_made_absolute() {
        assert_eq!(
            parse_path_argument("foo/bar", false, "/home/user"),
            Ok(Some("/home/user/foo/bar".to_owned()))
        );
    }

    #[test]
    fn test_parse_path_suppress_root() {
        assert_eq!(parse_path_argument("/", true, "/home"), Ok(None));
    }

    #[test]
    fn test_parse_path_suppress_root_off() {
        assert_eq!(
            parse_path_argument("/", false, "/home"),
            Ok(Some("/".to_owned()))
        );
    }

    #[test]
    fn test_parse_path_simplifies_dot_components() {
        assert_eq!(
            parse_path_argument("/usr/./bin", false, "/home"),
            Ok(Some("/usr/bin".to_owned()))
        );
    }

    #[test]
    fn test_parse_path_simplifies_dot_dot() {
        assert_eq!(
            parse_path_argument("/usr/local/../bin", false, "/home"),
            Ok(Some("/usr/bin".to_owned()))
        );
    }

    // -- signal ------------------------------------------------------------

    #[test]
    fn test_parse_signal_help() {
        assert_eq!(parse_signal_argument("help"), Ok(SignalParseResult::Help));
    }

    #[test]
    fn test_parse_signal_list() {
        assert_eq!(parse_signal_argument("list"), Ok(SignalParseResult::List));
    }

    #[test]
    fn test_parse_signal_by_number() {
        assert_eq!(
            parse_signal_argument("15"),
            Ok(SignalParseResult::Signal(15))
        );
    }

    #[test]
    fn test_parse_signal_by_name() {
        assert_eq!(
            parse_signal_argument("TERM"),
            Ok(SignalParseResult::Signal(15))
        );
    }

    #[test]
    fn test_parse_signal_by_name_with_sig_prefix() {
        assert_eq!(
            parse_signal_argument("SIGKILL"),
            Ok(SignalParseResult::Signal(9))
        );
    }

    #[test]
    fn test_parse_signal_by_name_case_insensitive() {
        assert_eq!(
            parse_signal_argument("sigterm"),
            Ok(SignalParseResult::Signal(15))
        );
    }

    #[test]
    fn test_parse_signal_invalid() {
        let err = parse_signal_argument("NOSUCHSIGNAL").unwrap_err();
        assert!(matches!(err, ParseArgumentError::InvalidSignal(_)));
    }

    // -- machine -----------------------------------------------------------

    #[test]
    fn test_parse_machine_valid_hostname() {
        let info = parse_machine_argument("myhost").unwrap();
        assert_eq!(info.host, "myhost");
        assert_eq!(info.transport, BusTransport::Machine);
    }

    #[test]
    fn test_parse_machine_valid_host_container() {
        let info = parse_machine_argument("host.example.com:container1").unwrap();
        assert_eq!(info.host, "host.example.com:container1");
    }

    #[test]
    fn test_parse_machine_empty() {
        assert!(parse_machine_argument("").is_err());
    }

    #[test]
    fn test_parse_machine_starts_with_hyphen() {
        assert!(parse_machine_argument("-bad").is_err());
    }

    // -- background --------------------------------------------------------

    #[test]
    fn test_parse_background_empty() {
        assert_eq!(parse_background_argument(""), Ok(String::new()));
    }

    #[test]
    fn test_parse_background_valid_ansi() {
        assert_eq!(parse_background_argument("31"), Ok("31".to_owned()));
        assert_eq!(parse_background_argument("1;31"), Ok("1;31".to_owned()));
        assert_eq!(
            parse_background_argument("38;5;196"),
            Ok("38;5;196".to_owned())
        );
    }

    #[test]
    fn test_parse_background_invalid() {
        let err = parse_background_argument("red").unwrap_err();
        assert!(matches!(err, ParseArgumentError::InvalidBackground(_)));
    }

    // -- path_simplify (unit) ----------------------------------------------

    #[test]
    fn test_path_simplify_root() {
        assert_eq!(path_simplify("/"), "/");
    }

    #[test]
    fn test_path_simplify_trailing_slash() {
        assert_eq!(path_simplify("/usr/bin/"), "/usr/bin");
    }

    #[test]
    fn test_path_simplify_double_slash() {
        assert_eq!(path_simplify("//usr//bin"), "/usr/bin");
    }

    #[test]
    fn test_path_simplify_dot_dot_above_root() {
        // ".." at root cannot go higher; stays at root.
        assert_eq!(path_simplify("/../../usr"), "/usr");
    }

    #[test]
    fn test_path_simplify_relative() {
        assert_eq!(path_simplify("foo/../bar"), "bar");
    }

    // -- hostname validation (unit) ----------------------------------------

    #[test]
    fn test_valid_hostname_labels() {
        assert!(is_valid_hostname_label("localhost"));
        assert!(is_valid_hostname_label("my-host"));
        assert!(is_valid_hostname_label("host.example.com"));
        assert!(is_valid_hostname_label("a"));
    }

    #[test]
    fn test_invalid_hostname_labels() {
        assert!(!is_valid_hostname_label(""));
        assert!(!is_valid_hostname_label("-bad"));
        assert!(!is_valid_hostname_label("bad-"));
        assert!(!is_valid_hostname_label("bad host"));
    }

    // -- looks_like_ansi_color_code (unit) ---------------------------------

    #[test]
    fn test_ansi_color_code_valid() {
        assert!(looks_like_ansi_color_code("0"));
        assert!(looks_like_ansi_color_code("31"));
        assert!(looks_like_ansi_color_code("1;31"));
        assert!(looks_like_ansi_color_code("38;5;196"));
        assert!(looks_like_ansi_color_code("48;2;255;128;0"));
    }

    #[test]
    fn test_ansi_color_code_invalid() {
        assert!(!looks_like_ansi_color_code("red"));
        assert!(!looks_like_ansi_color_code("31;abc"));
        assert!(!looks_like_ansi_color_code(";31"));
    }
}
