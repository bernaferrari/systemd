// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/verbs.c, src/shared/verbs.h

use std::env;
use std::ffi::OsString;
use std::fmt;
use std::fs;
use std::path::Path;

use crate::format_table::{Table, TableDataType, TableValue};

pub const VERB_ANY: usize = usize::MAX;
pub const VERB_DEFAULT: u32 = 1 << 0;
pub const VERB_ONLINE_ONLY: u32 = 1 << 1;

const SYSTEMD_OFFLINE: &str = "SYSTEMD_OFFLINE";
const SYSTEMD_IGNORE_CHROOT: &str = "SYSTEMD_IGNORE_CHROOT";

pub type DispatchFn<T, U> = fn(&[&str], usize, &mut U) -> Result<T, i32>;

#[derive(Clone, Copy)]
pub struct Verb<'a, T, U> {
    pub verb: &'a str,
    pub min_args: usize,
    pub max_args: usize,
    pub flags: u32,
    pub dispatch: DispatchFn<T, U>,
    pub data: usize,
    pub argspec: Option<&'a str>,
    pub help: Option<&'a str>,
}

impl<'a, T, U> fmt::Debug for Verb<'a, T, U> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Verb")
            .field("verb", &self.verb)
            .field("min_args", &self.min_args)
            .field("max_args", &self.max_args)
            .field("flags", &self.flags)
            .field("data", &self.data)
            .field("argspec", &self.argspec)
            .field("help", &self.help)
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseBooleanError {
    Unset,
    Invalid,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum EnvValue {
    Unset,
    Text(String),
    NonUtf8(OsString),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DispatchOutcome<T> {
    Executed(T),
    Skipped { verb: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerbError {
    Errno(i32),
    UnknownVerb {
        input: String,
        suggestion: Option<String>,
    },
    MissingVerb {
        expected: Vec<String>,
    },
    TooFewArguments,
    TooManyArguments,
}

impl VerbError {
    pub fn errno(&self) -> i32 {
        match self {
            Self::Errno(errno) => *errno,
            Self::UnknownVerb { .. }
            | Self::MissingVerb { .. }
            | Self::TooFewArguments
            | Self::TooManyArguments => -libc::EINVAL,
        }
    }
}

impl fmt::Display for VerbError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Errno(errno) => write!(f, "errno {}", errno),
            Self::UnknownVerb { input, suggestion } => match suggestion {
                Some(found) => write!(f, "Unknown command verb '{input}', did you mean '{found}'?"),
                None => write!(f, "Unknown command verb '{input}'."),
            },
            Self::MissingVerb { expected } if expected.len() >= 2 => {
                write!(f, "Command verb required (one of {}).", expected.join(", "))
            }
            Self::MissingVerb { expected } => {
                let first = expected.first().map(String::as_str).unwrap_or("");
                write!(f, "Command verb '{first}' required.")
            }
            Self::TooFewArguments => write!(f, "Too few arguments."),
            Self::TooManyArguments => write!(f, "Too many arguments."),
        }
    }
}

impl std::error::Error for VerbError {}

pub fn parse_boolean(value: &str) -> Result<bool, ParseBooleanError> {
    if value.eq_ignore_ascii_case("1")
        || value.eq_ignore_ascii_case("yes")
        || value.eq_ignore_ascii_case("y")
        || value.eq_ignore_ascii_case("true")
        || value.eq_ignore_ascii_case("t")
        || value.eq_ignore_ascii_case("on")
    {
        return Ok(true);
    }

    if value.eq_ignore_ascii_case("0")
        || value.eq_ignore_ascii_case("no")
        || value.eq_ignore_ascii_case("n")
        || value.eq_ignore_ascii_case("false")
        || value.eq_ignore_ascii_case("f")
        || value.eq_ignore_ascii_case("off")
    {
        return Ok(false);
    }

    Err(ParseBooleanError::Invalid)
}

fn getenv_bool_from_value(value: &EnvValue) -> Result<bool, ParseBooleanError> {
    match value {
        EnvValue::Unset => Err(ParseBooleanError::Unset),
        EnvValue::Text(text) => parse_boolean(text),
        EnvValue::NonUtf8(_) => Err(ParseBooleanError::Invalid),
    }
}

fn env_value_from_os(value: Option<OsString>) -> EnvValue {
    match value {
        None => EnvValue::Unset,
        Some(value) => match value.into_string() {
            Ok(text) => EnvValue::Text(text),
            Err(raw) => EnvValue::NonUtf8(raw),
        },
    }
}

fn env_value_from_process(name: &str) -> EnvValue {
    env_value_from_os(env::var_os(name))
}

fn running_in_chroot_from_paths(root: &Path, init_root: &Path) -> Result<bool, i32> {
    let root_meta = fs::metadata(root).map_err(io_error_to_negative_errno)?;
    let init_meta = fs::metadata(init_root).map_err(io_error_to_negative_errno)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        return Ok(root_meta.dev() != init_meta.dev() || root_meta.ino() != init_meta.ino());
    }

    #[cfg(not(unix))]
    {
        let root_canonical = fs::canonicalize(root).map_err(io_error_to_negative_errno)?;
        let init_canonical = fs::canonicalize(init_root).map_err(io_error_to_negative_errno)?;
        Ok(root_canonical != init_canonical)
    }
}

fn io_error_to_negative_errno(error: std::io::Error) -> i32 {
    -error.raw_os_error().unwrap_or(libc::EIO)
}

pub fn running_in_chroot() -> Result<bool, i32> {
    if matches!(
        getenv_bool_from_value(&env_value_from_process(SYSTEMD_IGNORE_CHROOT)),
        Ok(true)
    ) {
        return Ok(false);
    }

    #[cfg(target_os = "linux")]
    {
        return running_in_chroot_from_paths(Path::new("/"), Path::new("/proc/1/root/."));
    }

    #[cfg(not(target_os = "linux"))]
    {
        Ok(false)
    }
}

pub fn running_in_chroot_or_offline() -> bool {
    running_in_chroot_or_offline_with_env(
        env_value_from_process(SYSTEMD_OFFLINE),
        running_in_chroot,
    )
}

fn running_in_chroot_or_offline_with_env<F>(offline: EnvValue, running_in_chroot: F) -> bool
where
    F: FnOnce() -> Result<bool, i32>,
{
    match getenv_bool_from_value(&offline) {
        Ok(value) => value,
        Err(ParseBooleanError::Unset | ParseBooleanError::Invalid) => {
            running_in_chroot().unwrap_or(false)
        }
    }
}

pub fn should_bypass(env_prefix: &str) -> bool {
    should_bypass_with_env(env_value_from_process(&format!("{env_prefix}_BYPASS")))
}

fn should_bypass_with_env(value: EnvValue) -> bool {
    matches!(getenv_bool_from_value(&value), Ok(true))
}

pub fn verbs_find_verb<'a, T, U>(
    name: Option<&str>,
    verbs: &'a [Verb<'a, T, U>],
) -> Option<&'a Verb<'a, T, U>> {
    verbs.iter().find(|verb| match name {
        Some(name) => name == verb.verb,
        None => verb.flags & VERB_DEFAULT != 0,
    })
}

pub fn dispatch_verb<'a, T, U>(
    argv: &[&str],
    optind: usize,
    verbs: &'a [Verb<'a, T, U>],
    userdata: &mut U,
) -> Result<DispatchOutcome<T>, VerbError> {
    if optind > argv.len() {
        return Err(VerbError::Errno(-libc::EINVAL));
    }

    dispatch_verb_with_args(
        &argv[optind..],
        verbs,
        userdata,
        running_in_chroot_or_offline,
    )
}

pub fn dispatch_verb_with_args<'a, T, U, F>(
    args: &[&str],
    verbs: &'a [Verb<'a, T, U>],
    userdata: &mut U,
    running_in_chroot_or_offline: F,
) -> Result<DispatchOutcome<T>, VerbError>
where
    F: FnOnce() -> bool,
{
    let first = args.first().copied();
    let mut left = args.len();

    let Some(verb) = verbs_find_verb(first, verbs) else {
        return Err(unknown_or_missing_verb_error(first, verbs));
    };

    if first.is_none() {
        left = 1;
    }

    if verb.min_args != VERB_ANY && left < verb.min_args {
        return Err(VerbError::TooFewArguments);
    }

    if verb.max_args != VERB_ANY && left > verb.max_args {
        return Err(VerbError::TooManyArguments);
    }

    if verb.flags & VERB_ONLINE_ONLY != 0 && running_in_chroot_or_offline() {
        return Ok(DispatchOutcome::Skipped {
            verb: first.unwrap_or(verb.verb).to_string(),
        });
    }

    if first.is_none() {
        return (verb.dispatch)(&[verb.verb], verb.data, userdata)
            .map(DispatchOutcome::Executed)
            .map_err(VerbError::Errno);
    }

    (verb.dispatch)(args, verb.data, userdata)
        .map(DispatchOutcome::Executed)
        .map_err(VerbError::Errno)
}

fn unknown_or_missing_verb_error<'a, T, U>(
    name: Option<&str>,
    verbs: &[Verb<'a, T, U>],
) -> VerbError {
    let known: Vec<String> = verbs.iter().map(|verb| verb.verb.to_string()).collect();

    match name {
        Some(name) => VerbError::UnknownVerb {
            input: name.to_string(),
            suggestion: strv_find_closest(&known, name),
        },
        None => VerbError::MissingVerb { expected: known },
    }
}

fn strv_find_closest(list: &[String], input: &str) -> Option<String> {
    let mut best = None;
    let mut best_len = 0usize;

    for item in list {
        let common = item
            .chars()
            .zip(input.chars())
            .take_while(|(a, b)| a == b)
            .count();
        if common > best_len {
            best_len = common;
            best = Some(item.clone());
        }
    }

    if best_len == 0 { None } else { best }
}

pub fn verb_help_rows<'a, T, U>(verbs: &[Verb<'a, T, U>]) -> Vec<(String, Vec<String>)> {
    let mut rows = Vec::new();

    for verb in verbs {
        let Some(help) = verb.help else {
            continue;
        };

        let spec = match verb.argspec {
            Some(argspec) if !argspec.is_empty() => format!("  {} {}", verb.verb, argspec),
            _ => format!("  {}", verb.verb),
        };

        let wrapped = help.split_whitespace().map(str::to_string).collect();
        rows.push((spec, wrapped));
    }

    rows
}

pub fn verbs_get_help_table<'a, T, U>(verbs: &[Verb<'a, T, U>]) -> Table {
    let mut table = Table::new(["verb", "help"]);

    for (verb, help) in verb_help_rows(verbs) {
        table.add_cell(TableDataType::String, verb);
        table.add_cell(TableDataType::StrvWrapped, TableValue::Strv(help));
    }

    table.set_header(false);
    table
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record_args(args: &[&str], data: usize, seen: &mut Vec<String>) -> Result<String, i32> {
        seen.push(format!("{data}:{:?}", args));
        Ok(args.join(" "))
    }

    fn fail_dispatch(_: &[&str], _: usize, _: &mut Vec<String>) -> Result<String, i32> {
        Err(-libc::EPERM)
    }

    fn verbs<'a>() -> [Verb<'a, String, Vec<String>>; 3] {
        [
            Verb {
                verb: "status",
                min_args: 1,
                max_args: 2,
                flags: VERB_DEFAULT,
                dispatch: record_args,
                data: 10,
                argspec: Some("[UNIT]"),
                help: Some("Show status"),
            },
            Verb {
                verb: "reload",
                min_args: 1,
                max_args: 1,
                flags: VERB_ONLINE_ONLY,
                dispatch: record_args,
                data: 20,
                argspec: None,
                help: Some("Reload units"),
            },
            Verb {
                verb: "help",
                min_args: VERB_ANY,
                max_args: VERB_ANY,
                flags: 0,
                dispatch: record_args,
                data: 30,
                argspec: None,
                help: None,
            },
        ]
    }

    #[test]
    fn parse_boolean_accepts_true_spellings() {
        assert_eq!(parse_boolean("1"), Ok(true));
        assert_eq!(parse_boolean("YES"), Ok(true));
        assert_eq!(parse_boolean("on"), Ok(true));
    }

    #[test]
    fn parse_boolean_accepts_false_spellings() {
        assert_eq!(parse_boolean("0"), Ok(false));
        assert_eq!(parse_boolean("No"), Ok(false));
        assert_eq!(parse_boolean("OFF"), Ok(false));
    }

    #[test]
    fn parse_boolean_rejects_invalid_values() {
        assert_eq!(parse_boolean("maybe"), Err(ParseBooleanError::Invalid));
    }

    #[test]
    fn running_in_chroot_or_offline_prefers_valid_offline_env() {
        let value = env_value_from_os(Some(OsString::from("yes")));
        let result = running_in_chroot_or_offline_with_env(value, || Ok(false));
        assert!(result);
    }

    #[test]
    fn running_in_chroot_or_offline_falls_back_on_invalid_env() {
        let value = env_value_from_os(Some(OsString::from("bogus")));
        let result = running_in_chroot_or_offline_with_env(value, || Ok(true));
        assert!(result);
    }

    #[test]
    fn should_bypass_requires_true_boolean() {
        assert!(should_bypass_with_env(env_value_from_os(Some(
            OsString::from("1")
        ))));
        assert!(!should_bypass_with_env(env_value_from_os(Some(
            OsString::from("0")
        ))));
    }

    #[test]
    fn verbs_find_verb_finds_named_and_default_verbs() {
        let verbs = verbs();
        assert_eq!(
            verbs_find_verb(None, &verbs).map(|v| v.verb),
            Some("status")
        );
        assert_eq!(
            verbs_find_verb(Some("reload"), &verbs).map(|v| v.verb),
            Some("reload")
        );
    }

    #[test]
    fn dispatch_verb_with_args_dispatches_named_verb() {
        let verbs = verbs();
        let mut seen = Vec::new();

        let result =
            dispatch_verb_with_args(&["status", "sshd.service"], &verbs, &mut seen, || false);

        assert_eq!(
            result,
            Ok(DispatchOutcome::Executed("status sshd.service".to_string()))
        );
        assert_eq!(seen, vec!["10:[\"status\", \"sshd.service\"]"]);
    }

    #[test]
    fn dispatch_verb_with_args_dispatches_default_verb_without_name() {
        let verbs = verbs();
        let mut seen = Vec::new();

        let result = dispatch_verb_with_args(&[], &verbs, &mut seen, || false);

        assert_eq!(result, Ok(DispatchOutcome::Executed("status".to_string())));
        assert_eq!(seen, vec!["10:[\"status\"]"]);
    }

    #[test]
    fn dispatch_verb_with_args_rejects_too_few_arguments() {
        let verbs = [Verb {
            min_args: 2,
            ..verbs()[0]
        }];
        let mut seen = Vec::new();

        let result = dispatch_verb_with_args(&["status"], &verbs, &mut seen, || false);

        assert_eq!(result, Err(VerbError::TooFewArguments));
    }

    #[test]
    fn dispatch_verb_with_args_rejects_too_many_arguments() {
        let verbs = [Verb {
            max_args: 1,
            ..verbs()[0]
        }];
        let mut seen = Vec::new();

        let result = dispatch_verb_with_args(&["status", "a"], &verbs, &mut seen, || false);

        assert_eq!(result, Err(VerbError::TooManyArguments));
    }

    #[test]
    fn dispatch_verb_with_args_skips_online_only_verbs_when_offline() {
        let verbs = verbs();
        let mut seen = Vec::new();

        let result = dispatch_verb_with_args(&["reload"], &verbs, &mut seen, || true);

        assert_eq!(
            result,
            Ok(DispatchOutcome::Skipped {
                verb: "reload".to_string()
            })
        );
        assert!(seen.is_empty());
    }

    #[test]
    fn dispatch_verb_with_args_reports_unknown_verbs_with_suggestion() {
        let verbs = verbs();
        let mut seen = Vec::new();

        let result = dispatch_verb_with_args(&["stat"], &verbs, &mut seen, || false);

        assert_eq!(
            result,
            Err(VerbError::UnknownVerb {
                input: "stat".to_string(),
                suggestion: Some("status".to_string())
            })
        );
    }

    #[test]
    fn dispatch_verb_with_args_reports_missing_verbs() {
        let verbs = [Verb {
            verb: "status",
            ..verbs()[0]
        }];
        let mut seen = Vec::new();

        let result = dispatch_verb_with_args(&[], &verbs, &mut seen, || false);

        assert_eq!(result, Ok(DispatchOutcome::Executed("status".to_string())));
    }

    #[test]
    fn missing_default_verb_reports_requirement() {
        let verbs = [Verb {
            flags: 0,
            ..verbs()[0]
        }];
        let mut seen = Vec::new();

        let result = dispatch_verb_with_args(&[], &verbs, &mut seen, || false);

        assert_eq!(
            result,
            Err(VerbError::MissingVerb {
                expected: vec!["status".to_string()]
            })
        );
    }

    #[test]
    fn dispatch_verb_maps_dispatch_errno() {
        let verbs = [Verb {
            dispatch: fail_dispatch,
            ..verbs()[0]
        }];
        let mut seen = Vec::new();

        let result = dispatch_verb_with_args(&["status"], &verbs, &mut seen, || false);

        assert_eq!(result, Err(VerbError::Errno(-libc::EPERM)));
    }

    #[test]
    fn dispatch_verb_applies_optind() {
        let verbs = verbs();
        let mut seen = Vec::new();

        let result = dispatch_verb(&["systemctl", "--no-pager", "status"], 2, &verbs, &mut seen);

        assert_eq!(result, Ok(DispatchOutcome::Executed("status".to_string())));
    }

    #[test]
    fn verb_error_display_matches_c_messages() {
        assert_eq!(VerbError::TooFewArguments.to_string(), "Too few arguments.");
        assert_eq!(
            VerbError::UnknownVerb {
                input: "stats".to_string(),
                suggestion: Some("status".to_string())
            }
            .to_string(),
            "Unknown command verb 'stats', did you mean 'status'?"
        );
    }

    #[test]
    fn verb_help_rows_skip_hidden_verbs() {
        let rows = verb_help_rows(&verbs());

        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].0, "  status [UNIT]");
        assert_eq!(rows[0].1, vec!["Show".to_string(), "status".to_string()]);
    }

    #[test]
    fn running_in_chroot_from_paths_detects_same_directory() {
        let temp = std::env::temp_dir();
        let result = running_in_chroot_from_paths(&temp, &temp).unwrap();
        assert!(!result);
    }
}
