// SPDX-License-Identifier: LGPL-2.1-or-later
// PORT-SYNC: src/varlinkctl/varlinkctl.c

use std::path::Path;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    InvalidVerb(String),
    MissingValue(&'static str),
    InvalidTimeout(String),
    InvalidPushFd(String),
    InvalidRuntimeScope(String),
    MissingAddress,
    MissingMethod,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidVerb(v) => write!(f, "invalid verb: {v}"),
            Self::MissingValue(v) => write!(f, "missing value for {v}"),
            Self::InvalidTimeout(v) => write!(f, "invalid timeout: {v}"),
            Self::InvalidPushFd(v) => write!(f, "invalid push fd: {v}"),
            Self::InvalidRuntimeScope(v) => write!(f, "invalid runtime scope: {v}"),
            Self::MissingAddress => f.write_str("missing varlink address"),
            Self::MissingMethod => f.write_str("missing varlink method"),
        }
    }
}

impl std::error::Error for Error {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VarlinkVerb {
    Info,
    ListInterfaces,
    Introspect,
    ListMethods,
    Call,
    ListRegistry,
    ValidateIdl,
    Help,
}

impl VarlinkVerb {
    pub fn parse(s: &str) -> Result<Self> {
        Ok(match s {
            "info" => Self::Info,
            "list-interfaces" => Self::ListInterfaces,
            "introspect" => Self::Introspect,
            "list-methods" => Self::ListMethods,
            "call" => Self::Call,
            "list-registry" => Self::ListRegistry,
            "validate-idl" => Self::ValidateIdl,
            "help" => Self::Help,
            _ => return Err(Error::InvalidVerb(s.to_owned())),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RuntimeScope {
    #[default]
    System,
    User,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MethodFlags {
    pub more: bool,
    pub oneway: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PushFdSpec {
    Path(String),
    Fd(i32),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectionTarget {
    FileSystemPath(String),
    Url(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedCommand {
    pub verb: VarlinkVerb,
    pub runtime_scope: RuntimeScope,
    pub method_flags: MethodFlags,
    pub collect: bool,
    pub quiet: bool,
    pub exec: bool,
    pub timeout_usec: Option<u64>,
    pub push_fds: Vec<PushFdSpec>,
    pub positional: Vec<String>,
}

impl Default for ParsedCommand {
    fn default() -> Self {
        Self {
            verb: VarlinkVerb::Help,
            runtime_scope: RuntimeScope::System,
            method_flags: MethodFlags::default(),
            collect: false,
            quiet: false,
            exec: false,
            timeout_usec: None,
            push_fds: Vec::new(),
            positional: Vec::new(),
        }
    }
}

pub fn classify_target(where_: &str) -> ConnectionTarget {
    if where_.starts_with('/') || where_.starts_with("./") {
        ConnectionTarget::FileSystemPath(where_.into())
    } else {
        ConnectionTarget::Url(where_.into())
    }
}

pub fn parse_timeout(value: &str) -> Result<Option<u64>> {
    if value.is_empty() || value == "infinity" {
        return Ok(None);
    }
    let secs: u64 = value
        .parse()
        .map_err(|_| Error::InvalidTimeout(value.into()))?;
    if secs == 0 {
        return Err(Error::InvalidTimeout(value.into()));
    }
    Ok(Some(secs.saturating_mul(1_000_000)))
}

pub fn parse_push_fd(value: &str) -> Result<PushFdSpec> {
    if value.starts_with('/') || value.starts_with("./") {
        return Ok(PushFdSpec::Path(value.into()));
    }
    let fd = value
        .parse::<i32>()
        .map_err(|_| Error::InvalidPushFd(value.into()))?;
    if fd < 0 {
        return Err(Error::InvalidPushFd(value.into()));
    }
    Ok(PushFdSpec::Fd(fd))
}

pub fn parse_runtime_scope(value: &str) -> Result<RuntimeScope> {
    match value {
        "system" => Ok(RuntimeScope::System),
        "user" => Ok(RuntimeScope::User),
        _ => Err(Error::InvalidRuntimeScope(value.into())),
    }
}

pub fn parse_cli(args: &[&str]) -> Result<ParsedCommand> {
    let mut command = ParsedCommand::default();
    let mut i = 0;
    while i < args.len() {
        match args[i] {
            "--system" => command.runtime_scope = RuntimeScope::System,
            "--user" => command.runtime_scope = RuntimeScope::User,
            "--more" => {
                command.method_flags.more = true;
                command.method_flags.oneway = false;
            }
            "--oneway" => {
                command.method_flags.oneway = true;
                command.method_flags.more = false;
            }
            "--collect" => command.collect = true,
            "--quiet" | "-q" => command.quiet = true,
            "--exec" => command.exec = true,
            "-E" => {
                command.method_flags.more = true;
                command.timeout_usec = None;
            }
            arg if arg.starts_with("--timeout=") => {
                command.timeout_usec = parse_timeout(&arg[10..])?
            }
            "--timeout" => {
                i += 1;
                command.timeout_usec =
                    parse_timeout(args.get(i).ok_or(Error::MissingValue("--timeout"))?)?;
            }
            arg if arg.starts_with("--push-fd=") => {
                command.push_fds.push(parse_push_fd(&arg[10..])?)
            }
            "--push-fd" => {
                i += 1;
                command.push_fds.push(parse_push_fd(
                    args.get(i).ok_or(Error::MissingValue("--push-fd"))?,
                )?);
            }
            "help" | "info" | "list-interfaces" | "introspect" | "list-methods" | "call"
            | "list-registry" | "validate-idl" => {
                command.verb = VarlinkVerb::parse(args[i])?;
                command
                    .positional
                    .extend(args[i + 1..].iter().map(|s| (*s).to_owned()));
                break;
            }
            other => return Err(Error::InvalidVerb(other.into())),
        }
        i += 1;
    }
    Ok(command)
}

pub fn required_address(verb: VarlinkVerb, positional: &[String]) -> Result<&str> {
    match verb {
        VarlinkVerb::Info
        | VarlinkVerb::ListInterfaces
        | VarlinkVerb::Introspect
        | VarlinkVerb::ListMethods
        | VarlinkVerb::Call => positional
            .first()
            .map(String::as_str)
            .ok_or(Error::MissingAddress),
        _ => Ok(""),
    }
}

pub fn required_method(verb: VarlinkVerb, positional: &[String]) -> Result<&str> {
    match verb {
        VarlinkVerb::Call => positional
            .get(1)
            .map(String::as_str)
            .ok_or(Error::MissingMethod),
        _ => Ok(""),
    }
}

pub fn validate_idl_input(path: &str) -> bool {
    Path::new(path)
        .extension()
        .is_some_and(|ext| ext == "varlink")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_call_verb() {
        assert_eq!(VarlinkVerb::parse("call").unwrap(), VarlinkVerb::Call);
    }
    #[test]
    fn classifies_paths() {
        assert_eq!(
            classify_target("/run/io.varlink"),
            ConnectionTarget::FileSystemPath("/run/io.varlink".into())
        );
    }
    #[test]
    fn classifies_urls() {
        assert_eq!(
            classify_target("unix:/run/x"),
            ConnectionTarget::Url("unix:/run/x".into())
        );
    }
    #[test]
    fn parses_infinite_timeout() {
        assert_eq!(parse_timeout("infinity").unwrap(), None);
    }
    #[test]
    fn parses_numeric_timeout() {
        assert_eq!(parse_timeout("5").unwrap(), Some(5_000_000));
    }
    #[test]
    fn parses_push_fd_number() {
        assert_eq!(parse_push_fd("4").unwrap(), PushFdSpec::Fd(4));
    }
    #[test]
    fn parses_push_fd_path() {
        assert_eq!(
            parse_push_fd("./payload").unwrap(),
            PushFdSpec::Path("./payload".into())
        );
    }
    #[test]
    fn cli_parses_flags_and_positional_arguments() {
        let parsed = parse_cli(&["--user", "--more", "call", "unix:/x", "a.b", "{}"]).unwrap();
        assert_eq!(parsed.runtime_scope, RuntimeScope::User);
        assert!(parsed.method_flags.more);
        assert_eq!(
            required_address(parsed.verb, &parsed.positional).unwrap(),
            "unix:/x"
        );
        assert_eq!(
            required_method(parsed.verb, &parsed.positional).unwrap(),
            "a.b"
        );
    }
}
