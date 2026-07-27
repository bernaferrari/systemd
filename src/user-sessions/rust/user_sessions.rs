// SPDX-License-Identifier: LGPL-2.1-or-later
// PORT-SYNC: src/user-sessions/user-sessions.c

use std::path::Path;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    InvalidArgCount,
    InvalidVerb(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidArgCount => f.write_str("this program requires one argument"),
            Self::InvalidVerb(v) => write!(f, "unknown verb '{v}'"),
        }
    }
}

impl std::error::Error for Error {}

pub const NOLOGIN_PATH: &str = "/run/nologin";
pub const DEFAULT_UMASK: u32 = 0o022;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionVerb {
    Start,
    Stop,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionAction {
    RemoveNologin,
    CreateShutdownNologin,
}

pub fn parse_verb(arg: &str) -> Result<SessionVerb> {
    match arg {
        "start" => Ok(SessionVerb::Start),
        "stop" => Ok(SessionVerb::Stop),
        _ => Err(Error::InvalidVerb(arg.to_owned())),
    }
}

pub fn parse_args(args: &[&str]) -> Result<SessionVerb> {
    if args.len() != 1 {
        return Err(Error::InvalidArgCount);
    }
    parse_verb(args[0])
}

pub fn compute_action(verb: SessionVerb) -> SessionAction {
    match verb {
        SessionVerb::Start => SessionAction::RemoveNologin,
        SessionVerb::Stop => SessionAction::CreateShutdownNologin,
    }
}

pub fn nologin_path() -> &'static Path {
    Path::new(NOLOGIN_PATH)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_start() {
        assert_eq!(parse_verb("start").unwrap(), SessionVerb::Start);
    }
    #[test]
    fn parses_stop() {
        assert_eq!(parse_verb("stop").unwrap(), SessionVerb::Stop);
    }
    #[test]
    fn rejects_unknown_verb() {
        assert!(matches!(parse_verb("reload"), Err(Error::InvalidVerb(_))));
    }
    #[test]
    fn rejects_missing_argument() {
        assert_eq!(parse_args(&[]).unwrap_err(), Error::InvalidArgCount);
    }
    #[test]
    fn rejects_extra_arguments() {
        assert_eq!(
            parse_args(&["start", "extra"]).unwrap_err(),
            Error::InvalidArgCount
        );
    }
    #[test]
    fn parse_args_accepts_one_argument() {
        assert_eq!(parse_args(&["stop"]).unwrap(), SessionVerb::Stop);
    }
    #[test]
    fn start_maps_to_remove() {
        assert_eq!(
            compute_action(SessionVerb::Start),
            SessionAction::RemoveNologin
        );
    }
    #[test]
    fn stop_maps_to_create() {
        assert_eq!(
            compute_action(SessionVerb::Stop),
            SessionAction::CreateShutdownNologin
        );
    }
}
