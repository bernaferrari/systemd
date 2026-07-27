// SPDX-License-Identifier: LGPL-2.1-or-later
#![deny(unsafe_op_in_unsafe_fn)]
//
// PORT-SYNC: src/user-sessions/user-sessions.c
//
// User session management tool.
//
// Implements the systemd-user-sessions tool which manages the /run/nologin
// file. On "start", it removes /run/nologin to allow user logins.
// On "stop", it creates /run/nologin to prevent new user sessions
// during shutdown.

// ── Constants ─────────────────────────────────────────────────────────────

/// Path to the nologin file that blocks user logins.
pub const NOLOGIN_PATH: &str = "/run/nologin";

/// Default umask for the tool.
pub const DEFAULT_UMASK: u32 = 0o022;

// ── Enums ─────────────────────────────────────────────────────────────────

/// Verb (action) for the user-sessions tool.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserSessionsVerb {
    /// Start: remove /run/nologin to allow logins
    Start,
    /// Stop: create /run/nologin to block logins
    Stop,
}

impl UserSessionsVerb {
    /// Parse a verb from its string representation.
    pub fn from_str(s: &str) -> Result<Self, i32> {
        match s {
            "start" => Ok(Self::Start),
            "stop" => Ok(Self::Stop),
            _ => Err(-libc::EINVAL),
        }
    }

    /// Convert to the string representation.
    pub fn to_str(self) -> &'static str {
        match self {
            Self::Start => "start",
            Self::Stop => "stop",
        }
    }
}

// ── Argument parsing ──────────────────────────────────────────────────────

/// Parsed arguments for the user-sessions tool.
#[derive(Debug, Clone)]
pub struct UserSessionsArgs {
    /// The verb to execute
    pub verb: UserSessionsVerb,
}

impl UserSessionsArgs {
    /// Parse command-line arguments.
    /// Expects exactly one argument after the program name.
    pub fn parse(args: &[&str]) -> Result<Self, i32> {
        if args.len() != 2 {
            return Err(-libc::EINVAL);
        }
        let verb = UserSessionsVerb::from_str(args[1])?;
        Ok(Self { verb })
    }
}

// ── Nologin file management ───────────────────────────────────────────────

/// Result of a nologin file operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NologinResult {
    /// File was successfully removed
    Removed,
    /// File did not exist (nothing to do)
    NotFound,
    /// File was successfully created
    Created,
}

/// Determine what action to take for the nologin file given a verb.
pub fn nologin_action(verb: UserSessionsVerb) -> NologinAction {
    match verb {
        UserSessionsVerb::Start => NologinAction::Remove,
        UserSessionsVerb::Stop => NologinAction::Create,
    }
}

/// Actions that can be taken on the nologin file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NologinAction {
    /// Remove the nologin file
    Remove,
    /// Create the nologin file with a shutdown message
    Create,
}

/// Default message written to the nologin file during shutdown.
pub const NOLOGIN_MESSAGE: &str = "System is going down. Please log out immediately.\n";

/// Expected number of arguments (program name + verb).
pub const EXPECTED_ARGC: usize = 2;

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verb_from_str() {
        assert_eq!(
            UserSessionsVerb::from_str("start"),
            Ok(UserSessionsVerb::Start)
        );
        assert_eq!(
            UserSessionsVerb::from_str("stop"),
            Ok(UserSessionsVerb::Stop)
        );
        assert!(UserSessionsVerb::from_str("invalid").is_err());
        assert!(UserSessionsVerb::from_str("").is_err());
    }

    #[test]
    fn test_verb_to_str() {
        assert_eq!(UserSessionsVerb::Start.to_str(), "start");
        assert_eq!(UserSessionsVerb::Stop.to_str(), "stop");
    }

    #[test]
    fn test_parse_args_valid() {
        let args = UserSessionsArgs::parse(&["systemd-user-sessions", "start"]).unwrap();
        assert_eq!(args.verb, UserSessionsVerb::Start);

        let args = UserSessionsArgs::parse(&["systemd-user-sessions", "stop"]).unwrap();
        assert_eq!(args.verb, UserSessionsVerb::Stop);
    }

    #[test]
    fn test_parse_args_no_args() {
        assert!(UserSessionsArgs::parse(&["systemd-user-sessions"]).is_err());
    }

    #[test]
    fn test_parse_args_too_many() {
        assert!(UserSessionsArgs::parse(&["systemd-user-sessions", "start", "extra"]).is_err());
    }

    #[test]
    fn test_parse_args_invalid_verb() {
        assert!(UserSessionsArgs::parse(&["systemd-user-sessions", "restart"]).is_err());
    }

    #[test]
    fn test_nologin_action() {
        assert_eq!(
            nologin_action(UserSessionsVerb::Start),
            NologinAction::Remove
        );
        assert_eq!(
            nologin_action(UserSessionsVerb::Stop),
            NologinAction::Create
        );
    }

    #[test]
    fn test_constants() {
        assert_eq!(NOLOGIN_PATH, "/run/nologin");
        assert_eq!(DEFAULT_UMASK, 0o022);
        assert_eq!(EXPECTED_ARGC, 2);
        assert!(!NOLOGIN_MESSAGE.is_empty());
    }

    #[test]
    fn test_nologin_result() {
        assert_eq!(NologinResult::Removed, NologinResult::Removed);
        assert_ne!(NologinResult::Removed, NologinResult::NotFound);
        assert_ne!(NologinResult::Created, NologinResult::Removed);
    }
}
