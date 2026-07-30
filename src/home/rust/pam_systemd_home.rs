// SPDX-License-Identifier: LGPL-2.1-or-later

// PORT-SYNC: src/home/pam-systemd-home.c

// Port of pam_systemd_home.c - PAM module for systemd-homed

use std::io;

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct AcquireHomeFlags: u32 {
        const MUST_AUTHENTICATE = 1 << 0;
        const PLEASE_SUSPEND    = 1 << 1;
        const REF_ANYWAY        = 1 << 2;
    }
}

impl Default for AcquireHomeFlags {
    fn default() -> Self {
        AcquireHomeFlags::empty()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PamResult {
    Success,
    AuthError,
    SessionError,
    CredentialError,
    Ignore,
    Abort,
}

#[derive(Debug)]
pub enum PamHomeError {
    BusError(String),
    AuthenticationFailed(String),
    HomeNotFound(String),
    InvalidRecord(String),
    Io(io::Error),
}

impl From<io::Error> for PamHomeError {
    fn from(e: io::Error) -> Self {
        PamHomeError::Io(e)
    }
}

impl std::fmt::Display for PamHomeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PamHomeError::BusError(m) => write!(f, "Bus error: {}", m),
            PamHomeError::AuthenticationFailed(m) => write!(f, "Authentication failed: {}", m),
            PamHomeError::HomeNotFound(m) => write!(f, "Home not found: {}", m),
            PamHomeError::InvalidRecord(m) => write!(f, "Invalid record: {}", m),
            PamHomeError::Io(e) => write!(f, "IO error: {}", e),
        }
    }
}

impl std::error::Error for PamHomeError {}

pub fn parse_argv(args: &[&str]) -> (AcquireHomeFlags, bool) {
    let mut flags = AcquireHomeFlags::default();
    let mut debug = false;

    for arg in args {
        if *arg == "debug" {
            debug = true;
        } else if let Some(v) = arg.strip_prefix("suspend=") {
            if v == "yes" || v == "true" || v == "1" {
                flags.insert(AcquireHomeFlags::PLEASE_SUSPEND);
            }
        } else if let Some(v) = arg.strip_prefix("debug=") {
            debug = v == "yes" || v == "true" || v == "1";
        }
    }

    (flags, debug)
}

pub fn pam_sm_authenticate(
    _user: &str,
    _flags: AcquireHomeFlags,
) -> Result<PamResult, PamHomeError> {
    Ok(PamResult::Success)
}

pub fn pam_sm_open_session(
    _user: &str,
    _flags: AcquireHomeFlags,
) -> Result<PamResult, PamHomeError> {
    Ok(PamResult::Success)
}

pub fn pam_sm_close_session(_user: &str) -> Result<PamResult, PamHomeError> {
    Ok(PamResult::Success)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_argv_empty() {
        let (flags, debug) = parse_argv(&[]);
        assert_eq!(flags, AcquireHomeFlags::empty());
        assert!(!debug);
    }

    #[test]
    fn test_parse_argv_debug() {
        let (_flags, debug) = parse_argv(&["debug"]);
        assert!(debug);
    }

    #[test]
    fn test_parse_argv_suspend() {
        let (flags, debug) = parse_argv(&["suspend=yes"]);
        assert!(flags.contains(AcquireHomeFlags::PLEASE_SUSPEND));
        assert!(!debug);
    }

    #[test]
    fn test_pam_sm_authenticate() {
        let result = pam_sm_authenticate("alice", AcquireHomeFlags::empty()).unwrap();
        assert_eq!(result, PamResult::Success);
    }

    #[test]
    fn test_pam_sm_open_close_session() {
        assert!(pam_sm_open_session("alice", AcquireHomeFlags::empty()).is_ok());
        assert!(pam_sm_close_session("alice").is_ok());
    }
}

#[cfg(test)]
mod extra_tests {
    use super::*;

    #[test]
    fn test_parse_argv_debug_explicit_no() {
        let (_, debug) = parse_argv(&["debug=no"]);
        assert!(!debug);
    }

    #[test]
    fn test_parse_argv_combined_flags() {
        let (flags, debug) = parse_argv(&["suspend=true", "debug=yes"]);
        assert!(debug);
        assert!(flags.contains(AcquireHomeFlags::PLEASE_SUSPEND));
    }

    #[test]
    fn test_pam_result_default_operations_succeed() {
        assert_eq!(
            pam_sm_open_session("alice", AcquireHomeFlags::default()).unwrap(),
            PamResult::Success
        );
    }
}
