// SPDX-License-Identifier: LGPL-2.1-or-later

// PORT-SYNC: src/home/homectl.c

// Port of homectl.c - Home directory management CLI tool

use std::io;

use crate::home_util::suitable_user_name;
use crate::homed_conf::UserStorage;

#[derive(Debug, Clone)]
pub struct HomectlOptions {
    pub identity: Option<String>,
    pub real_name: Option<String>,
    pub realm: Option<String>,
    pub home_dir: Option<String>,
    pub shell: Option<String>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub storage: Option<UserStorage>,
    pub image_path: Option<String>,
    pub fs_type: Option<String>,
    pub disk_size: Option<u64>,
    pub password: Option<String>,
    pub pkcs11_token_uri: Option<String>,
    pub fido2_device: Option<String>,
    pub recovery_key: bool,
    pub enforce_password_policy: bool,
    pub kill_processes: bool,
    pub json: bool,
    pub no_pager: bool,
    pub lines: Option<usize>,
}

impl Default for HomectlOptions {
    fn default() -> Self {
        Self {
            identity: None,
            real_name: None,
            realm: None,
            home_dir: None,
            shell: None,
            uid: None,
            gid: None,
            storage: None,
            image_path: None,
            fs_type: None,
            disk_size: None,
            password: None,
            pkcs11_token_uri: None,
            fido2_device: None,
            recovery_key: false,
            enforce_password_policy: false,
            kill_processes: false,
            json: false,
            no_pager: false,
            lines: None,
        }
    }
}

#[derive(Debug)]
pub enum HomectlError {
    InvalidArgument(String),
    NotFound(String),
    AlreadyExists(String),
    AuthenticationFailed(String),
    BusError(String),
    Io(io::Error),
}

impl From<io::Error> for HomectlError {
    fn from(e: io::Error) -> Self {
        HomectlError::Io(e)
    }
}

impl std::fmt::Display for HomectlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HomectlError::InvalidArgument(m) => write!(f, "Invalid argument: {}", m),
            HomectlError::NotFound(n) => write!(f, "Not found: {}", n),
            HomectlError::AlreadyExists(n) => write!(f, "Already exists: {}", n),
            HomectlError::AuthenticationFailed(m) => write!(f, "Authentication failed: {}", m),
            HomectlError::BusError(m) => write!(f, "Bus error: {}", m),
            HomectlError::Io(e) => write!(f, "IO error: {}", e),
        }
    }
}

impl std::error::Error for HomectlError {}

pub fn parse_identity(identity: &str) -> Result<(String, Option<String>), HomectlError> {
    let identity = identity.trim();
    if identity.is_empty() {
        return Err(HomectlError::InvalidArgument("Empty identity".to_string()));
    }
    if !suitable_user_name(identity) {
        return Err(HomectlError::InvalidArgument(format!(
            "Invalid user name: {}",
            identity
        )));
    }
    Ok((identity.to_string(), None))
}

pub fn validate_options(opts: &HomectlOptions) -> Result<(), HomectlError> {
    if let Some(ref identity) = opts.identity {
        if !suitable_user_name(identity) {
            return Err(HomectlError::InvalidArgument(format!(
                "Invalid user name: {}",
                identity
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_identity() {
        let (name, realm) = parse_identity("alice").unwrap();
        assert_eq!(name, "alice");
        assert!(realm.is_none());
    }

    #[test]
    fn test_parse_identity_empty() {
        assert!(parse_identity("").is_err());
    }

    #[test]
    fn test_parse_identity_reserved() {
        assert!(parse_identity("root").is_err());
    }

    #[test]
    fn test_validate_options_default() {
        let opts = HomectlOptions::default();
        assert!(validate_options(&opts).is_ok());
    }

    #[test]
    fn test_validate_options_invalid_name() {
        let opts = HomectlOptions {
            identity: Some("root".to_string()),
            ..Default::default()
        };
        assert!(validate_options(&opts).is_err());
    }
}

#[cfg(test)]
mod extra_tests {
    use super::*;

    #[test]
    fn test_parse_identity_trims_whitespace() {
        let (name, realm) = parse_identity("  alice  ").unwrap();
        assert_eq!(name, "alice");
        assert!(realm.is_none());
    }

    #[test]
    fn test_validate_options_valid_identity() {
        let options = HomectlOptions {
            identity: Some("alice".into()),
            ..Default::default()
        };
        assert!(validate_options(&options).is_ok());
    }

    #[test]
    fn test_default_options_flags_are_disabled() {
        let options = HomectlOptions::default();
        assert!(!options.recovery_key);
        assert!(!options.enforce_password_policy);
        assert!(!options.kill_processes);
    }
}
