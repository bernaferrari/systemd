// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/creds/creds.c

pub const EINVAL: i32 = -22;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TranscodeMode {
    Off,
    Base64,
    Unbase64,
    Hex,
    Unhex,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyType {
    Auto,
    Host,
    Tpm2,
    Tpm2WithPublicKey,
    HostTpm2,
    Null,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub system: bool,
    pub transcode: TranscodeMode,
    pub name: Option<String>,
    pub pretty: bool,
    pub quiet: bool,
    pub varlink: bool,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            system: false,
            transcode: TranscodeMode::Off,
            name: None,
            pretty: false,
            quiet: false,
            varlink: false,
        }
    }
}
pub fn parse_transcode(s: &str) -> Result<TranscodeMode, i32> {
    match s {
        "off" => Ok(TranscodeMode::Off),
        "base64" => Ok(TranscodeMode::Base64),
        "unbase64" => Ok(TranscodeMode::Unbase64),
        "hex" => Ok(TranscodeMode::Hex),
        "unhex" => Ok(TranscodeMode::Unhex),
        _ => Err(EINVAL),
    }
}
pub fn parse_key_type(s: &str) -> Result<KeyType, i32> {
    match s {
        "auto" => Ok(KeyType::Auto),
        "host" => Ok(KeyType::Host),
        "tpm2" => Ok(KeyType::Tpm2),
        "tpm2-with-public-key" => Ok(KeyType::Tpm2WithPublicKey),
        "host+tpm2" | "tpm2+host" => Ok(KeyType::HostTpm2),
        "null" | "tpm2-absent" => Ok(KeyType::Null),
        _ => Err(EINVAL),
    }
}
pub fn validate_name(name: &str) -> Result<(), i32> {
    if name.is_empty() || name.contains('/') || name.contains('\0') {
        Err(EINVAL)
    } else {
        Ok(())
    }
}
pub fn newline_default(pretty: bool) -> bool {
    pretty
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn default_config() {
        assert!(!Config::default().system);
    }
    #[test]
    fn parse_hex_transcode() {
        assert_eq!(parse_transcode("hex").unwrap(), TranscodeMode::Hex);
    }
    #[test]
    fn parse_invalid_transcode() {
        assert!(parse_transcode("x").is_err());
    }
    #[test]
    fn parse_key_type_alias() {
        assert_eq!(parse_key_type("tpm2+host").unwrap(), KeyType::HostTpm2);
    }
    #[test]
    fn parse_null_alias() {
        assert_eq!(parse_key_type("tpm2-absent").unwrap(), KeyType::Null);
    }
    #[test]
    fn name_validation_accepts_simple_name() {
        assert!(validate_name("db.password").is_ok());
    }
    #[test]
    fn name_validation_rejects_slash() {
        assert!(validate_name("a/b").is_err());
    }
    #[test]
    fn name_validation_rejects_empty() {
        assert!(validate_name("").is_err());
    }
    #[test]
    fn pretty_implies_newline_default() {
        assert!(newline_default(true));
    }
    #[test]
    fn non_pretty_does_not_force_newline() {
        assert!(!newline_default(false));
    }
}
