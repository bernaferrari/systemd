// SPDX-License-Identifier: LGPL-2.1-or-later
// PORT-SYNC: src/login/pam_systemd_loadkey.c

pub const DEFAULT_KEYNAME: &str = "cryptsetup";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadKeyOptions {
    pub keyname: String,
    pub debug: bool,
}

impl Default for LoadKeyOptions {
    fn default() -> Self {
        Self {
            keyname: DEFAULT_KEYNAME.to_string(),
            debug: false,
        }
    }
}

pub fn parse_options(args: &[&str]) -> Result<LoadKeyOptions, String> {
    let mut options = LoadKeyOptions::default();

    for arg in args {
        if let Some(value) = arg.strip_prefix("keyname=") {
            options.keyname = value.to_string();
        } else if *arg == "debug" {
            options.debug = true;
        }
    }

    Ok(options)
}

pub fn parse_nulstr_passwords(blob: &[u8]) -> Result<Vec<String>, String> {
    if blob.is_empty() {
        return Ok(Vec::new());
    }

    blob.split(|byte| *byte == 0)
        .filter(|segment| !segment.is_empty())
        .map(|segment| String::from_utf8(segment.to_vec()).map_err(|e| e.to_string()))
        .collect()
}

pub fn pam_sm_authenticate(key_payload: &[u8]) -> Result<String, String> {
    let passwords = parse_nulstr_passwords(key_payload)?;
    passwords
        .last()
        .cloned()
        .ok_or_else(|| "key does not contain any passwords".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn options_match_c_defaults() {
        let options = parse_options(&["debug", "keyname=luks"]).unwrap();
        assert!(options.debug);
        assert_eq!(options.keyname, "luks");
    }

    #[test]
    fn last_password_becomes_auth_token() {
        let payload = b"first\0second\0";
        assert_eq!(pam_sm_authenticate(payload), Ok("second".to_string()));
    }
}
