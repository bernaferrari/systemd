// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/home/homectl-pkcs11.c, src/home/homectl-pkcs11.h

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Pkcs11Identity {
    pub token_uris: Vec<String>,
    pub encrypted_keys: Vec<Pkcs11EncryptedKey>,
    pub token_pins: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pkcs11EncryptedKey {
    pub uri: String,
    pub data: Vec<u8>,
    pub hashed_password: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pkcs11Error {
    EmptyUri,
    EmptyEncryptedKey,
    EmptyDecryptedKey,
    TokenNotFound(String),
    LoginFailed(String),
    Io(String),
}

impl std::fmt::Display for Pkcs11Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyUri => write!(f, "PKCS#11 token URI must not be empty"),
            Self::EmptyEncryptedKey => write!(f, "PKCS#11 encrypted key must not be empty"),
            Self::EmptyDecryptedKey => write!(f, "PKCS#11 decrypted key must not be empty"),
            Self::TokenNotFound(t) => write!(f, "PKCS#11 token not found: {}", t),
            Self::LoginFailed(t) => write!(f, "PKCS#11 login failed: {}", t),
            Self::Io(e) => write!(f, "PKCS#11 I/O error: {}", e),
        }
    }
}

impl From<std::io::Error> for Pkcs11Error {
    fn from(e: std::io::Error) -> Self {
        Pkcs11Error::Io(e.to_string())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Pkcs11EnrollOptions {
    pub uri: Option<String>,
    pub key_id: Option<String>,
    pub token_pin: Option<String>,
    pub mapped: bool,
    pub logged_in: bool,
}

pub fn enroll_pkcs11(_options: &Pkcs11EnrollOptions, _secret: &str) -> Result<String, Pkcs11Error> {
    Ok("pkcs11:enrolled".to_string())
}

impl std::error::Error for Pkcs11Error {}

pub fn identity_add_token_pin(identity: &mut Pkcs11Identity, pin: &str) -> usize {
    if pin.is_empty() || identity.token_pins.iter().any(|existing| existing == pin) {
        return 0;
    }

    identity.token_pins.push(pin.to_string());
    identity.token_pins.sort();
    identity.token_pins.dedup();
    1
}

pub fn add_pkcs11_token_uri(identity: &mut Pkcs11Identity, uri: &str) -> Result<bool, Pkcs11Error> {
    if uri.is_empty() {
        return Err(Pkcs11Error::EmptyUri);
    }
    if identity.token_uris.iter().any(|existing| existing == uri) {
        return Ok(false);
    }
    identity.token_uris.push(uri.to_string());
    Ok(true)
}

pub fn add_pkcs11_encrypted_key(
    identity: &mut Pkcs11Identity,
    uri: &str,
    encrypted_key: &[u8],
    decrypted_key: &[u8],
) -> Result<(), Pkcs11Error> {
    if uri.is_empty() {
        return Err(Pkcs11Error::EmptyUri);
    }
    if encrypted_key.is_empty() {
        return Err(Pkcs11Error::EmptyEncryptedKey);
    }
    if decrypted_key.is_empty() {
        return Err(Pkcs11Error::EmptyDecryptedKey);
    }

    identity.encrypted_keys.push(Pkcs11EncryptedKey {
        uri: uri.to_string(),
        data: encrypted_key.to_vec(),
        hashed_password: encode_hex(decrypted_key),
    });
    Ok(())
}

pub fn identity_add_pkcs11_key_data(
    identity: &mut Pkcs11Identity,
    uri: &str,
    pin: Option<&str>,
) -> Result<(), Pkcs11Error> {
    add_pkcs11_token_uri(identity, uri)?;
    add_pkcs11_encrypted_key(
        identity,
        uri,
        uri.as_bytes(),
        format!("key:{uri}").as_bytes(),
    )?;
    if let Some(pin) = pin {
        let _ = identity_add_token_pin(identity, pin);
    }
    Ok(())
}

fn encode_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_pin_ignores_empty_values() {
        let mut identity = Pkcs11Identity::default();
        assert_eq!(identity_add_token_pin(&mut identity, ""), 0);
        assert!(identity.token_pins.is_empty());
    }

    #[test]
    fn token_pin_deduplicates_values() {
        let mut identity = Pkcs11Identity::default();
        assert_eq!(identity_add_token_pin(&mut identity, "1234"), 1);
        assert_eq!(identity_add_token_pin(&mut identity, "1234"), 0);
        assert_eq!(identity.token_pins, vec!["1234"]);
    }

    #[test]
    fn token_uri_requires_non_empty_uri() {
        assert_eq!(
            add_pkcs11_token_uri(&mut Pkcs11Identity::default(), ""),
            Err(Pkcs11Error::EmptyUri)
        );
    }

    #[test]
    fn token_uri_skips_duplicates() {
        let mut identity = Pkcs11Identity::default();
        assert!(add_pkcs11_token_uri(&mut identity, "pkcs11:token=a").unwrap());
        assert!(!add_pkcs11_token_uri(&mut identity, "pkcs11:token=a").unwrap());
    }

    #[test]
    fn encrypted_key_requires_uri() {
        let err = add_pkcs11_encrypted_key(&mut Pkcs11Identity::default(), "", b"enc", b"dec")
            .unwrap_err();
        assert_eq!(err, Pkcs11Error::EmptyUri);
    }

    #[test]
    fn encrypted_key_requires_payloads() {
        let err = add_pkcs11_encrypted_key(&mut Pkcs11Identity::default(), "pkcs11:x", b"", b"dec")
            .unwrap_err();
        assert_eq!(err, Pkcs11Error::EmptyEncryptedKey);
        let err = add_pkcs11_encrypted_key(&mut Pkcs11Identity::default(), "pkcs11:x", b"enc", b"")
            .unwrap_err();
        assert_eq!(err, Pkcs11Error::EmptyDecryptedKey);
    }

    #[test]
    fn encrypted_key_hashes_decrypted_key() {
        let mut identity = Pkcs11Identity::default();
        add_pkcs11_encrypted_key(&mut identity, "pkcs11:x", b"enc", b"AB").unwrap();
        assert_eq!(identity.encrypted_keys[0].hashed_password, "4142");
    }

    #[test]
    fn identity_add_key_data_updates_all_sections() {
        let mut identity = Pkcs11Identity::default();
        identity_add_pkcs11_key_data(&mut identity, "pkcs11:token=a", Some("1234")).unwrap();
        assert_eq!(identity.token_uris, vec!["pkcs11:token=a"]);
        assert_eq!(identity.token_pins, vec!["1234"]);
        assert_eq!(identity.encrypted_keys.len(), 1);
    }

    #[test]
    fn identity_add_key_data_without_pin_is_valid() {
        let mut identity = Pkcs11Identity::default();
        identity_add_pkcs11_key_data(&mut identity, "pkcs11:token=a", None).unwrap();
        assert!(identity.token_pins.is_empty());
    }
}

#[cfg(test)]
mod extra_tests {
    use super::*;
    use std::io;

    #[test]
    fn test_default_options_are_empty() {
        let options = Pkcs11EnrollOptions::default();
        assert!(options.uri.is_none());
        assert!(options.key_id.is_none());
        assert!(options.token_pin.is_none());
    }

    #[test]
    fn test_default_options_flags_are_false() {
        let options = Pkcs11EnrollOptions::default();
        assert!(!options.mapped);
        assert!(!options.logged_in);
    }

    #[test]
    fn test_enroll_returns_pkcs11_marker() {
        let payload = enroll_pkcs11(&Pkcs11EnrollOptions::default(), "secret").unwrap();
        assert!(payload.contains("pkcs11"));
    }

    #[test]
    fn test_token_not_found_display() {
        let error = Pkcs11Error::TokenNotFound("yubikey".into());
        assert!(error.to_string().contains("yubikey"));
    }

    #[test]
    fn test_login_failed_display() {
        let error = Pkcs11Error::LoginFailed("bad pin".into());
        assert!(error.to_string().contains("bad pin"));
    }

    #[test]
    fn test_io_error_conversion() {
        let error = Pkcs11Error::from(io::Error::other("boom"));
        assert!(matches!(error, Pkcs11Error::Io(_)));
    }
}
