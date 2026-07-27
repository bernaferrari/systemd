// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/varlink-io.systemd.Credentials.c
//
// Rust shadow of the io.systemd.Credentials varlink interface.
//
// Types for encrypting and decrypting service credentials with various
// key-binding strategies (TPM, host key, null) and scope controls.

// ── Constants ─────────────────────────────────────────────────────────────

pub const INTERFACE_NAME: &str = "io.systemd.Credentials";

// ── Enums ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    System,
    User,
}

impl Scope {
    pub fn from_varlink(s: &str) -> Result<Scope, CredentialsError> {
        match s {
            "system" => Ok(Scope::System),
            "user" => Ok(Scope::User),
            _ => Err(CredentialsError::BadScope),
        }
    }

    pub fn to_varlink(self) -> &'static str {
        match self {
            Scope::System => "system",
            Scope::User => "user",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WithKey {
    Auto,
    AutoInitrd,
    Host,
    Tpm2,
    Tpm2WithPublicKey,
    HostTpm2,
    HostTpm2WithPublicKey,
    Null,
}

impl WithKey {
    pub fn from_varlink(s: &str) -> Result<WithKey, CredentialsError> {
        match s {
            "auto" => Ok(WithKey::Auto),
            "auto_initrd" => Ok(WithKey::AutoInitrd),
            "host" => Ok(WithKey::Host),
            "tpm2" => Ok(WithKey::Tpm2),
            "tpm2_with_public_key" => Ok(WithKey::Tpm2WithPublicKey),
            "host_tpm2" => Ok(WithKey::HostTpm2),
            "host_tpm2_with_public_key" => Ok(WithKey::HostTpm2WithPublicKey),
            "null" => Ok(WithKey::Null),
            _ => Err(CredentialsError::BadFormat),
        }
    }

    pub fn to_varlink(self) -> &'static str {
        match self {
            WithKey::Auto => "auto",
            WithKey::AutoInitrd => "auto_initrd",
            WithKey::Host => "host",
            WithKey::Tpm2 => "tpm2",
            WithKey::Tpm2WithPublicKey => "tpm2_with_public_key",
            WithKey::HostTpm2 => "host_tpm2",
            WithKey::HostTpm2WithPublicKey => "host_tpm2_with_public_key",
            WithKey::Null => "null",
        }
    }

    pub fn uses_tpm(self) -> bool {
        matches!(
            self,
            WithKey::Tpm2
                | WithKey::Tpm2WithPublicKey
                | WithKey::HostTpm2
                | WithKey::HostTpm2WithPublicKey
        )
    }

    pub fn uses_host(self) -> bool {
        matches!(
            self,
            WithKey::Host | WithKey::HostTpm2 | WithKey::HostTpm2WithPublicKey
        )
    }

    pub fn is_null(self) -> bool {
        self == WithKey::Null
    }
}

// ── Structs ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub struct EncryptInput {
    pub name: Option<String>,
    pub text: Option<String>,
    pub data: Option<String>,
    pub timestamp: Option<i64>,
    pub not_after: Option<i64>,
    pub scope: Option<Scope>,
    pub with_key: Option<WithKey>,
    pub uid: Option<i64>,
}

impl EncryptInput {
    pub fn new() -> Self {
        EncryptInput {
            name: None,
            text: None,
            data: None,
            timestamp: None,
            not_after: None,
            scope: None,
            with_key: None,
            uid: None,
        }
    }

    pub fn has_plaintext(&self) -> bool {
        self.text.is_some() || self.data.is_some()
    }

    pub fn effective_scope(&self) -> Scope {
        if self.scope.is_some() {
            self.scope.unwrap()
        } else if self.uid.is_some() {
            Scope::User
        } else {
            Scope::System
        }
    }
}

impl Default for EncryptInput {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct EncryptOutput {
    pub blob: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct DecryptInput {
    pub name: Option<String>,
    pub blob: String,
    pub timestamp: Option<i64>,
    pub scope: Option<Scope>,
    pub uid: Option<i64>,
    pub allow_null: Option<bool>,
}

impl DecryptInput {
    pub fn new(blob: String) -> Self {
        DecryptInput {
            name: None,
            blob,
            timestamp: None,
            scope: None,
            uid: None,
            allow_null: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct DecryptOutput {
    pub data: String,
}

// ── Error type ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum CredentialsError {
    BadFormat,
    NameMismatch,
    TimeMismatch,
    NoSuchUser,
    BadScope,
    CantFindPcrSignature,
    NullKeyNotAllowed,
    KeyBelongsToOtherTpm,
    TpmInDictionaryLockout,
    UnexpectedPcrState,
    MissingPlaintext,
}

impl std::fmt::Display for CredentialsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CredentialsError::BadFormat => write!(f, "BadFormat"),
            CredentialsError::NameMismatch => write!(f, "NameMismatch"),
            CredentialsError::TimeMismatch => write!(f, "TimeMismatch"),
            CredentialsError::NoSuchUser => write!(f, "NoSuchUser"),
            CredentialsError::BadScope => write!(f, "BadScope"),
            CredentialsError::CantFindPcrSignature => write!(f, "CantFindPCRSignature"),
            CredentialsError::NullKeyNotAllowed => write!(f, "NullKeyNotAllowed"),
            CredentialsError::KeyBelongsToOtherTpm => write!(f, "KeyBelongsToOtherTPM"),
            CredentialsError::TpmInDictionaryLockout => write!(f, "TPMInDictionaryLockout"),
            CredentialsError::UnexpectedPcrState => write!(f, "UnexpectedPCRState"),
            CredentialsError::MissingPlaintext => write!(f, "MissingPlaintext"),
        }
    }
}

impl std::error::Error for CredentialsError {}

// ── Methods ───────────────────────────────────────────────────────────────

pub fn validate_encrypt_input(input: &EncryptInput) -> Result<(), CredentialsError> {
    if !input.has_plaintext() {
        return Err(CredentialsError::MissingPlaintext);
    }
    Ok(())
}

pub fn encrypt(input: &EncryptInput) -> Result<EncryptOutput, CredentialsError> {
    validate_encrypt_input(input)?;

    /*
     * Never substitute an identity transform for credential encryption. The C
     * implementation produces an authenticated, base64-encoded credential
     * using the selected host/TPM/null key binding. Returning plaintext here
     * would label a secret as encrypted and can cause it to be stored or sent
     * where confidentiality and authenticity are expected.
     *
     * The Credentials varlink interface has no generic "unsupported" error.
     * BadFormat is its documented error for unsupported encrypted credentials,
     * so it is the closest faithful error until authenticated encryption is
     * implemented.
     */
    Err(CredentialsError::BadFormat)
}

pub fn validate_decrypt_input(input: &DecryptInput) -> Result<(), CredentialsError> {
    if input.blob.is_empty() {
        return Err(CredentialsError::BadFormat);
    }
    Ok(())
}

pub fn decrypt(
    input: &DecryptInput,
    expected_name: Option<&str>,
) -> Result<DecryptOutput, CredentialsError> {
    validate_decrypt_input(input)?;

    if let (Some(ref name), Some(expected)) = (&input.name, expected_name) {
        if name != expected {
            return Err(CredentialsError::NameMismatch);
        }
    }

    // See encrypt(): accepting a blob as plaintext would bypass both format
    // checks and GCM authentication. Fail closed until real decryption exists.
    Err(CredentialsError::BadFormat)
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scope_roundtrip() {
        assert_eq!(Scope::from_varlink("system").unwrap(), Scope::System);
        assert_eq!(Scope::from_varlink("user").unwrap(), Scope::User);
        assert_eq!(Scope::System.to_varlink(), "system");
        assert_eq!(Scope::User.to_varlink(), "user");
    }

    #[test]
    fn scope_invalid() {
        assert_eq!(
            Scope::from_varlink("global").unwrap_err(),
            CredentialsError::BadScope
        );
    }

    #[test]
    fn with_key_all_variants_roundtrip() {
        let pairs = [
            ("auto", WithKey::Auto),
            ("auto_initrd", WithKey::AutoInitrd),
            ("host", WithKey::Host),
            ("tpm2", WithKey::Tpm2),
            ("tpm2_with_public_key", WithKey::Tpm2WithPublicKey),
            ("host_tpm2", WithKey::HostTpm2),
            ("host_tpm2_with_public_key", WithKey::HostTpm2WithPublicKey),
            ("null", WithKey::Null),
        ];
        for (s, variant) in pairs {
            assert_eq!(WithKey::from_varlink(s).unwrap(), variant);
            assert_eq!(variant.to_varlink(), s);
        }
    }

    #[test]
    fn with_key_uses_tpm() {
        assert!(WithKey::Tpm2.uses_tpm());
        assert!(WithKey::HostTpm2.uses_tpm());
        assert!(!WithKey::Host.uses_tpm());
        assert!(!WithKey::Null.uses_tpm());
    }

    #[test]
    fn with_key_uses_host() {
        assert!(WithKey::Host.uses_host());
        assert!(WithKey::HostTpm2.uses_host());
        assert!(!WithKey::Tpm2.uses_host());
        assert!(!WithKey::Null.uses_host());
    }

    #[test]
    fn with_key_is_null() {
        assert!(WithKey::Null.is_null());
        assert!(!WithKey::Auto.is_null());
    }

    #[test]
    fn encrypt_input_has_plaintext() {
        let mut input = EncryptInput::new();
        assert!(!input.has_plaintext());
        input.text = Some("hello".to_owned());
        assert!(input.has_plaintext());
    }

    #[test]
    fn encrypt_input_effective_scope_default() {
        let input = EncryptInput::new();
        assert_eq!(input.effective_scope(), Scope::System);
    }

    #[test]
    fn encrypt_input_effective_scope_with_uid() {
        let mut input = EncryptInput::new();
        input.uid = Some(1000);
        assert_eq!(input.effective_scope(), Scope::User);
    }

    #[test]
    fn encrypt_fails_closed_without_authenticated_crypto() {
        let mut input = EncryptInput::new();
        input.text = Some("secret".to_owned());
        assert_eq!(encrypt(&input), Err(CredentialsError::BadFormat));
    }

    #[test]
    fn encrypt_fails_without_plaintext() {
        let input = EncryptInput::new();
        assert_eq!(
            encrypt(&input).unwrap_err(),
            CredentialsError::MissingPlaintext
        );
    }

    #[test]
    fn decrypt_fails_closed_without_authenticated_crypto() {
        let input = DecryptInput::new("blobdata".to_owned());
        assert_eq!(decrypt(&input, None), Err(CredentialsError::BadFormat));
    }

    #[test]
    fn decrypt_name_mismatch() {
        let mut input = DecryptInput::new("blobdata".to_owned());
        input.name = Some("wrong".to_owned());
        assert_eq!(
            decrypt(&input, Some("correct")).unwrap_err(),
            CredentialsError::NameMismatch
        );
    }

    #[test]
    fn decrypt_name_match_still_fails_closed() {
        let mut input = DecryptInput::new("blobdata".to_owned());
        input.name = Some("mycred".to_owned());
        assert_eq!(
            decrypt(&input, Some("mycred")),
            Err(CredentialsError::BadFormat)
        );
    }

    #[test]
    fn decrypt_empty_blob() {
        let input = DecryptInput::new(String::new());
        assert_eq!(
            decrypt(&input, None).unwrap_err(),
            CredentialsError::BadFormat
        );
    }

    #[test]
    fn error_display() {
        assert_eq!(format!("{}", CredentialsError::BadFormat), "BadFormat");
        assert_eq!(
            format!("{}", CredentialsError::KeyBelongsToOtherTpm),
            "KeyBelongsToOtherTPM"
        );
        assert_eq!(
            format!("{}", CredentialsError::TpmInDictionaryLockout),
            "TPMInDictionaryLockout"
        );
    }

    #[test]
    fn interface_name() {
        assert_eq!(INTERFACE_NAME, "io.systemd.Credentials");
    }
}
