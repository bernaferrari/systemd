// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/varlink-io.systemd.Credentials.c
//
// Varlink interface definition for io.systemd.Credentials.
//
// APIs for encrypting and decrypting service credentials, with support
// for TPM2 binding, host keys, and scoped credential storage.

// ── Constants ─────────────────────────────────────────────────────────────

/// Interface name for the Credentials service.
pub const INTERFACE_NAME: &str = "io.systemd.Credentials";

/// Method name for Encrypt.
pub const METHOD_ENCRYPT: &str = "io.systemd.Credentials.Encrypt";

/// Method name for Decrypt.
pub const METHOD_DECRYPT: &str = "io.systemd.Credentials.Decrypt";

/// Error: corrupt or unsupported encrypted credential.
pub const ERROR_BAD_FORMAT: &str = "io.systemd.Credentials.BadFormat";

/// Error: specified name does not match the name stored in the credential.
pub const ERROR_NAME_MISMATCH: &str = "io.systemd.Credentials.NameMismatch";

/// Error: credential is no longer or not yet valid.
pub const ERROR_TIME_MISMATCH: &str = "io.systemd.Credentials.TimeMismatch";

/// Error: specified user does not exist.
pub const ERROR_NO_SUCH_USER: &str = "io.systemd.Credentials.NoSuchUser";

/// Error: credential does not match the selected scope.
pub const ERROR_BAD_SCOPE: &str = "io.systemd.Credentials.BadScope";

/// Error: PCR signature required for decryption but not found.
pub const ERROR_CANT_FIND_PCR_SIGNATURE: &str = "io.systemd.Credentials.CantFindPCRSignature";

/// Error: null key was used but is not allowed.
pub const ERROR_NULL_KEY_NOT_ALLOWED: &str = "io.systemd.Credentials.NullKeyNotAllowed";

/// Error: TPM integrity check failed, key belongs to another TPM.
pub const ERROR_KEY_BELONGS_TO_OTHER_TPM: &str = "io.systemd.Credentials.KeyBelongsToOtherTPM";

/// Error: TPM is in dictionary lockout mode.
pub const ERROR_TPM_IN_DICTIONARY_LOCKOUT: &str = "io.systemd.Credentials.TPMInDictionaryLockout";

/// Error: unexpected TPM PCR state.
pub const ERROR_UNEXPECTED_PCR_STATE: &str = "io.systemd.Credentials.UnexpectedPCRState";

// ── Enums ─────────────────────────────────────────────────────────────────

/// The intended scope for the credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// Generate a system-bound credential.
    System,
    /// Generate a system and user bound credential.
    User,
}

impl Scope {
    /// Parse a scope from its varlink string representation.
    pub fn from_str(s: &str) -> Result<Scope, i32> {
        match s {
            "system" => Ok(Scope::System),
            "user" => Ok(Scope::User),
            _ => Err(-22),
        }
    }

    /// Convert to the varlink string representation.
    pub fn as_str(&self) -> &'static str {
        match self {
            Scope::System => "system",
            Scope::User => "user",
        }
    }
}

/// Selects the type of key to encrypt the credential with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WithKey {
    /// Automatically pick the key to bind the credential to.
    Auto,
    /// Automatically pick, but ensure accessibility in the initrd.
    AutoInitrd,
    /// Bind to the host key only (not TPM).
    Host,
    /// Bind to the TPM only, not the host key.
    Tpm2,
    /// Bind to the TPM using a public key identifying the UKI.
    Tpm2WithPublicKey,
    /// Bind to both the TPM and the host key.
    HostTpm2,
    /// Bind to both the TPM (with public key) and the host key.
    HostTpm2WithPublicKey,
    /// No binding — null encryption (no authenticity or confidentiality).
    Null,
}

impl WithKey {
    /// Parse a WithKey from its varlink string representation.
    pub fn from_str(s: &str) -> Result<WithKey, i32> {
        match s {
            "auto" => Ok(WithKey::Auto),
            "auto_initrd" => Ok(WithKey::AutoInitrd),
            "host" => Ok(WithKey::Host),
            "tpm2" => Ok(WithKey::Tpm2),
            "tpm2_with_public_key" => Ok(WithKey::Tpm2WithPublicKey),
            "host_tpm2" => Ok(WithKey::HostTpm2),
            "host_tpm2_with_public_key" => Ok(WithKey::HostTpm2WithPublicKey),
            "null" => Ok(WithKey::Null),
            _ => Err(-22),
        }
    }

    /// Convert to the varlink string representation.
    pub fn as_str(&self) -> &'static str {
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

    /// Check if this key type involves the TPM.
    pub fn involves_tpm(&self) -> bool {
        matches!(
            self,
            WithKey::Tpm2
                | WithKey::Tpm2WithPublicKey
                | WithKey::HostTpm2
                | WithKey::HostTpm2WithPublicKey
                | WithKey::Auto
                | WithKey::AutoInitrd
        )
    }

    /// Check if this key type involves the host key.
    pub fn involves_host(&self) -> bool {
        matches!(
            self,
            WithKey::Host
                | WithKey::HostTpm2
                | WithKey::HostTpm2WithPublicKey
                | WithKey::Auto
                | WithKey::AutoInitrd
        )
    }

    /// Check if this is the null (no encryption) key type.
    pub fn is_null(&self) -> bool {
        matches!(self, WithKey::Null)
    }
}

// ── Structs ───────────────────────────────────────────────────────────────

/// Parameters for the Encrypt method.
#[derive(Debug, Clone, Default)]
pub struct EncryptParams {
    /// Name for the encrypted credential.
    pub name: Option<String>,
    /// Plaintext to encrypt (textual data).
    pub text: Option<String>,
    /// Plaintext to encrypt (Base64-encoded binary data).
    pub data: Option<String>,
    /// Timestamp in µs since UNIX epoch.
    pub timestamp: Option<i64>,
    /// Expiry timestamp in µs since UNIX epoch.
    pub not_after: Option<i64>,
    /// The intended scope.
    pub scope: Option<Scope>,
    /// The type of key to encrypt with.
    pub with_key: Option<WithKey>,
    /// The numeric UNIX UID (for user scope).
    pub uid: Option<i64>,
}

impl EncryptParams {
    /// Create a new empty EncryptParams.
    pub fn new() -> Self {
        Self::default()
    }

    /// Validate that at least one of text or data is provided.
    pub fn validate(&self) -> Result<(), i32> {
        if self.text.is_none() && self.data.is_none() {
            return Err(-22); // -EINVAL: must provide text or data
        }
        if let (Some(ts), Some(na)) = (self.timestamp, self.not_after) {
            if na < ts {
                return Err(-22); // notAfter before timestamp
            }
        }
        Ok(())
    }
}

/// Parameters for the Decrypt method.
#[derive(Debug, Clone, Default)]
pub struct DecryptParams {
    /// Name of the encrypted credential.
    pub name: Option<String>,
    /// The encrypted credential in Base64.
    pub blob: Option<String>,
    /// Timestamp for validation.
    pub timestamp: Option<i64>,
    /// The scope.
    pub scope: Option<Scope>,
    /// The numeric UNIX UID.
    pub uid: Option<i64>,
    /// Allow decryption of null-key-encrypted credentials.
    pub allow_null: Option<bool>,
}

impl DecryptParams {
    /// Create a new empty DecryptParams.
    pub fn new() -> Self {
        Self::default()
    }

    /// Validate that blob is provided.
    pub fn validate(&self) -> Result<(), i32> {
        if self.blob.is_none() {
            return Err(-22); // -EINVAL: blob is required
        }
        Ok(())
    }
}

// ── Interface definition ──────────────────────────────────────────────────

/// Returns the Varlink interface definition as a JSON string.
pub fn get_interface_definition() -> &'static str {
    r#"{
  "types": [
    {
      "name": "Scope",
      "type": "enum",
      "values": ["system", "user"]
    },
    {
      "name": "WithKey",
      "type": "enum",
      "values": ["auto", "auto_initrd", "host", "tpm2", "tpm2_with_public_key", "host_tpm2", "host_tpm2_with_public_key", "null"]
    }
  ],
  "methods": {
    "Encrypt": {
      "parameters": {
        "name": { "type": "string", "nullable": true },
        "text": { "type": "string", "nullable": true },
        "data": { "type": "string", "nullable": true },
        "timestamp": { "type": "int", "nullable": true },
        "notAfter": { "type": "int", "nullable": true },
        "scope": { "type": "Scope", "nullable": true },
        "withKey": { "type": "WithKey", "nullable": true },
        "uid": { "type": "int", "nullable": true }
      },
      "return": {
        "blob": { "type": "string" }
      }
    },
    "Decrypt": {
      "parameters": {
        "name": { "type": "string", "nullable": true },
        "blob": { "type": "string" },
        "timestamp": { "type": "int", "nullable": true },
        "scope": { "type": "Scope", "nullable": true },
        "uid": { "type": "int", "nullable": true },
        "allowNull": { "type": "bool", "nullable": true }
      },
      "return": {
        "data": { "type": "string" }
      }
    }
  },
  "errors": {
    "BadFormat": { "description": "Indicates that a corrupt and unsupported encrypted credential was provided." },
    "NameMismatch": { "description": "The specified name does not match the name stored in the credential." },
    "TimeMismatch": { "description": "The credential's is no longer or not yet valid." },
    "NoSuchUser": { "description": "The specified user does not exist." },
    "BadScope": { "description": "The credential does not match the selected scope." },
    "CantFindPCRSignature": { "description": "PCR signature required for decryption, but not found." },
    "NullKeyNotAllowed": { "description": "The key was encrypted with a null key, but that's now allowed during decryption." },
    "KeyBelongsToOtherTPM": { "description": "The TPM integrity check for this key failed, key probably belongs to another TPM, or was corrupted." },
    "TPMInDictionaryLockout": { "description": "The TPM is in dictionary lockout mode, cannot operate." },
    "UnexpectedPCRState": { "description": "Unexpected TPM PCR state of the system." }
  },
  "interface": "io.systemd.Credentials",
  "description": "APIs for encrypting and decrypting service credentials."
}"#
}

// ── Helper functions ──────────────────────────────────────────────────────

/// Check if a short method name belongs to this interface.
pub fn is_method(name: &str) -> bool {
    matches!(name, "Encrypt" | "Decrypt")
}

/// Look up the fully qualified method name from a short name.
pub fn qualified_method(short: &str) -> Result<&'static str, i32> {
    match short {
        "Encrypt" => Ok(METHOD_ENCRYPT),
        "Decrypt" => Ok(METHOD_DECRYPT),
        _ => Err(-22),
    }
}

/// Check if a fully qualified error name belongs to this interface.
pub fn is_error(name: &str) -> bool {
    matches!(
        name,
        ERROR_BAD_FORMAT
            | ERROR_NAME_MISMATCH
            | ERROR_TIME_MISMATCH
            | ERROR_NO_SUCH_USER
            | ERROR_BAD_SCOPE
            | ERROR_CANT_FIND_PCR_SIGNATURE
            | ERROR_NULL_KEY_NOT_ALLOWED
            | ERROR_KEY_BELONGS_TO_OTHER_TPM
            | ERROR_TPM_IN_DICTIONARY_LOCKOUT
            | ERROR_UNEXPECTED_PCR_STATE
    )
}

/// Collect all error names for this interface.
pub fn all_errors() -> Vec<&'static str> {
    vec![
        ERROR_BAD_FORMAT,
        ERROR_NAME_MISMATCH,
        ERROR_TIME_MISMATCH,
        ERROR_NO_SUCH_USER,
        ERROR_BAD_SCOPE,
        ERROR_CANT_FIND_PCR_SIGNATURE,
        ERROR_NULL_KEY_NOT_ALLOWED,
        ERROR_KEY_BELONGS_TO_OTHER_TPM,
        ERROR_TPM_IN_DICTIONARY_LOCKOUT,
        ERROR_UNEXPECTED_PCR_STATE,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_interface_name() {
        assert_eq!(INTERFACE_NAME, "io.systemd.Credentials");
    }

    #[test]
    fn test_method_constants() {
        assert_eq!(METHOD_ENCRYPT, "io.systemd.Credentials.Encrypt");
        assert_eq!(METHOD_DECRYPT, "io.systemd.Credentials.Decrypt");
    }

    #[test]
    fn test_scope_from_str() {
        assert_eq!(Scope::from_str("system"), Ok(Scope::System));
        assert_eq!(Scope::from_str("user"), Ok(Scope::User));
        assert!(Scope::from_str("invalid").is_err());
    }

    #[test]
    fn test_scope_as_str() {
        assert_eq!(Scope::System.as_str(), "system");
        assert_eq!(Scope::User.as_str(), "user");
    }

    #[test]
    fn test_scope_roundtrip() {
        assert_eq!(Scope::from_str(Scope::System.as_str()), Ok(Scope::System));
        assert_eq!(Scope::from_str(Scope::User.as_str()), Ok(Scope::User));
    }

    #[test]
    fn test_with_key_from_str() {
        assert_eq!(WithKey::from_str("auto"), Ok(WithKey::Auto));
        assert_eq!(WithKey::from_str("auto_initrd"), Ok(WithKey::AutoInitrd));
        assert_eq!(WithKey::from_str("host"), Ok(WithKey::Host));
        assert_eq!(WithKey::from_str("tpm2"), Ok(WithKey::Tpm2));
        assert_eq!(
            WithKey::from_str("tpm2_with_public_key"),
            Ok(WithKey::Tpm2WithPublicKey)
        );
        assert_eq!(WithKey::from_str("host_tpm2"), Ok(WithKey::HostTpm2));
        assert_eq!(
            WithKey::from_str("host_tpm2_with_public_key"),
            Ok(WithKey::HostTpm2WithPublicKey)
        );
        assert_eq!(WithKey::from_str("null"), Ok(WithKey::Null));
        assert!(WithKey::from_str("invalid").is_err());
    }

    #[test]
    fn test_with_key_as_str() {
        assert_eq!(WithKey::Auto.as_str(), "auto");
        assert_eq!(WithKey::Null.as_str(), "null");
        assert_eq!(
            WithKey::HostTpm2WithPublicKey.as_str(),
            "host_tpm2_with_public_key"
        );
    }

    #[test]
    fn test_with_key_involves_tpm() {
        assert!(WithKey::Tpm2.involves_tpm());
        assert!(WithKey::HostTpm2.involves_tpm());
        assert!(WithKey::Auto.involves_tpm());
        assert!(!WithKey::Host.involves_tpm());
        assert!(!WithKey::Null.involves_tpm());
    }

    #[test]
    fn test_with_key_involves_host() {
        assert!(WithKey::Host.involves_host());
        assert!(WithKey::HostTpm2.involves_host());
        assert!(!WithKey::Tpm2.involves_host());
        assert!(!WithKey::Null.involves_host());
    }

    #[test]
    fn test_with_key_is_null() {
        assert!(WithKey::Null.is_null());
        assert!(!WithKey::Auto.is_null());
        assert!(!WithKey::Host.is_null());
    }

    #[test]
    fn test_encrypt_params_validate_text() {
        let p = EncryptParams::new();
        assert!(p.validate().is_err()); // no text or data
    }

    #[test]
    fn test_encrypt_params_validate_with_text() {
        let mut p = EncryptParams::new();
        p.text = Some("hello".into());
        assert!(p.validate().is_ok());
    }

    #[test]
    fn test_encrypt_params_validate_with_data() {
        let mut p = EncryptParams::new();
        p.data = Some("aGVsbG8=".into());
        assert!(p.validate().is_ok());
    }

    #[test]
    fn test_encrypt_params_validate_timestamp_order() {
        let mut p = EncryptParams::new();
        p.text = Some("hello".into());
        p.timestamp = Some(2000);
        p.not_after = Some(1000);
        assert!(p.validate().is_err()); // notAfter < timestamp
    }

    #[test]
    fn test_decrypt_params_validate_requires_blob() {
        let p = DecryptParams::new();
        assert!(p.validate().is_err()); // no blob
    }

    #[test]
    fn test_decrypt_params_validate_with_blob() {
        let mut p = DecryptParams::new();
        p.blob = Some("aGVsbG8=".into());
        assert!(p.validate().is_ok());
    }

    #[test]
    fn test_interface_definition_contents() {
        let def = get_interface_definition();
        assert!(def.contains("io.systemd.Credentials"));
        assert!(def.contains("Encrypt"));
        assert!(def.contains("Decrypt"));
        assert!(def.contains("Scope"));
        assert!(def.contains("WithKey"));
        assert!(def.contains("BadFormat"));
        assert!(def.contains("UnexpectedPCRState"));
    }

    #[test]
    fn test_is_method() {
        assert!(is_method("Encrypt"));
        assert!(is_method("Decrypt"));
        assert!(!is_method("encrypt"));
        assert!(!is_method("Ping"));
    }

    #[test]
    fn test_qualified_method() {
        assert_eq!(qualified_method("Encrypt"), Ok(METHOD_ENCRYPT));
        assert_eq!(qualified_method("Decrypt"), Ok(METHOD_DECRYPT));
        assert!(qualified_method("Ping").is_err());
    }

    #[test]
    fn test_is_error() {
        assert!(is_error(ERROR_BAD_FORMAT));
        assert!(is_error(ERROR_UNEXPECTED_PCR_STATE));
        assert!(!is_error("io.systemd.Credentials.Unknown"));
    }

    #[test]
    fn test_all_errors() {
        let errors = all_errors();
        assert_eq!(errors.len(), 10);
        assert!(errors.contains(&ERROR_BAD_FORMAT));
        assert!(errors.contains(&ERROR_UNEXPECTED_PCR_STATE));
    }
}
