// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/cryptsetup-fido2.c, src/shared/cryptsetup-fido2.h
//
// FIDO2 token key acquisition for LUKS2 volumes.
//
// Provides logic for unlocking LUKS2 encrypted volumes using FIDO2 security
// tokens (HMAC-secret extension). Handles device detection, PIN prompting,
// salt loading, and the full authentication loop including retries for
// missing/incorrect PINs.

use std::fmt;
use std::time::Duration;

use crate::ask_password_api::{AskPasswordFlags, AskPasswordRequest, ask_password_auto};
use crate::ffi::Errno;
use crate::libfido2_util::{Fido2EnrollFlags, Fido2Error, fido2_have_device, fido2_use_hmac_hash};

// ── Constants ─────────────────────────────────────────────────────────────

/// Default relying-party ID when none is specified.
const DEFAULT_RP_ID: &str = "io.systemd.cryptsetup";

/// Prompt message for FIDO2 PIN entry.
pub const FIDO2_PIN_PROMPT: &str = "Please enter security token PIN:";

/// Credential type string used in LUKS2 JSON token headers.
const TOKEN_TYPE: &str = "systemd-fido2";

/// Maximum number of LUKS2 tokens to scan.
const TOKEN_MAX: i32 = 32;

// ── Error type ────────────────────────────────────────────────────────────

/// Errors specific to FIDO2 key acquisition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CryptsetupFido2Error {
    /// FIDO2 support not compiled in or libfido2 unavailable.
    NotSupported,
    /// Local verification required but headless mode active.
    HeadlessVerificationRequired,
    /// Headless mode but PIN querying needed.
    HeadlessPinQuery,
    /// Invalid input (null credential, missing fields, etc.).
    InvalidArgument(String),
    /// FIDO2 device not found (caller should retry/wait).
    DeviceNotFound,
    /// No valid FIDO2 token data found on the LUKS2 volume.
    NoTokenData,
    /// Failed to read the salt key file.
    SaltFileError(String),
    /// Failed to decode base64 data from LUKS2 JSON token.
    Base64Error(String),
    /// Failed to read JSON token data from disk.
    TokenReadError(String),
    /// Failed to extract keyslot from token JSON.
    KeyslotError(String),
    /// PIN prompt / ask-password failure.
    AskPasswordError(String),
    /// Underlying FIDO2 operation error.
    Fido2(Fido2Error),
    /// Generic I/O or OS error.
    IoError(String),
}

impl fmt::Display for CryptsetupFido2Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotSupported => write!(f, "FIDO2 token support not available"),
            Self::HeadlessVerificationRequired => write!(
                f,
                "Local verification is required to unlock this volume, but the 'headless' parameter was set."
            ),
            Self::HeadlessPinQuery => write!(
                f,
                "PIN querying disabled via 'headless' option. Use the '$PIN' environment variable."
            ),
            Self::InvalidArgument(msg) => write!(f, "Invalid argument: {}", msg),
            Self::DeviceNotFound => write!(f, "FIDO2 device not found"),
            Self::NoTokenData => write!(f, "No valid FIDO2 token data found"),
            Self::SaltFileError(msg) => write!(f, "Failed to read salt file: {}", msg),
            Self::Base64Error(msg) => write!(f, "Base64 decode error: {}", msg),
            Self::TokenReadError(msg) => write!(f, "Failed to read token data: {}", msg),
            Self::KeyslotError(msg) => write!(f, "Keyslot error: {}", msg),
            Self::AskPasswordError(msg) => write!(f, "Password prompt error: {}", msg),
            Self::Fido2(e) => write!(f, "FIDO2 error: {}", e),
            Self::IoError(msg) => write!(f, "I/O error: {}", msg),
        }
    }
}

impl std::error::Error for CryptsetupFido2Error {}

impl From<Fido2Error> for CryptsetupFido2Error {
    fn from(e: Fido2Error) -> Self {
        Self::Fido2(e)
    }
}

impl From<std::io::Error> for CryptsetupFido2Error {
    fn from(e: std::io::Error) -> Self {
        Self::IoError(e.to_string())
    }
}

impl CryptsetupFido2Error {
    /// Map to the nearest negative errno value, mirroring the C return codes.
    pub fn to_neg_errno(&self) -> i32 {
        match self {
            Self::NotSupported => Errno::EOPNOTSUPP.to_neg_errno(),
            Self::HeadlessVerificationRequired | Self::HeadlessPinQuery => {
                // ENOPKG = 65 on Linux
                -(65)
            }
            Self::InvalidArgument(_) => Errno::EINVAL.to_neg_errno(),
            Self::DeviceNotFound => Errno::EAGAIN.to_neg_errno(),
            Self::NoTokenData => Errno::ENXIO.to_neg_errno(),
            Self::SaltFileError(_) | Self::TokenReadError(_) | Self::IoError(_) => {
                Errno::EIO.to_neg_errno()
            }
            Self::Base64Error(_) | Self::KeyslotError(_) => Errno::EINVAL.to_neg_errno(),
            Self::AskPasswordError(_) => Errno::EIO.to_neg_errno(),
            Self::Fido2(e) => {
                // Delegate to Fido2Error's own errno mapping
                let code: i32 = e.clone().into();
                code
            }
        }
    }
}

/// Convenience Result alias for this module.
pub type Result<T> = std::result::Result<T, CryptsetupFido2Error>;

// ── LUKS2 FIDO2 token metadata ───────────────────────────────────────────

/// Parsed FIDO2 metadata from a LUKS2 JSON token header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fido2TokenMetadata {
    /// The credential ID (base64-decoded).
    pub credential_id: Vec<u8>,
    /// The salt (base64-decoded).
    pub salt: Vec<u8>,
    /// Relying-party ID (optional, defaults to `io.systemd.cryptsetup`).
    pub rp_id: Option<String>,
    /// Client PIN is required.
    pub pin_required: bool,
    /// User presence is required.
    pub up_required: bool,
    /// User verification is required.
    pub uv_required: bool,
    /// Whether the `clientPin-required` field was present.
    pub has_pin_field: bool,
    /// Whether the `up-required` field was present.
    pub has_up_field: bool,
    /// Whether the `uv-required` field was present.
    pub has_uv_field: bool,
}

impl Fido2TokenMetadata {
    /// Compute the effective [`Fido2EnrollFlags`] from the parsed metadata.
    ///
    /// When a boolean field is absent from the JSON token (systemd 248 compat),
    /// the corresponding "if-needed" / "omit" flag is set instead.
    pub fn to_enroll_flags(&self) -> Fido2EnrollFlags {
        let mut flags = Fido2EnrollFlags::empty();

        if self.pin_required {
            flags.insert(Fido2EnrollFlags::PIN);
        } else if !self.has_pin_field {
            flags.insert(Fido2EnrollFlags::PIN_IF_NEEDED);
        }

        if self.up_required {
            flags.insert(Fido2EnrollFlags::UP);
        } else if !self.has_up_field {
            flags.insert(Fido2EnrollFlags::UP_IF_NEEDED);
        }

        if self.uv_required {
            flags.insert(Fido2EnrollFlags::UV);
        } else if !self.has_uv_field {
            flags.insert(Fido2EnrollFlags::UV_OMIT);
        }

        flags
    }

    /// Effective relying-party ID (falls back to the systemd default).
    pub fn effective_rp_id(&self) -> &str {
        self.rp_id.as_deref().unwrap_or(DEFAULT_RP_ID)
    }
}

// ── Key acquisition result ────────────────────────────────────────────────

/// The result of a successful FIDO2 key acquisition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecryptedKey {
    /// The raw decrypted key bytes.
    pub data: Vec<u8>,
}

// ── acquire_fido2_key ────────────────────────────────────────────────────

/// Parameters for [`acquire_fido2_key`].
#[derive(Debug, Clone)]
pub struct AcquireFido2KeyParams<'a> {
    /// Volume name (used for logging / agent identification).
    pub volume_name: &'a str,
    /// Human-friendly name shown in prompts.
    pub friendly_name: Option<&'a str>,
    /// Device path (e.g. `/dev/hidraw0`), or `None` for auto-detect.
    pub device: Option<&'a str>,
    /// Relying-party ID override.
    pub rp_id: Option<&'a str>,
    /// Credential ID bytes.
    pub credential_id: &'a [u8],
    /// Salt data (if provided directly, `key_file` is ignored).
    pub key_data: Option<&'a [u8]>,
    /// Key file path (used when `key_data` is `None`).
    pub key_file: Option<&'a std::path::Path>,
    /// Size to read from the key file (0 = whole file).
    pub key_file_size: u64,
    /// Byte offset within the key file.
    pub key_file_offset: u64,
    /// Deadline for user interaction.
    pub until: Option<Duration>,
    /// Required enrollment flags (PIN, UP, UV).
    pub required: Fido2EnrollFlags,
    /// Credential identifier for the ask-password agent.
    pub askpw_credential: &'a str,
    /// Flags controlling password prompting behaviour.
    pub askpw_flags: AskPasswordFlags,
    /// Initial PINs from the `$PIN` environment variable.
    pub env_pins: Vec<String>,
}

/// Acquire a decrypted LUKS2 key using a FIDO2 security token.
///
/// This is the Rust equivalent of the C `acquire_fido2_key()` function.
/// It performs the full authentication loop:
///
/// 1. Load the salt (from `key_data` or from a key file).
/// 2. Check if a FIDO2 device is present.
/// 3. Attempt HMAC-secret assertion with the current set of PINs.
/// 4. If the token needs a PIN or the PIN was wrong, prompt the user
///    (unless headless mode is active) and retry.
///
/// Returns the decrypted key on success.
pub fn acquire_fido2_key(params: &AcquireFido2KeyParams) -> Result<DecryptedKey> {
    let needs_verification = params
        .required
        .intersects(Fido2EnrollFlags::PIN | Fido2EnrollFlags::UP | Fido2EnrollFlags::UV);

    if needs_verification && params.askpw_flags.contains(AskPasswordFlags::HEADLESS) {
        return Err(CryptsetupFido2Error::HeadlessVerificationRequired);
    }

    if params.credential_id.is_empty() {
        return Err(CryptsetupFido2Error::InvalidArgument(
            "credential ID is empty".into(),
        ));
    }

    if params.key_data.is_none() && params.key_file.is_none() {
        return Err(CryptsetupFido2Error::InvalidArgument(
            "either key_data or key_file must be provided".into(),
        ));
    }

    // Resolve salt: use provided key_data or load from file
    let salt = if let Some(data) = params.key_data {
        data.to_vec()
    } else {
        // key_file is guaranteed Some here
        let path = params.key_file.unwrap();
        read_salt_file(path, params.key_file_offset, params.key_file_size)?
    };

    let rp_id = params.rp_id.unwrap_or(DEFAULT_RP_ID);
    let mut pins: Option<Vec<String>> = if params.env_pins.is_empty() {
        None
    } else {
        Some(params.env_pins.clone())
    };

    let mut device_exists = false;

    loop {
        if !device_exists {
            match fido2_have_device(params.device) {
                Ok(true) => {
                    device_exists = true;
                }
                Ok(false) => return Err(CryptsetupFido2Error::DeviceNotFound),
                Err(e) => return Err(CryptsetupFido2Error::Fido2(e)),
            }
        }

        // Attempt HMAC-secret assertion
        match fido2_use_hmac_hash(
            params.device,
            rp_id,
            &salt,
            params.credential_id,
            pins.as_ref().and_then(|v| v.first().map(|s| s.as_str())),
            !params.required.is_empty(),
        ) {
            Ok(key) => {
                return Ok(DecryptedKey { data: key });
            }
            Err(Fido2Error::PinRequired | Fido2Error::PinInvalid) => {
                // PIN needed or wrong — fall through to prompt
                device_exists = true;
            }
            Err(e) => return Err(CryptsetupFido2Error::Fido2(e)),
        }

        // Need to ask for PIN
        if params.askpw_flags.contains(AskPasswordFlags::HEADLESS) {
            return Err(CryptsetupFido2Error::HeadlessPinQuery);
        }

        let req = AskPasswordRequest {
            message: FIDO2_PIN_PROMPT.to_string(),
            icon: Some("drive-harddisk".to_string()),
            keyring: Some("fido2-pin".to_string()),
            credential: Some(params.askpw_credential.to_string()),
            tty_fd: -1,
            hup_fd: -1,
            until: params.until,
            ..Default::default()
        };

        match ask_password_auto(&req, params.askpw_flags) {
            Ok(new_pins) => {
                pins = Some(new_pins);
            }
            Err(e) => {
                return Err(CryptsetupFido2Error::AskPasswordError(e.to_string()));
            }
        }
    }
}

// ── acquire_fido2_key_auto ───────────────────────────────────────────────

/// Parameters for [`acquire_fido2_key_auto`].
#[derive(Debug, Clone)]
pub struct AcquireFido2KeyAutoParams<'a> {
    /// Volume name.
    pub name: &'a str,
    /// Human-friendly name.
    pub friendly_name: Option<&'a str>,
    /// FIDO2 device path (or `None` for auto-detect).
    pub fido2_device: Option<&'a str>,
    /// Deadline for user interaction.
    pub until: Option<Duration>,
    /// Credential identifier for the ask-password agent.
    pub askpw_credential: &'a str,
    /// Flags controlling password prompting behaviour.
    pub askpw_flags: AskPasswordFlags,
    /// Parsed LUKS2 JSON tokens to iterate over.
    pub tokens: &'a [Fido2TokenMetadata],
    /// Initial PINs from the `$PIN` environment variable.
    pub env_pins: Vec<String>,
}

/// Acquire a decrypted LUKS2 key using FIDO2, scanning all available tokens.
///
/// This is the Rust equivalent of the C `acquire_fido2_key_auto()` function.
/// It iterates over all LUKS2 JSON tokens of type `systemd-fido2`, parses
/// the FIDO2 metadata, and attempts to unlock the volume with each token
/// until one succeeds.
///
/// Returns the decrypted key on success, or an error if no token works.
pub fn acquire_fido2_key_auto(params: &AcquireFido2KeyAutoParams) -> Result<DecryptedKey> {
    if params.tokens.is_empty() {
        return Err(CryptsetupFido2Error::NoTokenData);
    }

    let mut last_error: Option<CryptsetupFido2Error> = None;

    for (token_idx, token) in params.tokens.iter().enumerate() {
        let flags = token.to_enroll_flags();

        let acquire_params = AcquireFido2KeyParams {
            volume_name: params.name,
            friendly_name: params.friendly_name,
            device: params.fido2_device,
            rp_id: token.rp_id.as_deref(),
            credential_id: &token.credential_id,
            key_data: Some(&token.salt),
            key_file: None,
            key_file_size: 0,
            key_file_offset: 0,
            until: params.until,
            required: flags,
            askpw_credential: params.askpw_credential,
            askpw_flags: params.askpw_flags,
            env_pins: params.env_pins.clone(),
        };

        match acquire_fido2_key(&acquire_params) {
            Ok(key) => return Ok(key),
            Err(CryptsetupFido2Error::DeviceNotFound) => {
                // Device not found: propagate as-is (caller will wait/watch udev)
                last_error = Some(CryptsetupFido2Error::DeviceNotFound);
            }
            Err(e) => {
                // Log warning for token parsing issues but continue scanning
                last_error = Some(CryptsetupFido2Error::InvalidArgument(format!(
                    "token {}: {}",
                    token_idx, e
                )));
                continue;
            }
        }
    }

    // We scanned at least one token (tokens was non-empty), so we found
    // FIDO2 data — report the last error.
    match last_error {
        Some(CryptsetupFido2Error::DeviceNotFound) => Err(CryptsetupFido2Error::DeviceNotFound),
        Some(e) => Err(e),
        None => Err(CryptsetupFido2Error::NoTokenData),
    }
}

// ── Salt file reading ────────────────────────────────────────────────────

/// Read salt data from a file, with optional offset and size limits.
///
/// This mirrors `fido2_read_salt_file()` behaviour for the cryptsetup context.
fn read_salt_file(path: &std::path::Path, offset: u64, size: u64) -> Result<Vec<u8>> {
    use std::fs::File;
    use std::io::{Read, Seek, SeekFrom};

    let mut file = File::open(path)
        .map_err(|e| CryptsetupFido2Error::SaltFileError(format!("{}: {}", path.display(), e)))?;

    if offset > 0 {
        file.seek(SeekFrom::Start(offset)).map_err(|e| {
            CryptsetupFido2Error::SaltFileError(format!(
                "seek to {} in {}: {}",
                offset,
                path.display(),
                e
            ))
        })?;
    }

    if size > 0 {
        let mut buf = vec![0u8; size as usize];
        let n = file.read(&mut buf).map_err(|e| {
            CryptsetupFido2Error::SaltFileError(format!("read from {}: {}", path.display(), e))
        })?;
        buf.truncate(n);
        Ok(buf)
    } else {
        let mut buf = Vec::new();
        file.read_to_end(&mut buf).map_err(|e| {
            CryptsetupFido2Error::SaltFileError(format!("read from {}: {}", path.display(), e))
        })?;
        Ok(buf)
    }
}

// ── Enrollment flag string conversion ────────────────────────────────────

/// Convert a set of FIDO2 enrollment flags to a human-readable comma-separated string.
pub fn fido2_enroll_flags_to_string(flags: Fido2EnrollFlags) -> String {
    let mut parts = Vec::new();

    if flags.contains(Fido2EnrollFlags::PIN) {
        parts.push("client-pin");
    }
    if flags.contains(Fido2EnrollFlags::UP) {
        parts.push("user-presence");
    }
    if flags.contains(Fido2EnrollFlags::UV) {
        parts.push("user-verification");
    }
    if flags.contains(Fido2EnrollFlags::PIN_IF_NEEDED) {
        parts.push("pin-if-needed");
    }
    if flags.contains(Fido2EnrollFlags::UP_IF_NEEDED) {
        parts.push("up-if-needed");
    }
    if flags.contains(Fido2EnrollFlags::UV_OMIT) {
        parts.push("uv-omit");
    }

    if parts.is_empty() {
        "none".to_string()
    } else {
        parts.join(",")
    }
}

/// Parse a single FIDO2 enrollment flag name.
pub fn parse_fido2_enroll_flag(s: &str) -> Option<Fido2EnrollFlags> {
    match s {
        "client-pin" => Some(Fido2EnrollFlags::PIN),
        "user-presence" => Some(Fido2EnrollFlags::UP),
        "user-verification" => Some(Fido2EnrollFlags::UV),
        "pin-if-needed" => Some(Fido2EnrollFlags::PIN_IF_NEEDED),
        "up-if-needed" => Some(Fido2EnrollFlags::UP_IF_NEEDED),
        "uv-omit" => Some(Fido2EnrollFlags::UV_OMIT),
        _ => None,
    }
}

/// Parse a comma-separated list of FIDO2 enrollment flags.
pub fn parse_fido2_enroll_flags(s: &str) -> Fido2EnrollFlags {
    s.split(',')
        .filter_map(|part| parse_fido2_enroll_flag(part.trim()))
        .fold(Fido2EnrollFlags::empty(), |acc, f| acc | f)
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Fido2TokenMetadata tests ───────────────────────────────────────

    #[test]
    fn test_token_metadata_to_enroll_flags_all_set() {
        let meta = Fido2TokenMetadata {
            credential_id: vec![1, 2, 3],
            salt: vec![0; 32],
            rp_id: Some("example.com".into()),
            pin_required: true,
            up_required: true,
            uv_required: true,
            has_pin_field: true,
            has_up_field: true,
            has_uv_field: true,
        };

        let flags = meta.to_enroll_flags();
        assert!(flags.contains(Fido2EnrollFlags::PIN));
        assert!(flags.contains(Fido2EnrollFlags::UP));
        assert!(flags.contains(Fido2EnrollFlags::UV));
        assert!(!flags.contains(Fido2EnrollFlags::PIN_IF_NEEDED));
        assert!(!flags.contains(Fido2EnrollFlags::UP_IF_NEEDED));
        assert!(!flags.contains(Fido2EnrollFlags::UV_OMIT));
    }

    #[test]
    fn test_token_metadata_to_enroll_flags_none_set() {
        let meta = Fido2TokenMetadata {
            credential_id: vec![1, 2, 3],
            salt: vec![0; 32],
            rp_id: None,
            pin_required: false,
            up_required: false,
            uv_required: false,
            has_pin_field: true,
            has_up_field: true,
            has_uv_field: true,
        };

        let flags = meta.to_enroll_flags();
        assert!(!flags.contains(Fido2EnrollFlags::PIN));
        assert!(!flags.contains(Fido2EnrollFlags::UP));
        assert!(!flags.contains(Fido2EnrollFlags::UV));
        // No compat flags when fields ARE present
        assert!(!flags.contains(Fido2EnrollFlags::PIN_IF_NEEDED));
        assert!(!flags.contains(Fido2EnrollFlags::UP_IF_NEEDED));
        assert!(!flags.contains(Fido2EnrollFlags::UV_OMIT));
    }

    #[test]
    fn test_token_metadata_compat_248_flags() {
        // systemd 248 compat: fields absent → if-needed/omit flags set
        let meta = Fido2TokenMetadata {
            credential_id: vec![1, 2, 3],
            salt: vec![0; 32],
            rp_id: None,
            pin_required: false,
            up_required: false,
            uv_required: false,
            has_pin_field: false,
            has_up_field: false,
            has_uv_field: false,
        };

        let flags = meta.to_enroll_flags();
        assert!(!flags.contains(Fido2EnrollFlags::PIN));
        assert!(!flags.contains(Fido2EnrollFlags::UP));
        assert!(!flags.contains(Fido2EnrollFlags::UV));
        assert!(flags.contains(Fido2EnrollFlags::PIN_IF_NEEDED));
        assert!(flags.contains(Fido2EnrollFlags::UP_IF_NEEDED));
        assert!(flags.contains(Fido2EnrollFlags::UV_OMIT));
    }

    #[test]
    fn test_token_metadata_effective_rp_id() {
        let with_rp = Fido2TokenMetadata {
            credential_id: vec![],
            salt: vec![],
            rp_id: Some("custom.com".into()),
            pin_required: false,
            up_required: false,
            uv_required: false,
            has_pin_field: false,
            has_up_field: false,
            has_uv_field: false,
        };
        assert_eq!(with_rp.effective_rp_id(), "custom.com");

        let without_rp = Fido2TokenMetadata {
            credential_id: vec![],
            salt: vec![],
            rp_id: None,
            pin_required: false,
            up_required: false,
            uv_required: false,
            has_pin_field: false,
            has_up_field: false,
            has_uv_field: false,
        };
        assert_eq!(without_rp.effective_rp_id(), DEFAULT_RP_ID);
    }

    // ── Enrollment flag parsing tests ─────────────────────────────────

    #[test]
    fn test_parse_fido2_enroll_flag() {
        assert_eq!(
            parse_fido2_enroll_flag("client-pin"),
            Some(Fido2EnrollFlags::PIN)
        );
        assert_eq!(
            parse_fido2_enroll_flag("user-presence"),
            Some(Fido2EnrollFlags::UP)
        );
        assert_eq!(
            parse_fido2_enroll_flag("user-verification"),
            Some(Fido2EnrollFlags::UV)
        );
        assert_eq!(
            parse_fido2_enroll_flag("pin-if-needed"),
            Some(Fido2EnrollFlags::PIN_IF_NEEDED)
        );
        assert_eq!(
            parse_fido2_enroll_flag("up-if-needed"),
            Some(Fido2EnrollFlags::UP_IF_NEEDED)
        );
        assert_eq!(
            parse_fido2_enroll_flag("uv-omit"),
            Some(Fido2EnrollFlags::UV_OMIT)
        );
        assert_eq!(parse_fido2_enroll_flag("invalid"), None);
        assert_eq!(parse_fido2_enroll_flag(""), None);
    }

    #[test]
    fn test_parse_fido2_enroll_flags_combined() {
        let flags = parse_fido2_enroll_flags("client-pin,user-presence");
        assert!(flags.contains(Fido2EnrollFlags::PIN));
        assert!(flags.contains(Fido2EnrollFlags::UP));
        assert!(!flags.contains(Fido2EnrollFlags::UV));
    }

    #[test]
    fn test_parse_fido2_enroll_flags_empty() {
        let flags = parse_fido2_enroll_flags("");
        assert!(flags.is_empty());
    }

    #[test]
    fn test_parse_fido2_enroll_flags_with_spaces() {
        let flags = parse_fido2_enroll_flags(" client-pin , user-presence ");
        assert!(flags.contains(Fido2EnrollFlags::PIN));
        assert!(flags.contains(Fido2EnrollFlags::UP));
    }

    #[test]
    fn test_fido2_enroll_flags_to_string() {
        assert_eq!(
            fido2_enroll_flags_to_string(Fido2EnrollFlags::empty()),
            "none"
        );
        assert_eq!(
            fido2_enroll_flags_to_string(Fido2EnrollFlags::PIN),
            "client-pin"
        );
        assert_eq!(
            fido2_enroll_flags_to_string(Fido2EnrollFlags::UP),
            "user-presence"
        );
        assert_eq!(
            fido2_enroll_flags_to_string(Fido2EnrollFlags::UV),
            "user-verification"
        );

        let combined = Fido2EnrollFlags::PIN | Fido2EnrollFlags::UP;
        let s = fido2_enroll_flags_to_string(combined);
        assert!(s.contains("client-pin"));
        assert!(s.contains("user-presence"));
    }

    #[test]
    fn test_fido2_enroll_flags_to_string_compat_flags() {
        let compat = Fido2EnrollFlags::PIN_IF_NEEDED
            | Fido2EnrollFlags::UP_IF_NEEDED
            | Fido2EnrollFlags::UV_OMIT;
        let s = fido2_enroll_flags_to_string(compat);
        assert!(s.contains("pin-if-needed"));
        assert!(s.contains("up-if-needed"));
        assert!(s.contains("uv-omit"));
    }

    // ── Error tests ──────────────────────────────────────────────────

    #[test]
    fn test_error_not_supported() {
        let e = CryptsetupFido2Error::NotSupported;
        assert_eq!(e.to_neg_errno(), Errno::EOPNOTSUPP.to_neg_errno());
        assert!(!e.to_string().is_empty());
    }

    #[test]
    fn test_error_headless_verification() {
        let e = CryptsetupFido2Error::HeadlessVerificationRequired;
        assert_eq!(e.to_neg_errno(), -65); // -ENOPKG
    }

    #[test]
    fn test_error_invalid_argument() {
        let e = CryptsetupFido2Error::InvalidArgument("bad cid".into());
        assert_eq!(e.to_neg_errno(), Errno::EINVAL.to_neg_errno());
        assert!(e.to_string().contains("bad cid"));
    }

    #[test]
    fn test_error_device_not_found() {
        let e = CryptsetupFido2Error::DeviceNotFound;
        assert_eq!(e.to_neg_errno(), Errno::EAGAIN.to_neg_errno());
    }

    #[test]
    fn test_error_no_token_data() {
        let e = CryptsetupFido2Error::NoTokenData;
        assert_eq!(e.to_neg_errno(), Errno::ENXIO.to_neg_errno());
    }

    #[test]
    fn test_error_from_fido2() {
        let fido_err = Fido2Error::PinRequired;
        let e = CryptsetupFido2Error::from(fido_err);
        assert!(matches!(
            e,
            CryptsetupFido2Error::Fido2(Fido2Error::PinRequired)
        ));
        // Verify errno delegation
        let code: i32 = Fido2Error::PinRequired.into();
        assert_eq!(e.to_neg_errno(), code);
    }

    // ── acquire_fido2_key validation tests ────────────────────────────

    #[test]
    fn test_acquire_fido2_key_empty_credential_id() {
        let params = AcquireFido2KeyParams {
            volume_name: "test",
            friendly_name: None,
            device: None,
            rp_id: None,
            credential_id: &[],
            key_data: Some(&[0; 32]),
            key_file: None,
            key_file_size: 0,
            key_file_offset: 0,
            until: None,
            required: Fido2EnrollFlags::empty(),
            askpw_credential: "cryptsetup.fido2-pin",
            askpw_flags: AskPasswordFlags::empty(),
            env_pins: vec![],
        };
        let err = acquire_fido2_key(&params).unwrap_err();
        assert!(matches!(err, CryptsetupFido2Error::InvalidArgument(_)));
    }

    #[test]
    fn test_acquire_fido2_key_no_key_source() {
        let params = AcquireFido2KeyParams {
            volume_name: "test",
            friendly_name: None,
            device: None,
            rp_id: None,
            credential_id: &[1, 2, 3],
            key_data: None,
            key_file: None,
            key_file_size: 0,
            key_file_offset: 0,
            until: None,
            required: Fido2EnrollFlags::empty(),
            askpw_credential: "cryptsetup.fido2-pin",
            askpw_flags: AskPasswordFlags::empty(),
            env_pins: vec![],
        };
        let err = acquire_fido2_key(&params).unwrap_err();
        assert!(matches!(err, CryptsetupFido2Error::InvalidArgument(_)));
    }

    #[test]
    fn test_acquire_fido2_key_headless_with_verification() {
        let params = AcquireFido2KeyParams {
            volume_name: "test",
            friendly_name: None,
            device: None,
            rp_id: None,
            credential_id: &[1, 2, 3],
            key_data: Some(&[0; 32]),
            key_file: None,
            key_file_size: 0,
            key_file_offset: 0,
            until: None,
            required: Fido2EnrollFlags::PIN,
            askpw_credential: "cryptsetup.fido2-pin",
            askpw_flags: AskPasswordFlags::HEADLESS,
            env_pins: vec![],
        };
        let err = acquire_fido2_key(&params).unwrap_err();
        assert!(matches!(
            err,
            CryptsetupFido2Error::HeadlessVerificationRequired
        ));
    }

    // ── acquire_fido2_key_auto validation tests ──────────────────────

    #[test]
    fn test_acquire_fido2_key_auto_empty_tokens() {
        let params = AcquireFido2KeyAutoParams {
            name: "test",
            friendly_name: None,
            fido2_device: None,
            until: None,
            askpw_credential: "cryptsetup.fido2-pin",
            askpw_flags: AskPasswordFlags::empty(),
            tokens: &[],
            env_pins: vec![],
        };
        let err = acquire_fido2_key_auto(&params).unwrap_err();
        assert!(matches!(err, CryptsetupFido2Error::NoTokenData));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_acquire_fido2_key_auto_single_token_device_not_found() {
        let token = Fido2TokenMetadata {
            credential_id: vec![1, 2, 3],
            salt: vec![0u8; 32],
            rp_id: None,
            pin_required: false,
            up_required: false,
            uv_required: false,
            has_pin_field: false,
            has_up_field: false,
            has_uv_field: false,
        };

        let params = AcquireFido2KeyAutoParams {
            name: "test",
            friendly_name: None,
            fido2_device: None,
            until: None,
            askpw_credential: "cryptsetup.fido2-pin",
            askpw_flags: AskPasswordFlags::empty(),
            tokens: &[token],
            env_pins: vec![],
        };

        // Will fail at device detection (no FIDO2 device present in test env)
        let err = acquire_fido2_key_auto(&params).unwrap_err();
        // Should be DeviceNotFound since the token iteration reaches acquire_fido2_key
        // which checks for the device
        assert!(matches!(err, CryptsetupFido2Error::DeviceNotFound));
    }

    // ── DecryptedKey tests ───────────────────────────────────────────

    #[test]
    fn test_decrypted_key() {
        let key = DecryptedKey {
            data: vec![0xDE, 0xAD, 0xBE, 0xEF],
        };
        assert_eq!(key.data.len(), 4);
        assert_eq!(key.data[0], 0xDE);
    }

    // ── Constants test ───────────────────────────────────────────────

    #[test]
    fn test_constants() {
        assert_eq!(DEFAULT_RP_ID, "io.systemd.cryptsetup");
        assert_eq!(TOKEN_TYPE, "systemd-fido2");
        assert_eq!(FIDO2_PIN_PROMPT, "Please enter security token PIN:");
        assert!(TOKEN_MAX > 0);
    }
}
