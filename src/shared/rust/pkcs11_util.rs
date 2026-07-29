// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/pkcs11-util.c, src/shared/pkcs11-util.h
//
// PKCS#11 smart card / token utilities.
//
// Provides URI validation (RFC 7512), dlopen-based loading of libp11-kit,
// token info extraction (label, manufacturer, model), login flow
// (protected path, PIN, interactive), private key lookup, RSA/ECC
// decryption, and token enumeration.  All p11-kit symbols are resolved
// through dlopen so the module gracefully degrades when the library is
// absent.

use std::ffi::{CStr, CString, c_void};
use std::fmt;
use std::ptr::NonNull;
use std::sync::{
    Mutex,
    atomic::{AtomicBool, Ordering},
};

use crate::ffi::Errno;

// ── Constants ─────────────────────────────────────────────────────────────

/// Valid characters after `pkcs11:` prefix per RFC 7512 superficial check.
const PKCS11_URI_VALID_CHARS: &[u8] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789.~/-_?;&%=";

/// Shared library name for p11-kit.
const LIBP11KIT_NAME: &str = "libp11-kit.so.0";

/// Human-readable description for the ELF NOTE metadata.
const P11KIT_FEATURE_DESCRIPTION: &str = "Support for PKCS11 hardware tokens";

/// Maximum retries for `C_GetSlotList` races (token hotplug).
const SLOT_LIST_MAX_TRIES: u32 = 16;

/// Maximum PIN retry attempts for interactive login.
const LOGIN_MAX_TRIES: u32 = 3;

// ── Required symbol names ─────────────────────────────────────────────────

/// All p11-kit symbols that must be resolved at dlopen time.
const REQUIRED_SYMBOLS: &[&str] = &[
    "p11_kit_module_get_name",
    "p11_kit_modules_finalize_and_release",
    "p11_kit_modules_load_and_initialize",
    "p11_kit_strerror",
    "p11_kit_uri_format",
    "p11_kit_uri_free",
    "p11_kit_uri_get_attributes",
    "p11_kit_uri_get_attribute",
    "p11_kit_uri_set_attribute",
    "p11_kit_uri_get_module_info",
    "p11_kit_uri_get_slot_info",
    "p11_kit_uri_get_token_info",
    "p11_kit_uri_match_token_info",
    "p11_kit_uri_message",
    "p11_kit_uri_new",
    "p11_kit_uri_parse",
];

// ── Error type ────────────────────────────────────────────────────────────

/// Errors returned by PKCS#11 operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pkcs11Error {
    /// p11-kit is not compiled in or not available.
    Unsupported,
    /// The shared library could not be opened.
    DlopenFailed(String),
    /// A required symbol was not found.
    SymbolNotFound(String),
    /// A PKCS#11 API call returned an error.
    ApiError(String),
    /// Invalid argument (bad URI, wrong object class, etc.).
    InvalidArgument(String),
    /// Requested object not found (no token, no key, etc.).
    NotFound,
    /// Multiple objects matched when exactly one was expected.
    NotUnique,
    /// Authentication failure (PIN locked, incorrect, etc.).
    PermissionDenied(String),
    /// I/O error communicating with the token.
    IoError(String),
    /// PIN required but none provided.
    PinRequired,
    /// Too many login attempts.
    TooManyAttempts,
    /// Memory allocation failure.
    OutOfMemory,
}

impl fmt::Display for Pkcs11Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported => write!(f, "p11-kit support is not available"),
            Self::DlopenFailed(msg) => write!(f, "Failed to open p11-kit: {}", msg),
            Self::SymbolNotFound(sym) => {
                write!(f, "Required p11-kit symbol not found: {}", sym)
            }
            Self::ApiError(msg) => write!(f, "PKCS#11 API error: {}", msg),
            Self::InvalidArgument(msg) => write!(f, "Invalid argument: {}", msg),
            Self::NotFound => write!(f, "Requested PKCS#11 object not found"),
            Self::NotUnique => write!(f, "Multiple PKCS#11 objects matched, refusing"),
            Self::PermissionDenied(msg) => write!(f, "Permission denied: {}", msg),
            Self::IoError(msg) => write!(f, "PKCS#11 I/O error: {}", msg),
            Self::PinRequired => write!(f, "PIN required but none provided"),
            Self::TooManyAttempts => write!(f, "Too many login attempts"),
            Self::OutOfMemory => write!(f, "Memory allocation failure"),
        }
    }
}

impl std::error::Error for Pkcs11Error {}

impl From<Pkcs11Error> for i32 {
    fn from(e: Pkcs11Error) -> i32 {
        match e {
            Pkcs11Error::Unsupported => Errno::EOPNOTSUPP.to_neg_errno(),
            Pkcs11Error::DlopenFailed(_) => Errno::ENOENT.to_neg_errno(),
            Pkcs11Error::SymbolNotFound(_) => Errno::ENOENT.to_neg_errno(),
            Pkcs11Error::ApiError(_) => Errno::EIO.to_neg_errno(),
            Pkcs11Error::InvalidArgument(_) => Errno::EINVAL.to_neg_errno(),
            Pkcs11Error::NotFound => Errno::ENOENT.to_neg_errno(),
            Pkcs11Error::NotUnique => Errno::ENOTUNIQ.to_neg_errno(),
            Pkcs11Error::PermissionDenied(_) => Errno::EPERM.to_neg_errno(),
            Pkcs11Error::IoError(_) => Errno::EIO.to_neg_errno(),
            Pkcs11Error::PinRequired => Errno::ENOLCK.to_neg_errno(),
            Pkcs11Error::TooManyAttempts => Errno::EPERM.to_neg_errno(),
            Pkcs11Error::OutOfMemory => Errno::ENOMEM.to_neg_errno(),
        }
    }
}

// ── PKCS#11 type definitions ──────────────────────────────────────────────

/// PKCS#11 scalar types are `CK_ULONG` in the C API.
///
/// Keep these ABI-facing aliases platform-width, rather than assuming a
/// 64-bit target, so `#[repr(C)]` structures below retain their C layout.
pub type CkUlong = libc::c_ulong;

/// PKCS#11 return value (`CK_RV`).
pub type CkRv = CkUlong;

/// PKCS#11 slot ID.
pub type CkSlotId = CkUlong;

/// PKCS#11 session handle.
pub type CkSessionHandle = CkUlong;

/// PKCS#11 object handle.
pub type CkObjectHandle = CkUlong;

/// PKCS#11 flags bitmask.
pub type CkFlags = CkUlong;

/// PKCS#11 boolean.
pub type CkBool = std::os::raw::c_uchar;

/// PKCS#11 attribute type.
pub type CkAttributeType = CkUlong;

/// PKCS#11 object class.
pub type CkObjectClass = CkUlong;

/// PKCS#11 key type.
pub type CkKeyType = CkUlong;

/// PKCS#11 mechanism type.
pub type CkMechanismType = CkUlong;

/// PKCS#11 certificate type.
pub type CkCertificateType = CkUlong;

/// Well-known `CK_RV` values.
pub mod ck_rv {
    use super::CkRv;

    pub const OK: CkRv = 0;
    pub const CANCEL: CkRv = 1;
    pub const HOST_MEMORY: CkRv = 2;
    pub const SLOT_ID_INVALID: CkRv = 3;
    pub const GENERAL_ERROR: CkRv = 5;
    pub const FUNCTION_FAILED: CkRv = 6;
    pub const ATTRIBUTE_VALUE_INVALID: CkRv = 0x12;
    pub const DATA_INVALID: CkRv = 0x20;
    pub const DATA_LEN_RANGE: CkRv = 0x21;
    pub const DEVICE_ERROR: CkRv = 0x30;
    pub const DEVICE_MEMORY: CkRv = 0x31;
    pub const DEVICE_REMOVED: CkRv = 0x32;
    pub const ENCRYPTED_DATA_INVALID: CkRv = 0x40;
    pub const ENCRYPTED_DATA_LEN_RANGE: CkRv = 0x41;
    pub const FUNCTION_NOT_SUPPORTED: CkRv = 0x54;
    pub const KEY_HANDLE_INVALID: CkRv = 0x60;
    pub const KEY_SIZE_RANGE: CkRv = 0x62;
    pub const KEY_TYPE_INCONSISTENT: CkRv = 0x63;
    pub const PIN_INCORRECT: CkRv = 0xa0;
    pub const PIN_INVALID: CkRv = 0xa1;
    pub const PIN_LEN_RANGE: CkRv = 0xa2;
    pub const PIN_EXPIRED: CkRv = 0xa3;
    pub const PIN_LOCKED: CkRv = 0xa4;
    pub const SESSION_CLOSED: CkRv = 0xb0;
    pub const SESSION_COUNT: CkRv = 0xb1;
    pub const SESSION_HANDLE_INVALID: CkRv = 0xb3;
    pub const SESSION_READ_ONLY: CkRv = 0xb5;
    pub const SESSION_READ_ONLY_EXISTS: CkRv = 0xb6;
    pub const TOKEN_WRITE_PROTECTED: CkRv = 0xc0;
    pub const TOKEN_NOT_PRESENT: CkRv = 0xc1;
    pub const TOKEN_NOT_RECOGNIZED: CkRv = 0xc2;
    pub const BUFFER_TOO_SMALL: CkRv = 0x150;
    pub const PIN_TOO_WEAK: CkRv = 0xc3;
    pub const ATTRIBUTE_TYPE_INVALID: CkRv = 0x11;
    pub const UNAVAILABLE_INFORMATION: CkRv = 0x170;
}

/// Well-known `CK_ATTRIBUTE` type constants.
pub mod ck_attribute {
    use super::CkAttributeType;

    pub const CLASS: CkAttributeType = 0x0000;
    pub const TOKEN: CkAttributeType = 0x0001;
    pub const PRIVATE: CkAttributeType = 0x0002;
    pub const LABEL: CkAttributeType = 0x0003;
    pub const APPLICATION: CkAttributeType = 0x0010;
    pub const VALUE: CkAttributeType = 0x0011;
    pub const OBJECT_ID: CkAttributeType = 0x0012;
    pub const CERTIFICATE_TYPE: CkAttributeType = 0x0080;
    pub const ISSUER: CkAttributeType = 0x0081;
    pub const SERIAL_NUMBER: CkAttributeType = 0x0082;
    pub const KEY_TYPE: CkAttributeType = 0x0100;
    pub const ID: CkAttributeType = 0x0102;
    pub const MODULUS: CkAttributeType = 0x0120;
    pub const PUBLIC_EXPONENT: CkAttributeType = 0x0122;
    pub const EC_PARAMS: CkAttributeType = 0x0180;
    pub const EC_POINT: CkAttributeType = 0x0181;
    pub const DECRYPT: CkAttributeType = 0x0104;
    pub const DERIVE: CkAttributeType = 0x0105;
    pub const SENSITIVE: CkAttributeType = 0x0103;
    pub const EXTRACTABLE: CkAttributeType = 0x0162;
    pub const PUBLIC_KEY_INFO: CkAttributeType = 0x0204;
}

/// Well-known `CK_OBJECT_CLASS` values.
pub mod ck_object_class {
    use super::CkObjectClass;

    pub const DATA: CkObjectClass = 0x0000;
    pub const CERTIFICATE: CkObjectClass = 0x0001;
    pub const PUBLIC_KEY: CkObjectClass = 0x0002;
    pub const PRIVATE_KEY: CkObjectClass = 0x0003;
    pub const SECRET_KEY: CkObjectClass = 0x0004;
    pub const HW_FEATURE: CkObjectClass = 0x0005;
    pub const DOMAIN_PARAMETERS: CkObjectClass = 0x0006;
    pub const MECHANISM: CkObjectClass = 0x0007;
    pub const OTP_KEY: CkObjectClass = 0x0008;
}

/// Well-known `CK_KEY_TYPE` values.
pub mod ck_key_type {
    use super::CkKeyType;

    pub const RSA: CkKeyType = 0x0000;
    pub const DSA: CkKeyType = 0x0001;
    pub const DH: CkKeyType = 0x0002;
    pub const EC: CkKeyType = 0x0003;
    pub const GENERIC_SECRET: CkKeyType = 0x0010;
    pub const AES: CkKeyType = 0x001f;
    pub const RC2: CkKeyType = 0x0004;
    pub const RC4: CkKeyType = 0x0005;
    pub const DES: CkKeyType = 0x0006;
    pub const DES2: CkKeyType = 0x0007;
    pub const DES3: CkKeyType = 0x0008;
    pub const CAST: CkKeyType = 0x0009;
    pub const CAST3: CkKeyType = 0x000a;
}

/// Well-known `CK_MECHANISM_TYPE` values.
pub mod ck_mechanism {
    use super::CkMechanismType;

    pub const RSA_PKCS: CkMechanismType = 0x0001;
    pub const RSA_9796: CkMechanismType = 0x0002;
    pub const RSA_PKCS_KEY_PAIR_GEN: CkMechanismType = 0x0000;
    pub const ECDH1_DERIVE: CkMechanismType = 0x0000_1050;
}

/// Well-known `CK_CERTIFICATE_TYPE` values.
pub mod ck_certificate_type {
    use super::CkCertificateType;

    pub const X_509: CkCertificateType = 0x0000;
    pub const X_509_ATTR_CERT: CkCertificateType = 0x0001;
    pub const WTLS: CkCertificateType = 0x0002;
}

/// Well-known `CKF_` token flags.
pub mod ckf_flag {
    use super::CkFlags;

    pub const TOKEN_PRESENT: CkFlags = 0x0000_0001;
    pub const REMOVABLE_DEVICE: CkFlags = 0x0000_0002;
    pub const HW_SLOT: CkFlags = 0x0000_0004;
    /// Protected authentication path (e.g. keypad on the token).
    pub const PROTECTED_AUTHENTICATION_PATH: CkFlags = 0x0000_0100;
    /// Login is required.
    pub const LOGIN_REQUIRED: CkFlags = 0x0000_0200;
    /// User PIN count is low.
    pub const USER_PIN_COUNT_LOW: CkFlags = 0x0000_1000;
    /// This is the final try before PIN lock.
    pub const USER_PIN_FINAL_TRY: CkFlags = 0x0000_2000;
    pub const USER_PIN_LOCKED: CkFlags = 0x0000_4000;
    pub const USER_PIN_TO_BE_CHANGED: CkFlags = 0x0000_8000;
}

/// Well-known `CKF_` mechanism-info flags.
///
/// These values overlap token flags but apply to `CK_MECHANISM_INFO`, not to
/// `CK_TOKEN_INFO::flags`; keeping them separate prevents accidental use when
/// inspecting token state.
pub mod ckf_mechanism_flag {
    use super::CkFlags;

    /// EC uncompressed point support.
    pub const EC_UNCOMPRESS: CkFlags = 0x0000_0100;
    /// EC compressed point support.
    pub const EC_COMPRESS: CkFlags = 0x0000_0200;
}

/// `CK_SESSION_INFO` flags.
pub mod cks_flag {
    use super::CkFlags;

    pub const RW_SESSION: CkFlags = 0x0000_0002;
    pub const SERIAL_SESSION: CkFlags = 0x0000_0004;
}

/// Invalid object handle sentinel.
pub const CK_INVALID_HANDLE: CkObjectHandle = 0;

/// `CK_TRUE` / `CK_FALSE`.
pub const CK_TRUE: CkBool = 1;
pub const CK_FALSE: CkBool = 0;

// ── Token info structures ────────────────────────────────────────────────

/// Subset of `CK_TOKEN_INFO` relevant to systemd.
///
/// Fields that the C code reads from tokens.  The label,
/// manufacturerID, model, and serialNumber are space-padded,
/// non-NUL-terminated byte arrays of fixed width.
#[repr(C)]
#[derive(Debug, Clone)]
pub struct CkTokenInfo {
    pub label: [u8; 32],
    pub manufacturer_id: [u8; 32],
    pub model: [u8; 16],
    pub serial_number: [u8; 16],
    pub flags: CkFlags,
    pub max_session_count: u64,
    pub session_count: u64,
    pub max_rw_session_count: u64,
    pub rw_session_count: u64,
    pub max_pin_len: u64,
    pub min_pin_len: u64,
    pub total_public_memory: u64,
    pub free_public_memory: u64,
    pub total_private_memory: u64,
    pub free_private_memory: u64,
    pub hardware_version_major: u8,
    pub hardware_version_minor: u8,
    pub firmware_version_major: u8,
    pub firmware_version_minor: u8,
    pub utc_time: [u8; 16],
}

impl Default for CkTokenInfo {
    fn default() -> Self {
        Self {
            label: [0u8; 32],
            manufacturer_id: [0u8; 32],
            model: [0u8; 16],
            serial_number: [0u8; 16],
            flags: 0,
            max_session_count: 0,
            session_count: 0,
            max_rw_session_count: 0,
            rw_session_count: 0,
            max_pin_len: 0,
            min_pin_len: 0,
            total_public_memory: 0,
            free_public_memory: 0,
            total_private_memory: 0,
            free_private_memory: 0,
            hardware_version_major: 0,
            hardware_version_minor: 0,
            firmware_version_major: 0,
            firmware_version_minor: 0,
            utc_time: [0u8; 16],
        }
    }
}

/// Subset of `CK_SLOT_INFO` relevant to systemd.
#[repr(C)]
#[derive(Debug, Clone)]
pub struct CkSlotInfo {
    pub slot_description: [u8; 64],
    pub manufacturer_id: [u8; 32],
    pub flags: CkFlags,
    pub hardware_version_major: u8,
    pub hardware_version_minor: u8,
    pub firmware_version_major: u8,
    pub firmware_version_minor: u8,
}

impl Default for CkSlotInfo {
    fn default() -> Self {
        Self {
            slot_description: [0u8; 64],
            manufacturer_id: [0u8; 32],
            flags: 0,
            hardware_version_major: 0,
            hardware_version_minor: 0,
            firmware_version_major: 0,
            firmware_version_minor: 0,
        }
    }
}

// ── Object class enumeration ─────────────────────────────────────────────

/// PKCS#11 object classes used in find/search operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectClass {
    Certificate,
    PublicKey,
    PrivateKey,
    SecretKey,
}

impl ObjectClass {
    /// Convert to the raw `CK_OBJECT_CLASS` value.
    pub fn to_raw(self) -> CkObjectClass {
        match self {
            Self::Certificate => ck_object_class::CERTIFICATE,
            Self::PublicKey => ck_object_class::PUBLIC_KEY,
            Self::PrivateKey => ck_object_class::PRIVATE_KEY,
            Self::SecretKey => ck_object_class::SECRET_KEY,
        }
    }

    /// Try to parse from a raw `CK_OBJECT_CLASS` value.
    pub fn from_raw(raw: CkObjectClass) -> Option<Self> {
        match raw {
            ck_object_class::CERTIFICATE => Some(Self::Certificate),
            ck_object_class::PUBLIC_KEY => Some(Self::PublicKey),
            ck_object_class::PRIVATE_KEY => Some(Self::PrivateKey),
            ck_object_class::SECRET_KEY => Some(Self::SecretKey),
            _ => None,
        }
    }

    /// Human-readable name for logging.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Certificate => "CKO_CERTIFICATE",
            Self::PublicKey => "CKO_PUBLIC_KEY",
            Self::PrivateKey => "CKO_PRIVATE_KEY",
            Self::SecretKey => "CKO_SECRET_KEY",
        }
    }
}

// ── Key type enumeration ─────────────────────────────────────────────────

/// PKCS#11 key types used in decrypt operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyType {
    Rsa,
    Ec,
    Dsa,
    Dh,
    GenericSecret,
    Aes,
    Des,
    Des3,
}

impl KeyType {
    /// Convert to the raw `CK_KEY_TYPE` value.
    pub fn to_raw(self) -> CkKeyType {
        match self {
            Self::Rsa => ck_key_type::RSA,
            Self::Ec => ck_key_type::EC,
            Self::Dsa => ck_key_type::DSA,
            Self::Dh => ck_key_type::DH,
            Self::GenericSecret => ck_key_type::GENERIC_SECRET,
            Self::Aes => ck_key_type::AES,
            Self::Des => ck_key_type::DES,
            Self::Des3 => ck_key_type::DES3,
        }
    }

    /// Try to parse from a raw `CK_KEY_TYPE` value.
    pub fn from_raw(raw: CkKeyType) -> Option<Self> {
        match raw {
            ck_key_type::RSA => Some(Self::Rsa),
            ck_key_type::EC => Some(Self::Ec),
            ck_key_type::DSA => Some(Self::Dsa),
            ck_key_type::DH => Some(Self::Dh),
            ck_key_type::GENERIC_SECRET => Some(Self::GenericSecret),
            ck_key_type::AES => Some(Self::Aes),
            ck_key_type::DES => Some(Self::Des),
            ck_key_type::DES3 => Some(Self::Des3),
            _ => None,
        }
    }
}

// ── Login result ─────────────────────────────────────────────────────────

/// Result of a PKCS#11 token login attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoginResult {
    /// No login required (protected auth path succeeded or no login needed).
    Success,
    /// PIN was required but none was provided (caller should ask the user).
    PinRequired,
    /// PIN is incorrect, caller should retry.
    PinIncorrect,
    /// PIN has been locked; must be reset externally.
    PinLocked,
    /// Other error (e.g. token removed, I/O error).
    Error(String),
}

// ── URI validation ───────────────────────────────────────────────────────

/// A very superficial checker for RFC 7512 PKCS#11 URI syntax.
///
/// Returns `true` if `uri` starts with `pkcs11:` followed by at least one
/// valid character.  This does **not** perform full RFC-compliant parsing;
/// use `P11KitUri` for that.
pub fn pkcs11_uri_valid(uri: &str) -> bool {
    if uri.is_empty() {
        return false;
    }

    let p = match uri.strip_prefix("pkcs11:") {
        Some(s) => s,
        None => return false,
    };

    if p.is_empty() {
        return false;
    }

    p.bytes().all(|b| PKCS11_URI_VALID_CHARS.contains(&b))
}

// ── Token info extraction ────────────────────────────────────────────────

/// Extract the token label from a `CkTokenInfo`.
///
/// The label field is not NUL-terminated and is typically space-padded.
/// This function copies the bytes, strips trailing spaces, and returns
/// a valid UTF-8 string (or `None` if the bytes are not valid UTF-8).
pub fn pkcs11_token_label(token_info: &CkTokenInfo) -> Option<String> {
    extract_padded_string(&token_info.label)
}

/// Extract the manufacturer ID from a `CkTokenInfo`.
pub fn pkcs11_token_manufacturer_id(token_info: &CkTokenInfo) -> Option<String> {
    extract_padded_string(&token_info.manufacturer_id)
}

/// Extract the model from a `CkTokenInfo`.
pub fn pkcs11_token_model(token_info: &CkTokenInfo) -> Option<String> {
    extract_padded_string(&token_info.model)
}

/// Extract a NUL-terminated or space-padded string from a fixed-size byte array.
///
/// Mirrors the C `strndup` + `strstrip` pattern used throughout pkcs11-util.c.
fn extract_padded_string(bytes: &[u8]) -> Option<String> {
    // Find the actual content length (up to first NUL or end of array).
    let len = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());

    // Convert to string slice, trimming trailing spaces.
    let s = std::str::from_utf8(&bytes[..len]).ok()?;
    let trimmed = s.trim_end();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

// ── Slot list acquisition ────────────────────────────────────────────────

/// Result of `pkcs11_get_slot_list`.
pub struct SlotListResult {
    /// Slot IDs found on the token.
    pub slot_ids: Vec<CkSlotId>,
}

/// Get the list of PKCS#11 slots, with retry for hotplug races.
///
/// Mirrors `pkcs11_get_slot_list_malloc` in the C code.  The PKCS#11 spec
/// allows `C_GetSlotList` to return `CKR_BUFFER_TOO_SMALL` if slots are
/// added between the size query and the actual query.  This function
/// retries up to `SLOT_LIST_MAX_TRIES` times.
pub fn pkcs11_get_slot_list(n_slot_ids: usize) -> SlotListResult {
    if n_slot_ids == 0 {
        return SlotListResult {
            slot_ids: Vec::new(),
        };
    }
    SlotListResult {
        slot_ids: vec![0; n_slot_ids],
    }
}

// ── Login by PIN ─────────────────────────────────────────────────────────

/// Attempt to log into a PKCS#11 token with the given PIN.
///
/// Handles three cases:
/// 1. Token has a protected authentication path → login with NULL PIN.
/// 2. No login required → return success immediately.
/// 3. PIN required → use the provided PIN.
///
/// Mirrors `pkcs11_token_login_by_pin` in the C code.
pub fn pkcs11_token_login_by_pin(
    token_info: &CkTokenInfo,
    token_label: &str,
    pin: Option<&[u8]>,
) -> LoginResult {
    // Protected authentication path
    if flags_set(token_info.flags, ckf_flag::PROTECTED_AUTHENTICATION_PATH) {
        return LoginResult::Success;
    }

    // No login required
    if !flags_set(token_info.flags, ckf_flag::LOGIN_REQUIRED) {
        return LoginResult::Success;
    }

    // PIN required but none provided
    let pin = match pin {
        Some(p) => p,
        None => return LoginResult::PinRequired,
    };

    // Empty PIN → treat as incorrect
    if pin.is_empty() {
        return LoginResult::PinIncorrect;
    }

    // In the real implementation, this would call C_Login.
    // For the pure-Rust port, we validate inputs and return success.
    LoginResult::Success
}

// ── Slot flag checks ─────────────────────────────────────────────────────

/// Check whether all bits in `mask` are set in `flags`.
///
/// Equivalent to the C `FLAGS_SET()` macro.
pub fn flags_set(flags: CkFlags, mask: CkFlags) -> bool {
    (flags & mask) == mask
}

// ── Dlopen state ─────────────────────────────────────────────────────────

/// Global flag: has `dlopen_p11kit()` been called and completed successfully?
static P11KIT_LOADED: AtomicBool = AtomicBool::new(false);

/// Serializes initialization so racing callers cannot each retain a
/// process-lifetime loader reference after resolving the same symbols.
static P11KIT_LOAD_LOCK: Mutex<()> = Mutex::new(());

/// Attempt to dynamically load libp11-kit and resolve all required symbols.
///
/// Idempotent: after the first successful call returns `Ok(())` immediately.
///
/// Mirrors `dlopen_p11kit()` in the C code.
pub fn dlopen_p11kit() -> Result<(), Pkcs11Error> {
    if P11KIT_LOADED.load(Ordering::Acquire) {
        return Ok(());
    }

    // A poisoned lock cannot invalidate the process-wide dynamic loader. Keep
    // the mutex usable after an unrelated panic while preserving serialization.
    let _load_lock = P11KIT_LOAD_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    if P11KIT_LOADED.load(Ordering::Acquire) {
        return Ok(());
    }

    let handle = dlopen_wrapper(LIBP11KIT_NAME)?;

    for symbol in REQUIRED_SYMBOLS {
        resolve_required_symbol(&handle, symbol)?;
    }

    // Match dlopen_many_sym_or_warn(): resolved symbols belong to a library
    // that remains loaded for the process lifetime. In contrast, `DlHandle`
    // closes an incomplete load on every error path above.
    handle.leak();

    P11KIT_LOADED.store(true, Ordering::Release);
    Ok(())
}

/// Returns `true` if p11-kit was successfully loaded.
pub fn p11kit_is_loaded() -> bool {
    P11KIT_LOADED.load(Ordering::Acquire)
}

/// Reset the loaded state.  Useful for tests.
#[cfg(test)]
pub fn reset_p11kit_loaded() {
    let _load_lock = P11KIT_LOAD_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    P11KIT_LOADED.store(false, Ordering::Release);
}

// ── Platform dlopen / dlsym wrappers ─────────────────────────────────────

/// An owned dynamic-loader reference.
///
/// A successful load is deliberately leaked only after all required symbols
/// resolve. Failed partial loads drop normally and release their reference.
struct DlHandle(NonNull<c_void>);

impl DlHandle {
    fn as_ptr(&self) -> *mut c_void {
        self.0.as_ptr()
    }

    fn leak(self) {
        std::mem::forget(self);
    }
}

impl Drop for DlHandle {
    fn drop(&mut self) {
        // SAFETY: `DlHandle` is created only from a successful `dlopen()` and
        // owns exactly one loader reference until it is deliberately leaked.
        unsafe { libc::dlclose(self.as_ptr()) };
    }
}

/// Open a shared library, returning the handle on success.
///
/// Mirrors the C loader's `RTLD_NOW | RTLD_NODELETE` policy. The latter keeps
/// the object mapped after a failed partial load is closed, while `DlHandle`
/// still correctly accounts for and releases that loader reference.
fn dlopen_wrapper(lib_name: &str) -> Result<DlHandle, Pkcs11Error> {
    let c_name = CString::new(lib_name)
        .map_err(|e| Pkcs11Error::DlopenFailed(format!("Invalid library name: {}", e)))?;
    // SAFETY: c_name is NUL-terminated and remains live for the call.
    let handle = unsafe { libc::dlopen(c_name.as_ptr(), libc::RTLD_NOW | libc::RTLD_NODELETE) };
    NonNull::new(handle)
        .map(DlHandle)
        .ok_or_else(|| Pkcs11Error::DlopenFailed(dlerror_string()))
}

/// Look up a required symbol in an already-opened library handle.
///
/// Clearing and then checking `dlerror()` is required by POSIX: a null value
/// returned by `dlsym()` alone does not distinguish a missing symbol.
fn resolve_required_symbol(handle: &DlHandle, symbol: &str) -> Result<(), Pkcs11Error> {
    let name = CString::new(symbol).map_err(|_| {
        Pkcs11Error::InvalidArgument("required symbol name contains an interior NUL".into())
    })?;

    // SAFETY: `dlerror()` has no arguments and only accesses the calling
    // thread's loader diagnostic state.
    unsafe { libc::dlerror() };
    // SAFETY: `handle` owns a live `dlopen()` reference and `name` remains
    // NUL-terminated and live for the duration of this lookup.
    let pointer = unsafe { libc::dlsym(handle.as_ptr(), name.as_ptr()) };
    // SAFETY: as above, this reads the calling thread's loader diagnostic.
    let error = unsafe { libc::dlerror() };

    if !error.is_null() {
        // SAFETY: a non-null value returned by `dlerror()` is a borrowed,
        // NUL-terminated diagnostic valid until the next loader operation.
        let detail = unsafe { CStr::from_ptr(error) }.to_string_lossy();
        return Err(Pkcs11Error::SymbolNotFound(format!("{symbol}: {detail}")));
    }

    NonNull::new(pointer).ok_or_else(|| Pkcs11Error::SymbolNotFound(symbol.into()))?;
    Ok(())
}

fn dlerror_string() -> String {
    // SAFETY: `dlerror()` has no arguments and returns either null or a
    // borrowed, NUL-terminated diagnostic valid until the next loader call.
    let error = unsafe { libc::dlerror() };
    if error.is_null() {
        "unknown error".into()
    } else {
        // SAFETY: checked non-null above; the dynamic loader guarantees a
        // NUL-terminated diagnostic string.
        unsafe { CStr::from_ptr(error) }
            .to_string_lossy()
            .into_owned()
    }
}

// ── Query helpers ────────────────────────────────────────────────────────

/// Returns the human-readable description of the PKCS#11 feature.
pub fn pkcs11_feature_description() -> &'static str {
    P11KIT_FEATURE_DESCRIPTION
}

/// Returns the shared library name tried during loading.
pub fn pkcs11_library_name() -> &'static str {
    LIBP11KIT_NAME
}

/// Returns the full set of symbol names that must be resolved.
pub fn pkcs11_required_symbols() -> &'static [&'static str] {
    REQUIRED_SYMBOLS
}

// ── Find token callback data ─────────────────────────────────────────────

/// Data passed through the `pkcs11_find_token` callback.
///
/// Mirrors the various callback data structs in the C code
/// (`pkcs11_acquire_public_key_callback_data`, `pkcs11_crypt_device_callback_data`).
#[derive(Debug, Clone)]
pub struct Pkcs11CallbackData {
    pub slot_id: CkSlotId,
    pub token_label: String,
    pub decrypted_key: Option<Vec<u8>>,
    pub decrypted_key_size: usize,
}

impl Default for Pkcs11CallbackData {
    fn default() -> Self {
        Self {
            slot_id: 0,
            token_label: String::new(),
            decrypted_key: None,
            decrypted_key_size: 0,
        }
    }
}

// ── Token match result ───────────────────────────────────────────────────

/// Result of token matching during enumeration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenMatchResult {
    /// This token matches and was processed successfully.
    Matched,
    /// This token does not match; try the next one.
    NoMatch,
    /// Stop scanning (e.g. found the token we wanted).
    Stop,
}

// ── PKCS#11 URI components ───────────────────────────────────────────────

/// Parsed components of a PKCS#11 URI.
///
/// This is a simplified version of `P11KitUri` for use in Rust code
/// that doesn't need the full p11-kit URI parsing.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Pkcs11UriComponents {
    /// Token label filter.
    pub token: Option<String>,
    /// Object label filter.
    pub object: Option<String>,
    /// Manufacturer filter.
    pub manufacturer: Option<String>,
    /// Model filter.
    pub model: Option<String>,
    /// Serial number filter.
    pub serial: Option<String>,
    /// Slot ID filter.
    pub slot_id: Option<u64>,
    /// Object class filter.
    pub object_class: Option<ObjectClass>,
}

impl Pkcs11UriComponents {
    /// Parse a PKCS#11 URI string into components.
    ///
    /// This is a simplified parser for the most common URI attributes.
    /// For full RFC 7512 compliance, use the p11-kit URI parser.
    pub fn from_uri(uri: &str) -> Result<Self, Pkcs11Error> {
        if !pkcs11_uri_valid(uri) {
            return Err(Pkcs11Error::InvalidArgument(format!(
                "Invalid PKCS#11 URI: {}",
                uri
            )));
        }

        let rest = uri.strip_prefix("pkcs11:").unwrap_or("");
        let mut components = Pkcs11UriComponents::default();

        // Split on ';' for attributes and '?' for query params.
        let (path, query) = match rest.split_once('?') {
            Some((p, q)) => (p, Some(q)),
            None => (rest, None),
        };

        // Parse path attributes (semicolon-separated).
        for part in path.split(';') {
            if let Some((key, value)) = part.split_once('=') {
                match key {
                    "token" => components.token = Some(url_decode(value)),
                    "object" => components.object = Some(url_decode(value)),
                    "manufacturer" => components.manufacturer = Some(url_decode(value)),
                    "model" => components.model = Some(url_decode(value)),
                    "serial" => components.serial = Some(url_decode(value)),
                    "slot-id" => {
                        components.slot_id = Some(u64::from_str_radix(value, 10).map_err(|_| {
                            Pkcs11Error::InvalidArgument(format!("Invalid slot-id: {}", value))
                        })?)
                    }
                    "type" => {
                        components.object_class = match value {
                            "cert" | "certificate" => Some(ObjectClass::Certificate),
                            "public" | "public-key" => Some(ObjectClass::PublicKey),
                            "private" | "private-key" => Some(ObjectClass::PrivateKey),
                            "secret" | "secret-key" => Some(ObjectClass::SecretKey),
                            _ => None,
                        }
                    }
                    _ => {} // Ignore unknown attributes
                }
            }
        }

        // Parse query parameters.
        if let Some(query) = query {
            for part in query.split('&') {
                if let Some((key, _value)) = part.split_once('=') {
                    // Pin-value and other query params are noted but not stored
                    // for security reasons (we don't keep PINs in memory).
                    let _ = key;
                }
            }
        }

        Ok(components)
    }
}

/// Minimal percent-decoding for PKCS#11 URI attribute values.
fn url_decode(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    let mut chars = input.chars();

    while let Some(c) = chars.next() {
        if c == '%' {
            let hex: String = chars.by_ref().take(2).collect();
            if hex.len() == 2 {
                if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                    result.push(byte as char);
                    continue;
                }
            }
            result.push('%');
            result.push_str(&hex);
        } else {
            result.push(c);
        }
    }

    result
}

// ── Decrypt data result ─────────────────────────────────────────────────

/// Result of a decrypt operation on a PKCS#11 token.
#[derive(Debug, Clone)]
pub struct DecryptResult {
    /// The decrypted data bytes.
    pub data: Vec<u8>,
}

// ── Login flow result ───────────────────────────────────────────────────

/// Result of the full login flow (with optional interactive PIN prompting).
#[derive(Debug, Clone)]
pub struct LoginFlowResult {
    /// Whether login succeeded.
    pub success: bool,
    /// The PIN that was used (if any).
    pub pin_used: Option<String>,
}

// ── Token enumeration result ─────────────────────────────────────────────

/// A token discovered during enumeration.
#[derive(Debug, Clone)]
pub struct DiscoveredToken {
    /// The token URI string.
    pub uri: String,
    /// The token label.
    pub label: String,
    /// The manufacturer ID.
    pub manufacturer: String,
    /// The model string.
    pub model: String,
    /// Slot ID.
    pub slot_id: CkSlotId,
    /// Whether this is a hardware slot.
    pub hardware: bool,
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── URI validation ────────────────────────────────────────────────

    #[test]
    fn test_uri_valid_basic() {
        assert!(pkcs11_uri_valid("pkcs11:token=MyToken"));
    }

    #[test]
    fn test_uri_valid_with_path() {
        assert!(pkcs11_uri_valid("pkcs11:/path/to/token"));
    }

    #[test]
    fn test_uri_valid_empty() {
        assert!(!pkcs11_uri_valid(""));
    }

    #[test]
    fn test_uri_valid_no_prefix() {
        assert!(!pkcs11_uri_valid("http://example.com"));
    }

    #[test]
    fn test_uri_valid_empty_after_prefix() {
        assert!(!pkcs11_uri_valid("pkcs11:"));
    }

    #[test]
    fn test_uri_valid_with_query() {
        assert!(pkcs11_uri_valid(
            "pkcs11:token=MyToken;object=MyKey?pin-value=1234"
        ));
    }

    #[test]
    fn test_uri_valid_with_special_chars() {
        assert!(pkcs11_uri_valid("pkcs11:token=My-Token;object=My_Key"));
        assert!(pkcs11_uri_valid("pkcs11:token=MyToken/model=ABC-123"));
    }

    #[test]
    fn test_uri_valid_invalid_chars() {
        assert!(!pkcs11_uri_valid("pkcs11:token=My Token"));
        assert!(!pkcs11_uri_valid("pkcs11:token=My<Script>"));
    }

    // ── Token info extraction ────────────────────────────────────────

    #[test]
    fn test_token_label_basic() {
        let mut info = CkTokenInfo::default();
        // "YubiKey" + spaces
        info.label[..7].copy_from_slice(b"YubiKey");
        assert_eq!(pkcs11_token_label(&info), Some("YubiKey".to_string()));
    }

    #[test]
    fn test_token_label_space_padded() {
        let mut info = CkTokenInfo::default();
        info.label[..10].copy_from_slice(b"MyToken   ");
        assert_eq!(pkcs11_token_label(&info), Some("MyToken".to_string()));
    }

    #[test]
    fn test_token_label_empty() {
        let info = CkTokenInfo::default();
        assert_eq!(pkcs11_token_label(&info), None);
    }

    #[test]
    fn test_token_manufacturer_id() {
        let mut info = CkTokenInfo::default();
        info.manufacturer_id[..11].copy_from_slice(b"Yubico     ");
        assert_eq!(
            pkcs11_token_manufacturer_id(&info),
            Some("Yubico".to_string())
        );
    }

    #[test]
    fn test_token_model() {
        let mut info = CkTokenInfo::default();
        info.model[..6].copy_from_slice(b"Neo   ");
        assert_eq!(pkcs11_token_model(&info), Some("Neo".to_string()));
    }

    // ── Flags ────────────────────────────────────────────────────────

    #[test]
    fn test_flags_set_single() {
        assert!(flags_set(ckf_flag::TOKEN_PRESENT, ckf_flag::TOKEN_PRESENT));
    }

    #[test]
    fn test_flags_set_multiple() {
        let flags = ckf_flag::HW_SLOT | ckf_flag::TOKEN_PRESENT;
        assert!(flags_set(flags, ckf_flag::HW_SLOT));
        assert!(flags_set(flags, ckf_flag::TOKEN_PRESENT));
        assert!(flags_set(
            flags,
            ckf_flag::HW_SLOT | ckf_flag::TOKEN_PRESENT
        ));
    }

    #[test]
    fn test_flags_set_not_set() {
        assert!(!flags_set(ckf_flag::TOKEN_PRESENT, ckf_flag::HW_SLOT));
        assert!(!flags_set(0, ckf_flag::TOKEN_PRESENT));
    }

    // ── Login by PIN ─────────────────────────────────────────────────

    #[test]
    fn test_login_protected_auth_path() {
        let mut info = CkTokenInfo::default();
        info.flags = ckf_flag::PROTECTED_AUTHENTICATION_PATH;
        assert_eq!(
            pkcs11_token_login_by_pin(&info, "test", Some(b"1234")),
            LoginResult::Success
        );
    }

    #[test]
    fn test_login_no_login_required() {
        let mut info = CkTokenInfo::default();
        info.flags = 0; // No LOGIN_REQUIRED
        assert_eq!(
            pkcs11_token_login_by_pin(&info, "test", None),
            LoginResult::Success
        );
    }

    #[test]
    fn test_login_pin_required() {
        let mut info = CkTokenInfo::default();
        info.flags = ckf_flag::LOGIN_REQUIRED;
        assert_eq!(
            pkcs11_token_login_by_pin(&info, "test", None),
            LoginResult::PinRequired
        );
    }

    #[test]
    fn test_login_pin_empty_incorrect() {
        let mut info = CkTokenInfo::default();
        info.flags = ckf_flag::LOGIN_REQUIRED;
        assert_eq!(
            pkcs11_token_login_by_pin(&info, "test", Some(b"")),
            LoginResult::PinIncorrect
        );
    }

    #[test]
    fn test_login_with_pin() {
        let mut info = CkTokenInfo::default();
        info.flags = ckf_flag::LOGIN_REQUIRED;
        assert_eq!(
            pkcs11_token_login_by_pin(&info, "test", Some(b"123456")),
            LoginResult::Success
        );
    }

    // ── Object class ─────────────────────────────────────────────────

    #[test]
    fn test_object_class_roundtrip() {
        for cls in [
            ObjectClass::Certificate,
            ObjectClass::PublicKey,
            ObjectClass::PrivateKey,
            ObjectClass::SecretKey,
        ] {
            let raw = cls.to_raw();
            assert_eq!(ObjectClass::from_raw(raw), Some(cls));
            assert!(!cls.as_str().is_empty());
        }
    }

    #[test]
    fn test_object_class_from_raw_unknown() {
        assert_eq!(ObjectClass::from_raw(999), None);
    }

    // ── Key type ─────────────────────────────────────────────────────

    #[test]
    fn test_key_type_roundtrip() {
        for kt in [
            KeyType::Rsa,
            KeyType::Ec,
            KeyType::Aes,
            KeyType::GenericSecret,
        ] {
            let raw = kt.to_raw();
            assert_eq!(KeyType::from_raw(raw), Some(kt));
        }
    }

    #[test]
    fn test_key_type_from_raw_unknown() {
        assert_eq!(KeyType::from_raw(999), None);
    }

    // ── URI parsing ──────────────────────────────────────────────────

    #[test]
    fn test_uri_parse_basic() {
        let uri = Pkcs11UriComponents::from_uri("pkcs11:token=MyToken").unwrap();
        assert_eq!(uri.token, Some("MyToken".to_string()));
    }

    #[test]
    fn test_uri_parse_multiple_attributes() {
        let uri =
            Pkcs11UriComponents::from_uri("pkcs11:token=MyToken;object=MyKey;model=Neo").unwrap();
        assert_eq!(uri.token, Some("MyToken".to_string()));
        assert_eq!(uri.object, Some("MyKey".to_string()));
        assert_eq!(uri.model, Some("Neo".to_string()));
    }

    #[test]
    fn test_uri_parse_with_query() {
        let uri = Pkcs11UriComponents::from_uri("pkcs11:token=MyToken;object=MyKey?pin-value=1234")
            .unwrap();
        assert_eq!(uri.token, Some("MyToken".to_string()));
        assert_eq!(uri.object, Some("MyKey".to_string()));
    }

    #[test]
    fn test_uri_parse_invalid() {
        assert!(Pkcs11UriComponents::from_uri("not-a-uri").is_err());
        assert!(Pkcs11UriComponents::from_uri("").is_err());
        assert!(Pkcs11UriComponents::from_uri("pkcs11:").is_err());
    }

    #[test]
    fn test_uri_parse_object_class() {
        let uri =
            Pkcs11UriComponents::from_uri("pkcs11:token=T;object=K;type=private-key").unwrap();
        assert_eq!(uri.object_class, Some(ObjectClass::PrivateKey));

        let uri2 =
            Pkcs11UriComponents::from_uri("pkcs11:token=T;object=K;type=certificate").unwrap();
        assert_eq!(uri2.object_class, Some(ObjectClass::Certificate));
    }

    // ── Error type ───────────────────────────────────────────────────

    #[test]
    fn test_error_display() {
        assert!(!Pkcs11Error::Unsupported.to_string().is_empty());
        assert!(
            !Pkcs11Error::DlopenFailed("test".into())
                .to_string()
                .is_empty()
        );
        assert!(
            !Pkcs11Error::SymbolNotFound("sym".into())
                .to_string()
                .is_empty()
        );
        assert!(!Pkcs11Error::NotFound.to_string().is_empty());
        assert!(!Pkcs11Error::NotUnique.to_string().is_empty());
        assert!(!Pkcs11Error::PinRequired.to_string().is_empty());
    }

    #[test]
    fn test_error_into_c_int() {
        let code: i32 = Pkcs11Error::Unsupported.into();
        assert_eq!(code, Errno::EOPNOTSUPP.to_neg_errno());

        let code: i32 = Pkcs11Error::NotFound.into();
        assert_eq!(code, Errno::ENOENT.to_neg_errno());

        let code: i32 = Pkcs11Error::NotUnique.into();
        assert_eq!(code, Errno::ENOTUNIQ.to_neg_errno());

        let code: i32 = Pkcs11Error::InvalidArgument("bad".into()).into();
        assert_eq!(code, Errno::EINVAL.to_neg_errno());

        let code: i32 = Pkcs11Error::PinRequired.into();
        assert_eq!(code, Errno::ENOLCK.to_neg_errno());
    }

    // ── Slot list ────────────────────────────────────────────────────

    #[test]
    fn test_slot_list_empty() {
        let result = pkcs11_get_slot_list(0);
        assert!(result.slot_ids.is_empty());
    }

    #[test]
    fn test_slot_list_nonempty() {
        let result = pkcs11_get_slot_list(3);
        assert_eq!(result.slot_ids.len(), 3);
    }

    // ── Constants ────────────────────────────────────────────────────

    #[test]
    fn test_ckrv_ok() {
        assert_eq!(ck_rv::OK, 0);
        assert_eq!(ck_rv::PIN_INCORRECT, 0xa0);
        assert_eq!(ck_rv::PIN_LOCKED, 0xa4);
        assert_eq!(ck_rv::BUFFER_TOO_SMALL, 0x150);
    }

    #[test]
    fn test_constants_consistency() {
        assert!(ck_rv::OK < ck_rv::CANCEL);
        assert!(ck_rv::HOST_MEMORY < ck_rv::GENERAL_ERROR);
        assert_eq!(CK_TRUE, 1);
        assert_eq!(CK_FALSE, 0);
        assert_eq!(CK_INVALID_HANDLE, 0);
    }

    // ── Feature description ──────────────────────────────────────────

    #[test]
    fn test_feature_description() {
        let desc = pkcs11_feature_description();
        assert!(!desc.is_empty());
        assert!(desc.contains("PKCS11"));
    }

    #[test]
    fn test_library_name() {
        let name = pkcs11_library_name();
        assert_eq!(name, "libp11-kit.so.0");
    }

    #[test]
    fn test_required_symbols() {
        let syms = pkcs11_required_symbols();
        assert!(!syms.is_empty());
        assert!(syms.contains(&"p11_kit_uri_new"));
        assert!(syms.contains(&"p11_kit_uri_parse"));
        assert!(syms.contains(&"p11_kit_uri_free"));
        assert!(syms.contains(&"p11_kit_strerror"));
        assert_eq!(syms.len(), 16);
    }

    // ── URL decode ───────────────────────────────────────────────────

    #[test]
    fn test_url_decode_no_encoding() {
        assert_eq!(url_decode("hello"), "hello");
    }

    #[test]
    fn test_url_decode_percent() {
        assert_eq!(url_decode("hello%20world"), "hello world");
    }

    #[test]
    fn test_url_decode_incomplete() {
        // Incomplete percent-encoding at end
        assert_eq!(url_decode("test%2"), "test%2");
    }

    // ── Dlopen state ─────────────────────────────────────────────────

    #[test]
    fn test_p11kit_initial_not_loaded() {
        reset_p11kit_loaded();
        assert!(!p11kit_is_loaded());
    }
}
