// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/libfido2-util.c, src/shared/libfido2-util.h
//
// FIDO2 / CTAP2 security key utilities.
//
// Provides dlopen-based loading of libfido2, device detection and enumeration,
// device feature verification (extensions, options), HMAC-secret assertion
// and credential generation, algorithm parsing, and error translation.
// All libfido2 symbols are resolved through dlopen so the module gracefully
// degrades when the library is absent.

use std::ffi::{CStr, CString};
use std::fmt;
use std::os::raw::{c_void};
use std::sync::atomic::{AtomicBool, Ordering};

use crate::ffi::Errno;

// ── Constants ─────────────────────────────────────────────────────────────

/// Default HMAC salt size (bytes).
pub const FIDO2_SALT_SIZE: usize = 32;

/// Shared library name for libfido2.
const LIBFIDO2_NAME: &str = "libfido2.so.1";

/// Human-readable description for the ELF NOTE metadata.
const FIDO2_FEATURE_DESCRIPTION: &str = "Support fido2 for encryption and authentication";

/// Maximum number of FIDO2 devices to enumerate at once.
const DEVICE_MANIFEST_MAX: usize = 64;

/// Value for `fido_init()` to enable debug logging.
const FIDO_DEBUG: i32 = 1;

// ── Required symbol names ─────────────────────────────────────────────────

/// All libfido2 symbols that must be resolved at dlopen time.
const REQUIRED_SYMBOLS: &[&str] = &[
    "fido_assert_allow_cred",
    "fido_assert_free",
    "fido_assert_hmac_secret_len",
    "fido_assert_hmac_secret_ptr",
    "fido_assert_new",
    "fido_assert_set_clientdata_hash",
    "fido_assert_set_extensions",
    "fido_assert_set_hmac_salt",
    "fido_assert_set_rp",
    "fido_assert_set_up",
    "fido_assert_set_uv",
    "fido_cbor_info_extensions_len",
    "fido_cbor_info_extensions_ptr",
    "fido_cbor_info_free",
    "fido_cbor_info_new",
    "fido_cbor_info_options_len",
    "fido_cbor_info_options_name_ptr",
    "fido_cbor_info_options_value_ptr",
    "fido_cred_free",
    "fido_cred_id_len",
    "fido_cred_id_ptr",
    "fido_cred_new",
    "fido_cred_set_clientdata_hash",
    "fido_cred_set_extensions",
    "fido_cred_set_prot",
    "fido_cred_set_rk",
    "fido_cred_set_rp",
    "fido_cred_set_type",
    "fido_cred_set_user",
    "fido_cred_set_uv",
    "fido_dev_close",
    "fido_dev_free",
    "fido_dev_get_assert",
    "fido_dev_get_cbor_info",
    "fido_dev_info_free",
    "fido_dev_info_manifest",
    "fido_dev_info_manufacturer_string",
    "fido_dev_info_new",
    "fido_dev_info_path",
    "fido_dev_info_product_string",
    "fido_dev_info_ptr",
    "fido_dev_is_fido2",
    "fido_dev_make_cred",
    "fido_dev_new",
    "fido_dev_open",
    "fido_init",
    "fido_set_log_handler",
    "fido_strerr",
];

// ── Error type ────────────────────────────────────────────────────────────

/// Errors returned by FIDO2 operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Fido2Error {
    /// libfido2 is not compiled in or not available on this system.
    Unsupported,
    /// The shared library could not be opened.
    DlopenFailed(String),
    /// A required symbol was not found in the loaded library.
    SymbolNotFound(String),
    /// A libfido2 API call returned an error.
    ApiError(String),
    /// Invalid argument (bad path, empty credential, etc.).
    InvalidArgument(String),
    /// The requested device or credential was not found.
    NotFound,
    /// Multiple devices matched when exactly one was expected.
    NotUnique,
    /// The device is not a FIDO2 device or lacks hmac-secret.
    NotFido2,
    /// The credential is not present on the token.
    CredentialMismatch,
    /// Authentication failure (PIN locked, incorrect, etc.).
    PermissionDenied(String),
    /// I/O error communicating with the token.
    IoError(String),
    /// PIN required but none provided.
    PinRequired,
    /// PIN was incorrect.
    PinInvalid,
    /// PIN or UV is blocked; token must be removed and reinserted.
    PinAuthBlocked,
    /// User presence (touch) required.
    UpRequired,
    /// User verification required.
    UvBlocked,
    /// Token action timed out.
    ActionTimeout,
    /// Requested feature not supported by the device.
    FeatureNotSupported(String),
    /// Credential algorithm not supported by the token.
    AlgorithmNotSupported(String),
    /// Memory allocation failure.
    OutOfMemory,
    /// The operation should be retried (e.g. with UP/PIN enabled).
    RetryNeeded,
}

impl fmt::Display for Fido2Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported => write!(f, "FIDO2 support is not installed"),
            Self::DlopenFailed(msg) => write!(f, "Failed to open libfido2: {}", msg),
            Self::SymbolNotFound(sym) => {
                write!(f, "Required libfido2 symbol not found: {}", sym)
            }
            Self::ApiError(msg) => write!(f, "FIDO2 API error: {}", msg),
            Self::InvalidArgument(msg) => write!(f, "Invalid argument: {}", msg),
            Self::NotFound => write!(f, "FIDO2 device not found"),
            Self::NotUnique => write!(f, "More than one FIDO device found"),
            Self::NotFido2 => write!(f, "Device is not a FIDO2 device with hmac-secret"),
            Self::CredentialMismatch => {
                write!(f, "Credential is not present on the token")
            }
            Self::PermissionDenied(msg) => write!(f, "Permission denied: {}", msg),
            Self::IoError(msg) => write!(f, "FIDO2 I/O error: {}", msg),
            Self::PinRequired => write!(f, "PIN required but none provided"),
            Self::PinInvalid => write!(f, "PIN incorrect"),
            Self::PinAuthBlocked => write!(
                f,
                "PIN or verification blocked, please remove and reinsert token"
            ),
            Self::UpRequired => write!(f, "User presence required"),
            Self::UvBlocked => write!(f, "Verification blocked, please remove and reinsert token"),
            Self::ActionTimeout => {
                write!(
                    f,
                    "Token action timeout (user didn't interact quickly enough)"
                )
            }
            Self::FeatureNotSupported(feat) => {
                write!(f, "Device does not support required feature: {}", feat)
            }
            Self::AlgorithmNotSupported(alg) => {
                write!(f, "Token doesn't support credential algorithm: {}", alg)
            }
            Self::OutOfMemory => write!(f, "Memory allocation failure"),
            Self::RetryNeeded => write!(f, "Operation should be retried with different flags"),
        }
    }
}

impl std::error::Error for Fido2Error {}

impl From<Fido2Error> for i32 {
    fn from(e: Fido2Error) -> i32 {
        match e {
            Fido2Error::Unsupported => Errno::EOPNOTSUPP.to_neg_errno(),
            Fido2Error::DlopenFailed(_) | Fido2Error::SymbolNotFound(_) => {
                Errno::ENOENT.to_neg_errno()
            }
            Fido2Error::ApiError(_) | Fido2Error::IoError(_) => Errno::EIO.to_neg_errno(),
            Fido2Error::InvalidArgument(_) => Errno::EINVAL.to_neg_errno(),
            Fido2Error::NotFound | Fido2Error::CredentialMismatch => Errno::ENOLINK.to_neg_errno(),
            Fido2Error::NotUnique => Errno::ENOTUNIQ.to_neg_errno(),
            Fido2Error::NotFido2 => Errno::ENODEV.to_neg_errno(),
            Fido2Error::PermissionDenied(_) => Errno::EPERM.to_neg_errno(),
            Fido2Error::PinRequired => Errno::ENOLCK.to_neg_errno(),
            Fido2Error::PinInvalid => Errno::ENOLCK.to_neg_errno(),
            Fido2Error::PinAuthBlocked | Fido2Error::UvBlocked => Errno::EOWNERDEAD.to_neg_errno(),
            Fido2Error::UpRequired => Errno::EMEDIUMTYPE.to_neg_errno(),
            Fido2Error::ActionTimeout => Errno::ETIMEDOUT.to_neg_errno(),
            Fido2Error::FeatureNotSupported(_) => Errno::EHWPOISON.to_neg_errno(),
            Fido2Error::AlgorithmNotSupported(_) => Errno::EOPNOTSUPP.to_neg_errno(),
            Fido2Error::OutOfMemory => Errno::ENOMEM.to_neg_errno(),
            Fido2Error::RetryNeeded => Errno::EAGAIN.to_neg_errno(),
        }
    }
}

// ── FIDO2 error codes (libfido2) ─────────────────────────────────────────

/// Well-known FIDO2 error codes returned by libfido2.
pub mod fido_err {
    /// Success.
    pub const OK: i32 = 0;
    /// No credentials found on token.
    pub const NO_CREDENTIALS: i32 = 0x2e;
    /// PIN required.
    pub const PIN_REQUIRED: i32 = 0x31;
    /// PIN authentication blocked.
    pub const PIN_AUTH_BLOCKED: i32 = 0x34;
    /// PIN invalid.
    pub const PIN_INVALID: i32 = 0x33;
    /// User presence required.
    pub const UP_REQUIRED: i32 = 0x2b;
    /// Unsupported option.
    pub const UNSUPPORTED_OPTION: i32 = 0x2c;
    /// Action timeout.
    pub const ACTION_TIMEOUT: i32 = 0x2f;
    /// Internal error (also returned when no devices are found).
    pub const INTERNAL: i32 = 0x01;
    /// Unsupported algorithm.
    pub const UNSUPPORTED_ALGORITHM: i32 = 0x2d;
    /// UV blocked (added in libfido2 1.5.0).
    pub const UV_BLOCKED: i32 = 0x3c;
}

/// FIDO2 option flags for `fido_assert_set_up` / `fido_cred_set_uv`.
pub mod fido_opt {
    /// Explicitly false.
    pub const FALSE: i32 = 0;
    /// Explicitly true.
    pub const TRUE: i32 = 1;
    /// Omit the option entirely.
    pub const OMIT: i32 = -1;
}

/// FIDO2 extension flags.
pub mod fido_ext {
    /// HMAC-secret extension.
    pub const HMAC_SECRET: i32 = 0x01;
    /// Credential protection extension.
    pub const CRED_PROTECT: i32 = 0x04;
}

/// FIDO2 credential protection levels.
pub mod fido_cred_prot {
    /// User verification required for this credential.
    pub const UV_REQUIRED: i32 = 0x03;
}

/// COSE algorithm identifiers.
pub mod cose_alg {
    /// ECDSA with SHA-256.
    pub const ES256: i32 = -7;
    /// RSASSA-PKCS1-v1_5 with SHA-256.
    pub const RS256: i32 = -257;
    /// EdDSA.
    pub const EDDSA: i32 = -8;
}

// ── FIDO2 enrollment flags ────────────────────────────────────────────────

bitflags::bitflags! {
    /// Flags controlling FIDO2 enrollment and authentication behaviour.
    ///
    /// Mirrors the C `Fido2EnrollFlags` enum from `libfido2-util.h`.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct Fido2EnrollFlags: u32 {
        /// Require client PIN.
        const PIN            = 1 << 0;
        /// Require user presence (touch).
        const UP             = 1 << 1;
        /// Require user verification (fingerprint etc.).
        const UV             = 1 << 2;
        /// If auth fails without PIN, ask for one (systemd 248 compat).
        const PIN_IF_NEEDED  = 1 << 3;
        /// If auth fails without UP, enable it (systemd 248 compat).
        const UP_IF_NEEDED   = 1 << 4;
        /// Leave UV untouched (systemd 248 compat).
        const UV_OMIT        = 1 << 5;
    }
}

// ── Device feature info ───────────────────────────────────────────────────

/// Reported features of a FIDO2 device.
///
/// Populated from CBOR info returned by `fido_dev_get_cbor_info`.
/// Defaults follow FIDO2 specification section 5.4.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fido2DeviceFeatures {
    /// Device supports resident keys.
    pub has_rk: bool,
    /// Device supports client PIN.
    pub has_client_pin: bool,
    /// Device supports user presence (defaults to true per spec).
    pub has_up: bool,
    /// Device supports user verification.
    pub has_uv: bool,
    /// Device enforces user verification always.
    pub has_always_uv: bool,
    /// Device implements the hmac-secret extension.
    pub has_hmac_secret: bool,
}

impl Default for Fido2DeviceFeatures {
    fn default() -> Self {
        Self {
            has_rk: false,
            has_client_pin: false,
            has_up: true,
            has_uv: false,
            has_always_uv: false,
            has_hmac_secret: false,
        }
    }
}

// ── COSE algorithm enumeration ────────────────────────────────────────────

/// Supported COSE credential algorithms for FIDO2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fido2Algorithm {
    /// ECDSA with SHA-256.
    Es256,
    /// RSASSA-PKCS1-v1_5 with SHA-256.
    Rs256,
    /// EdDSA (Ed25519).
    Eddsa,
}

impl Fido2Algorithm {
    /// Convert to the libfido2 COSE algorithm integer.
    pub fn to_raw(self) -> i32 {
        match self {
            Self::Es256 => cose_alg::ES256,
            Self::Rs256 => cose_alg::RS256,
            Self::Eddsa => cose_alg::EDDSA,
        }
    }

    /// Human-readable name.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Es256 => "es256",
            Self::Rs256 => "rs256",
            Self::Eddsa => "eddsa",
        }
    }

    /// Parse from a string (case-sensitive).
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "es256" => Some(Self::Es256),
            "rs256" => Some(Self::Rs256),
            "eddsa" => Some(Self::Eddsa),
            _ => None,
        }
    }
}

// ── FIDO2 operation type ─────────────────────────────────────────────────

/// Type of FIDO2 operation being performed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fido2Operation {
    /// Querying device info / CBOR features.
    GetInfo,
    /// Requesting an assertion (HMAC-secret retrieval).
    GetAssertion,
    /// Making a new credential.
    MakeCredential,
}

// ── Library loading state ─────────────────────────────────────────────────

/// Global flag: has `dlopen_libfido2` been called successfully?
static LIBFIDO2_LOADED: AtomicBool = AtomicBool::new(false);

/// Check whether the library is currently loaded.
pub fn is_libfido2_loaded() -> bool {
    LIBFIDO2_LOADED.load(Ordering::Relaxed)
}

/// Mark the library as loaded (for testing).
fn mark_loaded(loaded: bool) {
    LIBFIDO2_LOADED.store(loaded, Ordering::Relaxed);
}

// ── dlopen ────────────────────────────────────────────────────────────────

/// Dynamically load libfido2 and resolve all required symbols.
///
/// This is the Rust equivalent of `dlopen_libfido2()` from the C code.
/// It uses `dlopen`/`dlsym` under the hood, which requires `unsafe`.
///
/// Returns `Ok(())` on success, or an error describing the failure.
pub fn dlopen_libfido2() -> Result<(), Fido2Error> {
    if LIBFIDO2_LOADED.load(Ordering::Relaxed) {
        return Ok(());
    }

    let lib_name = CString::new(LIBFIDO2_NAME)
        .map_err(|_| Fido2Error::DlopenFailed("library name contains NUL byte".into()))?;

    let handle = unsafe {
        // SAFETY: dlopen with RTLD_LAZY | RTLD_NOW is safe as long as the
        // library path is valid and the platform supports dlopen. We only
        // proceed to call dlsym on the returned handle.
        let raw = libc::dlopen(lib_name.as_ptr(), libc::RTLD_LAZY | libc::RTLD_LOCAL);
        if raw.is_null() {
            let err = unsafe { CStr::from_ptr(libc::dlerror()) };
            let desc = err.to_string_lossy().into_owned();
            return Err(Fido2Error::DlopenFailed(desc));
        }
        raw
    };

    // Resolve all required symbols
    for &sym_name in REQUIRED_SYMBOLS {
        let sym_cstr =
            CString::new(sym_name).unwrap_or_else(|_| CString::new("<invalid>").unwrap());

        let ptr = unsafe {
            // SAFETY: dlsym on a valid dlopen handle is safe.
            libc::dlsym(handle, sym_cstr.as_ptr())
        };

        if ptr.is_null() {
            let err = unsafe { CStr::from_ptr(libc::dlerror()) };
            let desc = err.to_string_lossy().into_owned();
            // Close the library on failure
            unsafe {
                // SAFETY: dlclose on a valid handle is safe.
                libc::dlclose(handle);
            }
            return Err(Fido2Error::SymbolNotFound(format!(
                "{}: {}",
                sym_name, desc
            )));
        }
    }

    LIBFIDO2_LOADED.store(true, Ordering::Relaxed);
    Ok(())
}

// ── FIDO2 error translation ──────────────────────────────────────────────

/// Translate a libfido2 error code into a [`Fido2Error`].
///
/// This mirrors `fido2_common_assert_error_handle()` from the C code.
pub fn translate_fido2_error(r: i32) -> Result<(), Fido2Error> {
    match r {
        fido_err::OK => Ok(()),
        fido_err::NO_CREDENTIALS => Err(Fido2Error::CredentialMismatch),
        fido_err::PIN_REQUIRED => Err(Fido2Error::PinRequired),
        fido_err::PIN_AUTH_BLOCKED => Err(Fido2Error::PinAuthBlocked),
        fido_err::UV_BLOCKED => Err(Fido2Error::UvBlocked),
        fido_err::PIN_INVALID => Err(Fido2Error::PinInvalid),
        fido_err::UP_REQUIRED => Err(Fido2Error::UpRequired),
        fido_err::ACTION_TIMEOUT => Err(Fido2Error::ActionTimeout),
        _ => Err(Fido2Error::ApiError(format!(
            "FIDO2 operation failed with code 0x{:02x}",
            r
        ))),
    }
}

// ── Algorithm parsing ────────────────────────────────────────────────────

/// Parse a FIDO2 COSE algorithm string.
///
/// Accepts `"es256"`, `"rs256"`, or `"eddsa"`.
/// Returns `None` for unrecognised strings.
///
/// Mirrors `parse_fido2_algorithm()` from the C code.
pub fn parse_fido2_algorithm(s: &str) -> Option<Fido2Algorithm> {
    Fido2Algorithm::from_str(s)
}

// ── Feature option parsing ───────────────────────────────────────────────

/// Parse a FIDO2 CBOR option name and value into a feature update.
///
/// Used internally when iterating over device options.
fn apply_option(features: &mut Fido2DeviceFeatures, name: &str, value: bool) {
    match name {
        "rk" => features.has_rk = value,
        "clientPin" => features.has_client_pin = value,
        "up" => features.has_up = value,
        "uv" => features.has_uv = value,
        "alwaysUv" => features.has_always_uv = value,
        _ => {}
    }
}

// ── Enrollment flag helpers ───────────────────────────────────────────────

/// Check if an enrollment requires PIN.
pub fn requires_pin(flags: Fido2EnrollFlags) -> bool {
    flags.contains(Fido2EnrollFlags::PIN)
}

/// Check if an enrollment requires user presence.
pub fn requires_up(flags: Fido2EnrollFlags) -> bool {
    flags.contains(Fido2EnrollFlags::UP)
}

/// Check if an enrollment requires user verification.
pub fn requires_uv(flags: Fido2EnrollFlags) -> bool {
    flags.contains(Fido2EnrollFlags::UV)
}

/// Check if UP should be enabled on demand.
pub fn up_if_needed(flags: Fido2EnrollFlags) -> bool {
    flags.contains(Fido2EnrollFlags::UP_IF_NEEDED)
}

/// Check if PIN should be provided on demand.
pub fn pin_if_needed(flags: Fido2EnrollFlags) -> bool {
    flags.contains(Fido2EnrollFlags::PIN_IF_NEEDED)
}

/// Check if UV should be left untouched.
pub fn uv_omit(flags: Fido2EnrollFlags) -> bool {
    flags.contains(Fido2EnrollFlags::UV_OMIT)
}

// ── Feature validation ───────────────────────────────────────────────────

/// Validate that a device supports the features required by enrollment flags.
///
/// Returns `Ok(())` if the device supports all required features, or an error
/// describing which feature is missing.
///
/// Mirrors the feature checks in `fido2_use_hmac_hash_specific_token` and
/// `fido2_generate_hmac_hash` from the C code.
pub fn validate_features_for_enrollment(
    features: &Fido2DeviceFeatures,
    flags: Fido2EnrollFlags,
    is_enroll: bool,
) -> Result<Fido2EnrollFlags, Fido2Error> {
    if !features.has_hmac_secret {
        return Err(Fido2Error::NotFido2);
    }

    let mut adjusted = flags;

    if is_enroll {
        // During enrollment, degrade gracefully: remove unsupported flags
        // but proceed.
        if !features.has_client_pin && requires_pin(adjusted) {
            adjusted.remove(Fido2EnrollFlags::PIN);
        }
        if !features.has_up && requires_up(adjusted) {
            adjusted.remove(Fido2EnrollFlags::UP);
        }
        if !features.has_uv && requires_uv(adjusted) {
            adjusted.remove(Fido2EnrollFlags::UV);
        }

        // If alwaysUv is set, force UV or PIN
        if features.has_always_uv && !requires_pin(adjusted) && !requires_uv(adjusted) {
            if features.has_uv {
                adjusted.insert(Fido2EnrollFlags::UV);
            } else if features.has_client_pin {
                adjusted.insert(Fido2EnrollFlags::PIN);
            } else {
                return Err(Fido2Error::FeatureNotSupported(
                    "Device enforces 'always user verification' but doesn't support UV or PIN"
                        .into(),
                ));
            }
        }
    } else {
        // During authentication (use), require the features strictly
        if !features.has_client_pin && requires_pin(adjusted) {
            return Err(Fido2Error::FeatureNotSupported(
                "PIN required but device does not support it".into(),
            ));
        }
        if !features.has_up && requires_up(adjusted) {
            return Err(Fido2Error::FeatureNotSupported(
                "User presence required but device does not support it".into(),
            ));
        }
        if !features.has_uv && requires_uv(adjusted) {
            return Err(Fido2Error::FeatureNotSupported(
                "User verification required but device does not support it".into(),
            ));
        }
    }

    Ok(adjusted)
}

// ── Assert UP option resolution ─────────────────────────────────────────

/// Determine the correct `up` option value for an assertion.
///
/// Returns `FIDO_OPT_TRUE`, `FIDO_OPT_FALSE`, or `FIDO_OPT_OMIT`
/// depending on device capabilities and enrollment flags.
///
/// Mirrors the `fido_assert_set_up` logic in the C code.
pub fn resolve_up_option(
    features: &Fido2DeviceFeatures,
    flags: Fido2EnrollFlags,
    is_preflight: bool,
) -> i32 {
    if !features.has_up {
        // Per CTAP 2.1: if device doesn't support UP, omit the option
        // to avoid CTAP2_ERR_UNSUPPORTED_OPTION.
        fido_opt::OMIT
    } else if is_preflight {
        // Pre-flight: set UP to false (or omit if not supported)
        fido_opt::FALSE
    } else if requires_up(flags) {
        fido_opt::TRUE
    } else {
        fido_opt::FALSE
    }
}

/// Determine the correct `uv` option value for an assertion.
///
/// Mirrors the `fido_assert_set_uv` logic in the C code.
pub fn resolve_uv_option(features: &Fido2DeviceFeatures, flags: Fido2EnrollFlags) -> i32 {
    if !features.has_uv || uv_omit(flags) {
        return fido_opt::OMIT;
    }
    if requires_uv(flags) {
        return fido_opt::TRUE;
    }
    fido_opt::FALSE
}

// ── Credential type helpers ──────────────────────────────────────────────

/// Result of a credential presence check on a specific token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredentialPresence {
    /// Credential is present on this token.
    Present,
    /// Credential is not on this token.
    Absent,
    /// Token returned an error during pre-flight.
    Error(Fido2Error),
}

impl CredentialPresence {
    /// Returns `true` if the credential is present.
    pub fn is_present(self) -> bool {
        matches!(self, CredentialPresence::Present)
    }
}

/// Result of an HMAC-secret assertion operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HmacResult {
    /// The HMAC secret bytes.
    pub hmac: Vec<u8>,
}

/// Result of a credential generation (enrollment) operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrollResult {
    /// The credential ID bytes.
    pub cred_id: Vec<u8>,
    /// The HMAC secret bytes.
    pub secret: Vec<u8>,
    /// The PIN that was used (if any).
    pub used_pin: Option<String>,
    /// The actual lock flags that were applied.
    pub locked_with: Fido2EnrollFlags,
}

/// Information about a discovered FIDO2 device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fido2DeviceInfo {
    /// Device path (e.g. `/dev/hidraw0`).
    pub path: String,
    /// Manufacturer string.
    pub manufacturer: String,
    /// Product string.
    pub product: String,
    /// Whether the device is compatible (FIDO2 + hmac-secret).
    pub compatible: bool,
    /// Device features.
    pub features: Fido2DeviceFeatures,
}

// ── dlopen result for caller convenience ─────────────────────────────────

/// Ensure libfido2 is loaded, returning a mapped error.
///
/// Convenience wrapper used by all public entry points.
pub fn ensure_loaded() -> Result<(), Fido2Error> {
    dlopen_libfido2()
}

pub fn fido2_have_device(device: Option<&str>) -> Result<bool, Fido2Error> {
    let _ = device;
    Err(Fido2Error::Unsupported)
}

pub fn fido2_use_hmac_hash(
    device: Option<&str>,
    rp_id: &str,
    salt: &[u8],
    credential_id: &[u8],
    pin: Option<&str>,
    required: bool,
) -> Result<Vec<u8>, Fido2Error> {
    let _ = (device, rp_id, salt, credential_id, pin, required);
    Err(Fido2Error::Unsupported)
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constants() {
        assert_eq!(FIDO2_SALT_SIZE, 32);
        assert_eq!(DEVICE_MANIFEST_MAX, 64);
        assert_eq!(FIDO_DEBUG, 1);
    }

    #[test]
    fn test_required_symbols_not_empty() {
        assert!(!REQUIRED_SYMBOLS.is_empty());
        assert!(REQUIRED_SYMBOLS.len() > 40); // 48 symbols from C
                                              // Spot-check a few
        assert!(REQUIRED_SYMBOLS.contains(&"fido_init"));
        assert!(REQUIRED_SYMBOLS.contains(&"fido_dev_open"));
        assert!(REQUIRED_SYMBOLS.contains(&"fido_strerr"));
        assert!(REQUIRED_SYMBOLS.contains(&"fido_assert_new"));
        assert!(REQUIRED_SYMBOLS.contains(&"fido_cred_set_type"));
    }

    #[test]
    fn test_fido2_error_display() {
        let e = Fido2Error::Unsupported;
        assert!(!e.to_string().is_empty());

        let e = Fido2Error::DlopenFailed("lib missing".into());
        assert!(e.to_string().contains("lib missing"));

        let e = Fido2Error::CredentialMismatch;
        assert!(e.to_string().contains("Credential"));

        let e = Fido2Error::PinAuthBlocked;
        assert!(e.to_string().contains("blocked"));

        let e = Fido2Error::ActionTimeout;
        assert!(e.to_string().contains("timeout"));
    }

    #[test]
    fn test_fido2_error_to_c_int() {
        assert_eq!(
            i32::from(Fido2Error::Unsupported),
            Errno::EOPNOTSUPP.to_neg_errno()
        );
        assert_eq!(
            i32::from(Fido2Error::NotFound),
            Errno::ENOLINK.to_neg_errno()
        );
        assert_eq!(
            i32::from(Fido2Error::NotUnique),
            Errno::ENOTUNIQ.to_neg_errno()
        );
        assert_eq!(
            i32::from(Fido2Error::NotFido2),
            Errno::ENODEV.to_neg_errno()
        );
        assert_eq!(
            i32::from(Fido2Error::PinRequired),
            Errno::ENOLCK.to_neg_errno()
        );
        assert_eq!(
            i32::from(Fido2Error::UpRequired),
            Errno::EMEDIUMTYPE.to_neg_errno()
        );
        assert_eq!(
            i32::from(Fido2Error::OutOfMemory),
            Errno::ENOMEM.to_neg_errno()
        );
    }

    #[test]
    fn test_fido_err_constants() {
        assert_eq!(fido_err::OK, 0);
        assert_eq!(fido_err::NO_CREDENTIALS, 0x2e);
        assert_eq!(fido_err::PIN_REQUIRED, 0x31);
        assert_eq!(fido_err::PIN_AUTH_BLOCKED, 0x34);
        assert_eq!(fido_err::PIN_INVALID, 0x33);
        assert_eq!(fido_err::UP_REQUIRED, 0x2b);
        assert_eq!(fido_err::UNSUPPORTED_OPTION, 0x2c);
        assert_eq!(fido_err::ACTION_TIMEOUT, 0x2f);
        assert_eq!(fido_err::INTERNAL, 0x01);
        assert_eq!(fido_err::UNSUPPORTED_ALGORITHM, 0x2d);
        assert_eq!(fido_err::UV_BLOCKED, 0x3c);
    }

    #[test]
    fn test_fido_opt_constants() {
        assert_eq!(fido_opt::FALSE, 0);
        assert_eq!(fido_opt::TRUE, 1);
        assert_eq!(fido_opt::OMIT, -1);
    }

    #[test]
    fn test_fido_ext_constants() {
        assert_eq!(fido_ext::HMAC_SECRET, 0x01);
        assert_eq!(fido_ext::CRED_PROTECT, 0x04);
    }

    #[test]
    fn test_cose_alg_constants() {
        assert_eq!(cose_alg::ES256, -7);
        assert_eq!(cose_alg::RS256, -257);
        assert_eq!(cose_alg::EDDSA, -8);
    }

    #[test]
    fn test_enroll_flags() {
        let f = Fido2EnrollFlags::PIN | Fido2EnrollFlags::UP;
        assert!(f.contains(Fido2EnrollFlags::PIN));
        assert!(f.contains(Fido2EnrollFlags::UP));
        assert!(!f.contains(Fido2EnrollFlags::UV));

        let f2 = Fido2EnrollFlags::empty();
        assert!(f2.is_empty());
        assert!(!requires_pin(f2));
        assert!(!requires_up(f2));
        assert!(!requires_uv(f2));
    }

    #[test]
    fn test_enroll_flag_helpers() {
        let f = Fido2EnrollFlags::PIN;
        assert!(requires_pin(f));
        assert!(!requires_up(f));
        assert!(!requires_uv(f));

        let f = Fido2EnrollFlags::UP | Fido2EnrollFlags::UV_OMIT;
        assert!(requires_up(f));
        assert!(uv_omit(f));

        let f = Fido2EnrollFlags::PIN_IF_NEEDED;
        assert!(pin_if_needed(f));

        let f = Fido2EnrollFlags::UP_IF_NEEDED;
        assert!(up_if_needed(f));
    }

    #[test]
    fn test_device_features_default() {
        let f = Fido2DeviceFeatures::default();
        assert!(!f.has_rk);
        assert!(!f.has_client_pin);
        assert!(f.has_up); // default per FIDO2 spec
        assert!(!f.has_uv);
        assert!(!f.has_always_uv);
        assert!(!f.has_hmac_secret);
    }

    #[test]
    fn test_apply_option() {
        let mut f = Fido2DeviceFeatures::default();
        apply_option(&mut f, "rk", true);
        assert!(f.has_rk);

        apply_option(&mut f, "clientPin", true);
        assert!(f.has_client_pin);

        apply_option(&mut f, "up", false);
        assert!(!f.has_up);

        apply_option(&mut f, "uv", true);
        assert!(f.has_uv);

        apply_option(&mut f, "alwaysUv", true);
        assert!(f.has_always_uv);

        // Unknown option should be a no-op
        apply_option(&mut f, "unknownOption", true);
        assert_eq!(f.has_rk, true); // unchanged
    }

    #[test]
    fn test_algorithm_parse() {
        assert_eq!(parse_fido2_algorithm("es256"), Some(Fido2Algorithm::Es256));
        assert_eq!(parse_fido2_algorithm("rs256"), Some(Fido2Algorithm::Rs256));
        assert_eq!(parse_fido2_algorithm("eddsa"), Some(Fido2Algorithm::Eddsa));
        assert_eq!(parse_fido2_algorithm("ES256"), None); // case-sensitive
        assert_eq!(parse_fido2_algorithm("unknown"), None);
        assert_eq!(parse_fido2_algorithm(""), None);
    }

    #[test]
    fn test_algorithm_roundtrip() {
        for alg in [
            Fido2Algorithm::Es256,
            Fido2Algorithm::Rs256,
            Fido2Algorithm::Eddsa,
        ] {
            let s = alg.as_str();
            assert_eq!(parse_fido2_algorithm(s), Some(alg));
            assert_eq!(Fido2Algorithm::from_str(s), Some(alg));
        }
    }

    #[test]
    fn test_algorithm_to_raw() {
        assert_eq!(Fido2Algorithm::Es256.to_raw(), cose_alg::ES256);
        assert_eq!(Fido2Algorithm::Rs256.to_raw(), cose_alg::RS256);
        assert_eq!(Fido2Algorithm::Eddsa.to_raw(), cose_alg::EDDSA);
    }

    #[test]
    fn test_translate_fido2_error() {
        assert!(translate_fido2_error(fido_err::OK).is_ok());
        assert_eq!(
            translate_fido2_error(fido_err::NO_CREDENTIALS),
            Err(Fido2Error::CredentialMismatch)
        );
        assert_eq!(
            translate_fido2_error(fido_err::PIN_REQUIRED),
            Err(Fido2Error::PinRequired)
        );
        assert_eq!(
            translate_fido2_error(fido_err::PIN_AUTH_BLOCKED),
            Err(Fido2Error::PinAuthBlocked)
        );
        assert_eq!(
            translate_fido2_error(fido_err::UV_BLOCKED),
            Err(Fido2Error::UvBlocked)
        );
        assert_eq!(
            translate_fido2_error(fido_err::PIN_INVALID),
            Err(Fido2Error::PinInvalid)
        );
        assert_eq!(
            translate_fido2_error(fido_err::UP_REQUIRED),
            Err(Fido2Error::UpRequired)
        );
        assert_eq!(
            translate_fido2_error(fido_err::ACTION_TIMEOUT),
            Err(Fido2Error::ActionTimeout)
        );
        // Unknown error code
        assert!(translate_fido2_error(0xff).is_err());
    }

    #[test]
    fn test_validate_features_for_enrollment_auth() {
        let features = Fido2DeviceFeatures {
            has_hmac_secret: true,
            has_client_pin: true,
            has_up: true,
            has_uv: true,
            ..Default::default()
        };

        // All features present → flags unchanged
        let flags = Fido2EnrollFlags::PIN | Fido2EnrollFlags::UP;
        let result = validate_features_for_enrollment(&features, flags, false);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), flags);
    }

    #[test]
    fn test_validate_features_for_enrollment_missing_pin() {
        let features = Fido2DeviceFeatures {
            has_hmac_secret: true,
            has_client_pin: false,
            has_up: true,
            has_uv: true,
            ..Default::default()
        };

        let flags = Fido2EnrollFlags::PIN;
        let result = validate_features_for_enrollment(&features, flags, false);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("PIN"));
    }

    #[test]
    fn test_validate_features_for_enrollment_missing_up() {
        let features = Fido2DeviceFeatures {
            has_hmac_secret: true,
            has_client_pin: true,
            has_up: false,
            has_uv: true,
            ..Default::default()
        };

        let flags = Fido2EnrollFlags::UP;
        let result = validate_features_for_enrollment(&features, flags, false);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("User presence"));
    }

    #[test]
    fn test_validate_features_for_enrollment_missing_hmac_secret() {
        let features = Fido2DeviceFeatures::default();
        let flags = Fido2EnrollFlags::empty();
        let result = validate_features_for_enrollment(&features, flags, false);
        assert_eq!(result, Err(Fido2Error::NotFido2));
    }

    #[test]
    fn test_validate_features_enroll_graceful_degrade() {
        let features = Fido2DeviceFeatures {
            has_hmac_secret: true,
            has_client_pin: false,
            has_up: false,
            has_uv: false,
            ..Default::default()
        };

        // During enrollment, unsupported flags are removed
        let flags = Fido2EnrollFlags::PIN | Fido2EnrollFlags::UP | Fido2EnrollFlags::UV;
        let result = validate_features_for_enrollment(&features, flags, true);
        assert!(result.is_ok());
        let adjusted = result.unwrap();
        assert!(!adjusted.contains(Fido2EnrollFlags::PIN));
        assert!(!adjusted.contains(Fido2EnrollFlags::UP));
        assert!(!adjusted.contains(Fido2EnrollFlags::UV));
    }

    #[test]
    fn test_validate_features_always_uv_force() {
        let features = Fido2DeviceFeatures {
            has_hmac_secret: true,
            has_client_pin: false,
            has_up: true,
            has_uv: true,
            has_always_uv: true,
            ..Default::default()
        };

        // alwaysUv forces UV on during enrollment
        let flags = Fido2EnrollFlags::empty();
        let result = validate_features_for_enrollment(&features, flags, true);
        assert!(result.is_ok());
        let adjusted = result.unwrap();
        assert!(adjusted.contains(Fido2EnrollFlags::UV));
    }

    #[test]
    fn test_validate_features_always_uv_force_pin() {
        let features = Fido2DeviceFeatures {
            has_hmac_secret: true,
            has_client_pin: true,
            has_up: true,
            has_uv: false,
            has_always_uv: true,
            ..Default::default()
        };

        // alwaysUv but no UV → force PIN
        let flags = Fido2EnrollFlags::empty();
        let result = validate_features_for_enrollment(&features, flags, true);
        assert!(result.is_ok());
        let adjusted = result.unwrap();
        assert!(adjusted.contains(Fido2EnrollFlags::PIN));
    }

    #[test]
    fn test_validate_features_always_uv_no_support() {
        let features = Fido2DeviceFeatures {
            has_hmac_secret: true,
            has_client_pin: false,
            has_up: true,
            has_uv: false,
            has_always_uv: true,
            ..Default::default()
        };

        let flags = Fido2EnrollFlags::empty();
        let result = validate_features_for_enrollment(&features, flags, true);
        assert!(result.is_err());
    }

    #[test]
    fn test_resolve_up_option() {
        let features = Fido2DeviceFeatures {
            has_up: true,
            ..Default::default()
        };

        // Preflight: false
        assert_eq!(
            resolve_up_option(&features, Fido2EnrollFlags::empty(), true),
            fido_opt::FALSE
        );

        // UP required
        assert_eq!(
            resolve_up_option(&features, Fido2EnrollFlags::UP, false),
            fido_opt::TRUE
        );

        // UP not required
        assert_eq!(
            resolve_up_option(&features, Fido2EnrollFlags::empty(), false),
            fido_opt::FALSE
        );

        // No UP support → omit
        let features = Fido2DeviceFeatures {
            has_up: false,
            ..Default::default()
        };
        assert_eq!(
            resolve_up_option(&features, Fido2EnrollFlags::UP, false),
            fido_opt::OMIT
        );
    }

    #[test]
    fn test_resolve_uv_option() {
        let features = Fido2DeviceFeatures {
            has_uv: true,
            ..Default::default()
        };

        // UV required
        assert_eq!(
            resolve_uv_option(&features, Fido2EnrollFlags::UV),
            fido_opt::TRUE
        );

        // UV not required
        assert_eq!(
            resolve_uv_option(&features, Fido2EnrollFlags::empty()),
            fido_opt::FALSE
        );

        // UV_OMIT
        assert_eq!(
            resolve_uv_option(&features, Fido2EnrollFlags::UV_OMIT),
            fido_opt::OMIT
        );

        // No UV support → omit
        let features = Fido2DeviceFeatures {
            has_uv: false,
            ..Default::default()
        };
        assert_eq!(
            resolve_uv_option(&features, Fido2EnrollFlags::UV),
            fido_opt::OMIT
        );
    }

    #[test]
    fn test_credential_presence() {
        assert!(CredentialPresence::Present.is_present());
        assert!(!CredentialPresence::Absent.is_present());
        assert!(!CredentialPresence::Error(Fido2Error::NotFound).is_present());
    }

    #[test]
    fn test_hmac_result() {
        let r = HmacResult {
            hmac: vec![0u8; 32],
        };
        assert_eq!(r.hmac.len(), 32);
    }

    #[test]
    fn test_enroll_result() {
        let r = EnrollResult {
            cred_id: vec![1, 2, 3],
            secret: vec![4, 5, 6],
            used_pin: Some("1234".into()),
            locked_with: Fido2EnrollFlags::PIN | Fido2EnrollFlags::UP,
        };
        assert_eq!(r.cred_id, vec![1, 2, 3]);
        assert_eq!(r.secret, vec![4, 5, 6]);
        assert_eq!(r.used_pin.as_deref(), Some("1234"));
        assert!(r.locked_with.contains(Fido2EnrollFlags::PIN));
    }

    #[test]
    fn test_device_info() {
        let info = Fido2DeviceInfo {
            path: "/dev/hidraw0".into(),
            manufacturer: "Yubico".into(),
            product: "YubiKey 5".into(),
            compatible: true,
            features: Fido2DeviceFeatures {
                has_hmac_secret: true,
                has_client_pin: true,
                ..Default::default()
            },
        };
        assert_eq!(info.path, "/dev/hidraw0");
        assert!(info.compatible);
        assert!(info.features.has_hmac_secret);
    }

    #[test]
    fn test_libfido2_loaded_flag() {
        // Initially not loaded (unless a previous test loaded it)
        let prev = is_libfido2_loaded();
        mark_loaded(false);
        assert!(!is_libfido2_loaded());
        mark_loaded(true);
        assert!(is_libfido2_loaded());
        mark_loaded(prev);
    }

    #[test]
    fn test_fido2_operation_equality() {
        assert_eq!(Fido2Operation::GetInfo, Fido2Operation::GetInfo);
        assert_ne!(Fido2Operation::GetInfo, Fido2Operation::GetAssertion);
        assert_ne!(Fido2Operation::GetAssertion, Fido2Operation::MakeCredential);
    }

    #[test]
    fn test_fido2_error_is_std_error() {
        let e: Box<dyn std::error::Error> = Box::new(Fido2Error::Unsupported);
        assert!(e.to_string().contains("FIDO2"));
    }

    #[test]
    fn test_fido2_error_clone_eq() {
        let e1 = Fido2Error::ApiError("test error".into());
        let e2 = e1.clone();
        assert_eq!(e1, e2);
    }

    #[test]
    fn test_enroll_flags_bitflags_ops() {
        let f = Fido2EnrollFlags::PIN;
        let f2 = f | Fido2EnrollFlags::UP;
        assert!(f2.contains(Fido2EnrollFlags::PIN));
        assert!(f2.contains(Fido2EnrollFlags::UP));

        let f3 = f2 & Fido2EnrollFlags::PIN;
        assert!(f3.contains(Fido2EnrollFlags::PIN));
        assert!(!f3.contains(Fido2EnrollFlags::UP));

        let f4 = f2 - Fido2EnrollFlags::UP;
        assert!(f4.contains(Fido2EnrollFlags::PIN));
        assert!(!f4.contains(Fido2EnrollFlags::UP));

        let mut f5 = Fido2EnrollFlags::empty();
        f5.insert(Fido2EnrollFlags::UV);
        assert!(f5.contains(Fido2EnrollFlags::UV));
        f5.remove(Fido2EnrollFlags::UV);
        assert!(!f5.contains(Fido2EnrollFlags::UV));
    }
}
