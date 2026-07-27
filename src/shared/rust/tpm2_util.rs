// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/tpm2-util.c, src/shared/tpm2-util.h
//
// TPM2 utility functions — algorithm identifiers, PCR constants,
// vendor info, support detection, hash sizing, and string conversions.
//
// This module provides the pure-data / stateless portions of the TPM2
// utility layer.  Anything requiring a live TPM context (Esys calls,
// dlopen of libtss2, etc.) lives in C and is accessed through the
// Tpm2Context / Tpm2Handle abstractions defined in tpm2-util.h.

use crate::ffi::Errno;

// ── Error type ────────────────────────────────────────────────────────────

/// Errors returned by TPM2 utility functions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tpm2Error {
    /// Invalid argument or value.
    InvalidArgument,
    /// Operation not supported by this TPM.
    NotSupported,
    /// A required resource was not found.
    NotFound,
    /// I/O or lower-level failure.
    Io,
    /// Out of memory.
    OutOfMemory,
    /// Underlying TPM2 error code.
    Tpm2Error(u32),
}

impl std::fmt::Display for Tpm2Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidArgument => write!(f, "invalid argument"),
            Self::NotSupported => write!(f, "not supported"),
            Self::NotFound => write!(f, "not found"),
            Self::Io => write!(f, "I/O error"),
            Self::OutOfMemory => write!(f, "out of memory"),
            Self::Tpm2Error(rc) => write!(f, "TPM2 error 0x{rc:08X}"),
        }
    }
}

impl std::error::Error for Tpm2Error {}

impl From<Errno> for Tpm2Error {
    fn from(e: Errno) -> Self {
        match e {
            Errno::EINVAL | Errno::ENOLINK => Tpm2Error::InvalidArgument,
            Errno::EOPNOTSUPP => Tpm2Error::NotSupported,
            Errno::ENOENT | Errno::ENXIO => Tpm2Error::NotFound,
            Errno::ENOMEM => Tpm2Error::OutOfMemory,
            Errno::EIO => Tpm2Error::Io,
            _ => Tpm2Error::Io,
        }
    }
}

// ── TPM2 Algorithm Constants ─────────────────────────────────────────────

// Asymmetric algorithms
pub const TPM2_ALG_RSA: u16 = 0x0001;
pub const TPM2_ALG_ECC: u16 = 0x0023;

// Symmetric algorithms
pub const TPM2_ALG_AES: u16 = 0x0006;
pub const TPM2_ALG_OAES: u16 = 0x003F;
pub const TPM2_ALG_XOR: u16 = 0x000A;
pub const TPM2_ALG_SM4: u16 = 0x0013;
pub const TPM2_ALG_CAMELLIA: u16 = 0x0026;
pub const TPM2_ALG_KEYEDHASH: u16 = 0x0008;

// Symmetric modes
pub const TPM2_ALG_CTR: u16 = 0x0040;
pub const TPM2_ALG_OFB: u16 = 0x0041;
pub const TPM2_ALG_CBC: u16 = 0x0042;
pub const TPM2_ALG_CFB: u16 = 0x0043;
pub const TPM2_ALG_ECB: u16 = 0x0044;

// Hash algorithms
pub const TPM2_ALG_SHA1: u16 = 0x0004;
pub const TPM2_ALG_SHA256: u16 = 0x000B;
pub const TPM2_ALG_SHA384: u16 = 0x000C;
pub const TPM2_ALG_SHA512: u16 = 0x000D;
pub const TPM2_ALG_SM3_256: u16 = 0x0012;
pub const TPM2_ALG_NULL: u16 = 0x0010;

// ECC curves
pub const TPM2_ECC_NIST_P256: u16 = 0x0003;
pub const TPM2_ECC_NIST_P384: u16 = 0x0004;
pub const TPM2_ECC_NIST_P521: u16 = 0x0005;

// Startup type
pub const TPM2_SU_CLEAR: u16 = 0x0000;
pub const TPM2_SU_STATE: u16 = 0x0001;

// Session types
pub const TPM2_SE_HMAC: u8 = 0x00;
pub const TPM2_SE_POLICY: u8 = 0x01;
pub const TPM2_SE_TRIAL: u8 = 0x03;

// Structure tags
pub const TPM2_ST_NO_SESSIONS: u16 = 0x8001;
pub const TPM2_ST_SESSIONS: u16 = 0x8002;

// Response codes
pub const TPM2_RC_SUCCESS: u32 = 0x0000;
pub const TPM2_RC_BAD_TAG: u32 = 0x001E;
pub const TPM2_RC_INITIALIZE: u32 = 0x0100;
pub const TPM2_RC_VALUE: u32 = 0x009B;

// ── PCR constants ────────────────────────────────────────────────────────

/// Maximum number of PCRs a Client PC TPM2 must have (TCG PC Client PFP).
pub const TPM2_PCRS_MAX: u32 = 24;

/// Bitmask with all valid PCR bits set.
pub const TPM2_PCRS_MASK: u32 = (1u32 << TPM2_PCRS_MAX) - 1;

/// Reserved handle for the Storage Root Key (TCG Provisioning Guidance).
pub const TPM2_SRK_HANDLE: u32 = 0x81000001;

/// Maximum sealed data size (TPM2 spec: 128 bytes for interoperability).
pub const TPM2_MAX_SEALED_DATA: u16 = 128;

/// Number of hash algorithms we track.
pub const TPM2_N_HASH_ALGORITHMS: usize = 4;

/// Ordered list of hash algorithms, in preference order.
pub const TPM2_HASH_ALGORITHMS: &[u16] = &[
    TPM2_ALG_SHA1,
    TPM2_ALG_SHA256,
    TPM2_ALG_SHA384,
    TPM2_ALG_SHA512,
];

/// NV index range that is not registered to any company (TCG Registry).
pub const TPM2_NV_INDEX_UNASSIGNED_FIRST: u32 = 0x01800000;
pub const TPM2_NV_INDEX_UNASSIGNED_LAST: u32 = 0x01BFFFFF;

// ── Handle type helpers ──────────────────────────────────────────────────

bitflags::bitflags! {
    /// Flags for TPM2 operations.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Tpm2Flags: u32 {
        const USE_PIN     = 1 << 0;
        const USE_PCRLOCK = 1 << 1;
    }
}

bitflags::bitflags! {
    /// Bitmask indicating which aspects of TPM2 support are available.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Tpm2Support: u32 {
        /// No support.
        const NONE         = 0;
        /// Firmware reports TPM2 was used.
        const FIRMWARE     = 1 << 0;
        /// Kernel has a driver loaded.
        const DRIVER       = 1 << 1;
        /// systemd supports TPM2 itself.
        const SYSTEM       = 1 << 2;
        /// Kernel has the tpm subsystem enabled.
        const SUBSYSTEM    = 1 << 3;
        /// We can dlopen the tpm2 libraries.
        const LIBRARIES    = 1 << 4;
        /// Combined API support flag.
        const API          = Self::FIRMWARE.bits()
                          | Self::DRIVER.bits()
                          | Self::SYSTEM.bits()
                          | Self::SUBSYSTEM.bits()
                          | Self::LIBRARIES.bits();
        /// Chip supports PolicyAuthorizeNV (pcrlock-specific).
        const AUTHORIZE_NV = 1 << 5;
        /// Chip supports SHA-256 (pcrlock-specific).
        const SHA256       = 1 << 6;
        /// Full pcrlock API support.
        const API_PCRLOCK  = Self::API.bits()
                          | Self::AUTHORIZE_NV.bits()
                          | Self::SHA256.bits();
        /// We can dlopen libtss2-esys.so.0.
        const LIBTSS2_ESYS = 1 << 7;
        /// We can dlopen libtss2-rc.so.0.
        const LIBTSS2_RC   = 1 << 8;
        /// We can dlopen libtss2-mu.so.0.
        const LIBTSS2_MU   = 1 << 9;
        /// All TSS2 libraries available.
        const LIBTSS2_ALL  = Self::LIBTSS2_ESYS.bits()
                          | Self::LIBTSS2_RC.bits()
                          | Self::LIBTSS2_MU.bits();
        /// Full support (API + all TSS2 libs).
        const FULL         = Self::API.bits()
                          | Self::LIBTSS2_ALL.bits();
        /// Software-only support (full without firmware).
        const SOFTWARE     = (Self::FULL.bits()) & !Self::FIRMWARE.bits();
    }
}

// ── Enumerations ─────────────────────────────────────────────────────────

/// Asymmetric algorithm types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tpm2AsymAlg {
    Rsa,
    Ecc,
}

impl Tpm2AsymAlg {
    /// Convert from a TPM2_ALG_* code.
    pub fn from_code(code: u16) -> Option<Self> {
        match code {
            TPM2_ALG_RSA => Some(Self::Rsa),
            TPM2_ALG_ECC => Some(Self::Ecc),
            _ => None,
        }
    }

    /// Convert to the TPM2_ALG_* code.
    pub const fn to_code(self) -> u16 {
        match self {
            Self::Rsa => TPM2_ALG_RSA,
            Self::Ecc => TPM2_ALG_ECC,
        }
    }

    /// Human-readable name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Rsa => "rsa",
            Self::Ecc => "ecc",
        }
    }
}

/// Hash algorithm types used in PCR operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Tpm2HashAlg {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

impl Tpm2HashAlg {
    /// Convert from a TPM2_ALG_* code.
    pub fn from_code(code: u16) -> Option<Self> {
        match code {
            TPM2_ALG_SHA1 => Some(Self::Sha1),
            TPM2_ALG_SHA256 => Some(Self::Sha256),
            TPM2_ALG_SHA384 => Some(Self::Sha384),
            TPM2_ALG_SHA512 => Some(Self::Sha512),
            _ => None,
        }
    }

    /// Convert to the TPM2_ALG_* code.
    pub const fn to_code(self) -> u16 {
        match self {
            Self::Sha1 => TPM2_ALG_SHA1,
            Self::Sha256 => TPM2_ALG_SHA256,
            Self::Sha384 => TPM2_ALG_SHA384,
            Self::Sha512 => TPM2_ALG_SHA512,
        }
    }

    /// Human-readable name (lowercase, matching C output).
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Sha1 => "sha1",
            Self::Sha256 => "sha256",
            Self::Sha384 => "sha384",
            Self::Sha512 => "sha512",
        }
    }

    /// Digest size in bytes for this hash algorithm.
    pub const fn digest_size(self) -> usize {
        match self {
            Self::Sha1 => 20,
            Self::Sha256 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
        }
    }
}

/// ECC curve identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tpm2EccCurve {
    NistP256,
    NistP384,
    NistP521,
}

impl Tpm2EccCurve {
    /// Convert from a TPM2 ECC curve code.
    pub fn from_code(code: u16) -> Option<Self> {
        match code {
            TPM2_ECC_NIST_P256 => Some(Self::NistP256),
            TPM2_ECC_NIST_P384 => Some(Self::NistP384),
            TPM2_ECC_NIST_P521 => Some(Self::NistP521),
            _ => None,
        }
    }

    /// Convert to the TPM2 ECC curve code.
    pub const fn to_code(self) -> u16 {
        match self {
            Self::NistP256 => TPM2_ECC_NIST_P256,
            Self::NistP384 => TPM2_ECC_NIST_P384,
            Self::NistP521 => TPM2_ECC_NIST_P521,
        }
    }

    /// Human-readable name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NistP256 => "nist-p256",
            Self::NistP384 => "nist-p384",
            Self::NistP521 => "nist-p521",
        }
    }
}

/// Symmetric algorithm types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tpm2SymAlg {
    Aes,
    Oaes,
    Xor,
    Sm4,
    Camellia,
}

impl Tpm2SymAlg {
    /// Convert from a TPM2_ALG_* code.
    pub fn from_code(code: u16) -> Option<Self> {
        match code {
            TPM2_ALG_AES => Some(Self::Aes),
            TPM2_ALG_OAES => Some(Self::Oaes),
            TPM2_ALG_XOR => Some(Self::Xor),
            TPM2_ALG_SM4 => Some(Self::Sm4),
            TPM2_ALG_CAMELLIA => Some(Self::Camellia),
            _ => None,
        }
    }

    /// Convert to the TPM2_ALG_* code.
    pub const fn to_code(self) -> u16 {
        match self {
            Self::Aes => TPM2_ALG_AES,
            Self::Oaes => TPM2_ALG_OAES,
            Self::Xor => TPM2_ALG_XOR,
            Self::Sm4 => TPM2_ALG_SM4,
            Self::Camellia => TPM2_ALG_CAMELLIA,
        }
    }

    /// Human-readable name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Aes => "aes",
            Self::Oaes => "oaes",
            Self::Xor => "xor",
            Self::Sm4 => "sm4",
            Self::Camellia => "camellia",
        }
    }
}

/// Symmetric cipher modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tpm2SymMode {
    Cfb,
    Ctr,
    Ofb,
    Cbc,
    Ecb,
}

impl Tpm2SymMode {
    /// Convert from a TPM2_ALG_* mode code.
    pub fn from_code(code: u16) -> Option<Self> {
        match code {
            TPM2_ALG_CFB => Some(Self::Cfb),
            TPM2_ALG_CTR => Some(Self::Ctr),
            TPM2_ALG_OFB => Some(Self::Ofb),
            TPM2_ALG_CBC => Some(Self::Cbc),
            TPM2_ALG_ECB => Some(Self::Ecb),
            _ => None,
        }
    }

    /// Convert to the TPM2_ALG_* mode code.
    pub const fn to_code(self) -> u16 {
        match self {
            Self::Cfb => TPM2_ALG_CFB,
            Self::Ctr => TPM2_ALG_CTR,
            Self::Ofb => TPM2_ALG_OFB,
            Self::Cbc => TPM2_ALG_CBC,
            Self::Ecb => TPM2_ALG_ECB,
        }
    }

    /// Human-readable name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Cfb => "cfb",
            Self::Ctr => "ctr",
            Self::Ofb => "ofb",
            Self::Cbc => "cbc",
            Self::Ecb => "ecb",
        }
    }

    /// Parse from a case-insensitive string.
    pub fn from_str_ci(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "cfb" => Some(Self::Cfb),
            "ctr" => Some(Self::Ctr),
            "ofb" => Some(Self::Ofb),
            "cbc" => Some(Self::Cbc),
            "ecb" => Some(Self::Ecb),
            _ => None,
        }
    }
}

/// Event types for userspace TPM2 measurements.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tpm2UserspaceEventType {
    Phase,
    Filesystem,
    VolumeKey,
    MachineId,
    ProductId,
    Keyslot,
    NvpcrInit,
    NvpcrSeparator,
    DmVerity,
    ImdsUserdata,
    OsSeparator,
}

impl Tpm2UserspaceEventType {
    /// Convert to the string representation used in log entries.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Phase => "phase",
            Self::Filesystem => "filesystem",
            Self::VolumeKey => "volume-key",
            Self::MachineId => "machine-id",
            Self::ProductId => "product-id",
            Self::Keyslot => "keyslot",
            Self::NvpcrInit => "nvpcr-init",
            Self::NvpcrSeparator => "nvpcr-separator",
            Self::DmVerity => "dm-verity",
            Self::ImdsUserdata => "imds-userdata",
            Self::OsSeparator => "os-separator",
        }
    }

    /// Parse from a string (case-sensitive).
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "phase" => Some(Self::Phase),
            "filesystem" => Some(Self::Filesystem),
            "volume-key" => Some(Self::VolumeKey),
            "machine-id" => Some(Self::MachineId),
            "product-id" => Some(Self::ProductId),
            "keyslot" => Some(Self::Keyslot),
            "nvpcr-init" => Some(Self::NvpcrInit),
            "nvpcr-separator" => Some(Self::NvpcrSeparator),
            "dm-verity" => Some(Self::DmVerity),
            "imds-userdata" => Some(Self::ImdsUserdata),
            "os-separator" => Some(Self::OsSeparator),
            _ => None,
        }
    }
}

// ── Vendor info ──────────────────────────────────────────────────────────

/// Information about a TPM2 chip vendor, extracted from capability properties.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tpm2VendorInfo {
    pub level: u32,
    pub revision_major: u32,
    pub revision_minor: u32,
    pub day_of_year: u32,
    pub year: u32,
    pub vendor_tpm_type: u32,
    pub firmware_version_major: u16,
    pub firmware_version_minor: u16,
    pub firmware_version2: u32,
    pub family_indicator: String,
    pub manufacturer: String,
    pub vendor_string: String,
}

impl Tpm2VendorInfo {
    /// Create a new vendor info with all fields zeroed / empty.
    pub fn new() -> Self {
        Self {
            level: 0,
            revision_major: 0,
            revision_minor: 0,
            day_of_year: 0,
            year: 0,
            vendor_tpm_type: 0,
            firmware_version_major: 0,
            firmware_version_minor: 0,
            firmware_version2: 0,
            family_indicator: String::new(),
            manufacturer: String::new(),
            vendor_string: String::new(),
        }
    }

    /// Convert to a modalias-style string (matching the C implementation).
    ///
    /// The format is inspired by kernel modalias strings and distills vendor
    /// data into a string suitable for matching hwdb.
    pub fn to_modalias(&self) -> String {
        format!(
            "fi{}:lv{}:rv{}.{}:sy{}:sd{}:mf{}:vs{}:ty{:x}:fw{}.{}.{}:",
            self.family_indicator,
            self.level,
            self.revision_major,
            self.revision_minor,
            self.year,
            self.day_of_year,
            self.manufacturer,
            self.vendor_string,
            self.vendor_tpm_type,
            self.firmware_version_major,
            self.firmware_version_minor,
            self.firmware_version2,
        )
    }
}

impl Default for Tpm2VendorInfo {
    fn default() -> Self {
        Self::new()
    }
}

// ── PCR value ────────────────────────────────────────────────────────────

/// A single PCR value: index + hash algorithm + digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tpm2PCRValue {
    /// PCR register index (0..TPM2_PCRS_MAX).
    pub index: u32,
    /// Hash algorithm used.
    pub hash: u16,
    /// The digest value.
    pub value: Vec<u8>,
}

impl Tpm2PCRValue {
    /// Create a new PCR value.
    pub fn new(index: u32, hash: u16, value: Vec<u8>) -> Self {
        Self { index, hash, value }
    }

    /// Check if the PCR index is valid.
    pub fn index_valid(&self) -> bool {
        self.index < TPM2_PCRS_MAX
    }

    /// Check if this value has actual digest data (non-empty).
    pub fn has_value(&self) -> bool {
        !self.value.is_empty()
    }

    /// Parse a PCR value from a string in the format "index:hash=value" or
    /// "index=value" (defaulting to sha256).
    pub fn from_string(s: &str) -> Result<Self, Tpm2Error> {
        let (index_part, rest) = s
            .split_once(':')
            .map(|(i, r)| (i, Some(r)))
            .unwrap_or((s, None));

        let index: u32 = index_part.parse().map_err(|_| Tpm2Error::InvalidArgument)?;
        if index >= TPM2_PCRS_MAX {
            return Err(Tpm2Error::InvalidArgument);
        }

        let (hash, hex_value) = match rest {
            Some(r) => {
                let (h, v) = r.split_once('=').ok_or(Tpm2Error::InvalidArgument)?;
                let alg = tpm2_hash_alg_from_string(h).ok_or(Tpm2Error::InvalidArgument)?;
                (alg, v)
            }
            None => (TPM2_ALG_SHA256, s),
        };

        let value = hex_decode(hex_value).map_err(|_| Tpm2Error::InvalidArgument)?;

        Ok(Self { index, hash, value })
    }

    /// Format as "index:hash=hexvalue".
    pub fn to_string_repr(&self) -> String {
        let hash_name = tpm2_hash_alg_to_string(self.hash).unwrap_or("unknown");
        let hex: String = self.value.iter().map(|b| format!("{b:02x}")).collect();
        format!("{}:{}={}", self.index, hash_name, hex)
    }
}

// ── Pure functions: hash algorithm sizing ────────────────────────────────

/// Return the digest size in bytes for a given hash algorithm code.
///
/// Returns `None` for unknown algorithms.
pub fn tpm2_hash_alg_to_size(alg: u16) -> Option<usize> {
    match alg {
        TPM2_ALG_SHA1 => Some(20),
        TPM2_ALG_SHA256 => Some(32),
        TPM2_ALG_SHA384 => Some(48),
        TPM2_ALG_SHA512 => Some(64),
        _ => None,
    }
}

// ── Pure functions: code → string ────────────────────────────────────────

/// Convert a TPM2 hash algorithm code to its human-readable name.
pub fn tpm2_hash_alg_to_string(alg: u16) -> Option<&'static str> {
    match alg {
        TPM2_ALG_SHA1 => Some("sha1"),
        TPM2_ALG_SHA256 => Some("sha256"),
        TPM2_ALG_SHA384 => Some("sha384"),
        TPM2_ALG_SHA512 => Some("sha512"),
        _ => None,
    }
}

/// Parse a case-insensitive hash algorithm name to its TPM2 code.
pub fn tpm2_hash_alg_from_string(s: &str) -> Option<u16> {
    match s.to_ascii_lowercase().as_str() {
        "sha1" => Some(TPM2_ALG_SHA1),
        "sha256" => Some(TPM2_ALG_SHA256),
        "sha384" => Some(TPM2_ALG_SHA384),
        "sha512" => Some(TPM2_ALG_SHA512),
        _ => None,
    }
}

/// Convert a TPM2 asymmetric algorithm code to its human-readable name.
pub fn tpm2_asym_alg_to_string(alg: u16) -> Option<&'static str> {
    match alg {
        TPM2_ALG_RSA => Some("rsa"),
        TPM2_ALG_ECC => Some("ecc"),
        _ => None,
    }
}

/// Parse a case-insensitive asymmetric algorithm name to its TPM2 code.
pub fn tpm2_asym_alg_from_string(s: &str) -> Option<u16> {
    match s.to_ascii_lowercase().as_str() {
        "rsa" => Some(TPM2_ALG_RSA),
        "ecc" => Some(TPM2_ALG_ECC),
        _ => None,
    }
}

/// Convert a TPM2 symmetric algorithm code to its human-readable name.
pub fn tpm2_sym_alg_to_string(alg: u16) -> Option<&'static str> {
    match alg {
        TPM2_ALG_AES => Some("aes"),
        TPM2_ALG_OAES => Some("oaes"),
        TPM2_ALG_XOR => Some("xor"),
        TPM2_ALG_SM4 => Some("sm4"),
        TPM2_ALG_CAMELLIA => Some("camellia"),
        _ => None,
    }
}

/// Convert a TPM2 symmetric mode code to its human-readable name.
pub fn tpm2_sym_mode_to_string(mode: u16) -> Option<&'static str> {
    match mode {
        TPM2_ALG_CFB => Some("cfb"),
        TPM2_ALG_CTR => Some("ctr"),
        TPM2_ALG_OFB => Some("ofb"),
        TPM2_ALG_CBC => Some("cbc"),
        TPM2_ALG_ECB => Some("ecb"),
        _ => None,
    }
}

/// Parse a case-insensitive symmetric mode name to its TPM2 code.
pub fn tpm2_sym_mode_from_string(s: &str) -> Option<u16> {
    match s.to_ascii_lowercase().as_str() {
        "cfb" => Some(TPM2_ALG_CFB),
        "ctr" => Some(TPM2_ALG_CTR),
        "ofb" => Some(TPM2_ALG_OFB),
        "cbc" => Some(TPM2_ALG_CBC),
        "ecb" => Some(TPM2_ALG_ECB),
        _ => None,
    }
}

/// Convert a TPM2 ECC curve code to its human-readable name.
pub fn tpm2_ecc_curve_to_string(curve: u16) -> Option<&'static str> {
    match curve {
        TPM2_ECC_NIST_P256 => Some("nist-p256"),
        TPM2_ECC_NIST_P384 => Some("nist-p384"),
        TPM2_ECC_NIST_P521 => Some("nist-p521"),
        _ => None,
    }
}

/// Parse a case-insensitive ECC curve name to its TPM2 code.
pub fn tpm2_ecc_curve_from_string(s: &str) -> Option<u16> {
    match s.to_ascii_lowercase().as_str() {
        "nist-p256" => Some(TPM2_ECC_NIST_P256),
        "nist-p384" => Some(TPM2_ECC_NIST_P384),
        "nist-p521" => Some(TPM2_ECC_NIST_P521),
        _ => None,
    }
}

// ── PCR mask utilities ───────────────────────────────────────────────────

/// Check if a PCR index is valid (0..TPM2_PCRS_MAX).
#[inline]
pub const fn tpm2_pcr_index_valid(pcr: u32) -> bool {
    pcr < TPM2_PCRS_MAX
}

/// Check if a PCR mask only covers valid PCR indices.
#[inline]
pub const fn tpm2_pcr_mask_valid(pcr_mask: u32) -> bool {
    pcr_mask <= TPM2_PCRS_MASK
}

/// Convert a PCR mask to a human-readable string like "0+1+7".
pub fn tpm2_pcr_mask_to_string(mask: u32) -> String {
    if mask == 0 {
        return String::new();
    }
    let mut parts = Vec::new();
    let mut m = mask;
    while m != 0 {
        let pcr = m.trailing_zeros();
        parts.push(pcr.to_string());
        m &= !(1u32 << pcr);
    }
    parts.join("+")
}

/// Iterate over each PCR index set in the mask, in ascending order.
pub fn tpm2_pcr_mask_iter(mask: u32) -> Tpm2PcrMaskIter {
    Tpm2PcrMaskIter { mask }
}

/// Iterator over PCR indices set in a bitmask.
pub struct Tpm2PcrMaskIter {
    mask: u32,
}

impl Iterator for Tpm2PcrMaskIter {
    type Item = u32;

    fn next(&mut self) -> Option<Self::Item> {
        if self.mask == 0 {
            return None;
        }
        let pcr = self.mask.trailing_zeros();
        self.mask &= !(1u32 << pcr);
        Some(pcr)
    }
}

/// Convert a PCR selection (hash + mask) to a combined mask.
/// Returns the intersection of the selection mask and the valid PCR range.
pub fn tpm2_pcr_selection_to_mask(selection_hash: u16, selection_mask: u32) -> u32 {
    let _ = selection_hash; // hash is used for bank filtering at a higher level
    selection_mask & TPM2_PCRS_MASK
}

// ── dlopen-related constants ─────────────────────────────────────────────

/// Names of the TSS2 shared libraries we attempt to load.
pub const TPM2_TSS2_ESYS_LIB: &str = "libtss2-esys.so.0";
pub const TPM2_TSS2_RC_LIB: &str = "libtss2-rc.so.0";
pub const TPM2_TSS2_MU_LIB: &str = "libtss2-mu.so.0";
pub const TPM2_TSS2_TCTI_DEVICE_LIB: &str = "libtss2-tcti-device.so.0";

/// The default TPM2 device TCTI string used when no device is specified.
pub const TPM2_DEFAULT_DEVICE: &str = "device:/dev/tpmrm0";

/// Path to the flag file indicating TPM entropy has already been credited.
pub const TPM2_CREDIT_RANDOM_FLAG_PATH: &str = "/run/systemd/tpm-rng-credited";

// ── Internal helpers ─────────────────────────────────────────────────────

/// Decode a hex string into bytes. Returns an error if the string is not
/// valid hex or has an odd length.
fn hex_decode(s: &str) -> Result<Vec<u8>, ()> {
    if s.len() % 2 != 0 {
        return Err(());
    }
    let mut bytes = Vec::with_capacity(s.len() / 2);
    for chunk in s.as_bytes().chunks(2) {
        let high = hex_nibble(chunk[0]).ok_or(())?;
        let low = hex_nibble(chunk[1]).ok_or(())?;
        bytes.push((high << 4) | low);
    }
    Ok(bytes)
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Algorithm constant tests ─────────────────────────────────────

    #[test]
    fn test_asym_alg_constants() {
        assert_eq!(TPM2_ALG_RSA, 0x0001);
        assert_eq!(TPM2_ALG_ECC, 0x0023);
    }

    #[test]
    fn test_sym_alg_constants() {
        assert_eq!(TPM2_ALG_AES, 0x0006);
        assert_eq!(TPM2_ALG_CFB, 0x0043);
        assert_eq!(TPM2_ALG_CTR, 0x0040);
        assert_eq!(TPM2_ALG_CBC, 0x0042);
        assert_eq!(TPM2_ALG_OFB, 0x0041);
        assert_eq!(TPM2_ALG_ECB, 0x0044);
    }

    #[test]
    fn test_hash_alg_constants() {
        assert_eq!(TPM2_ALG_SHA1, 0x0004);
        assert_eq!(TPM2_ALG_SHA256, 0x000B);
        assert_eq!(TPM2_ALG_SHA384, 0x000C);
        assert_eq!(TPM2_ALG_SHA512, 0x000D);
    }

    #[test]
    fn test_pcr_constants() {
        assert_eq!(TPM2_PCRS_MAX, 24);
        assert_eq!(TPM2_PCRS_MASK, (1u32 << 24) - 1);
        assert_eq!(TPM2_SRK_HANDLE, 0x81000001);
        assert_eq!(TPM2_MAX_SEALED_DATA, 128);
        assert_eq!(TPM2_HASH_ALGORITHMS.len(), TPM2_N_HASH_ALGORITHMS);
    }

    #[test]
    fn test_rc_constants() {
        assert_eq!(TPM2_RC_SUCCESS, 0x0000);
        assert_eq!(TPM2_RC_INITIALIZE, 0x0100);
        assert_eq!(TPM2_RC_BAD_TAG, 0x001E);
    }

    // ── Hash algorithm roundtrip ────────────────────────────────────

    #[test]
    fn test_hash_alg_roundtrip() {
        for &code in TPM2_HASH_ALGORITHMS {
            let name = tpm2_hash_alg_to_string(code).unwrap();
            let back = tpm2_hash_alg_from_string(name).unwrap();
            assert_eq!(code, back);
        }
    }

    #[test]
    fn test_hash_alg_to_string_unknown() {
        assert!(tpm2_hash_alg_to_string(0xFFFF).is_none());
        assert!(tpm2_hash_alg_from_string("blake2").is_none());
    }

    #[test]
    fn test_hash_alg_case_insensitive() {
        assert_eq!(tpm2_hash_alg_from_string("SHA256"), Some(TPM2_ALG_SHA256));
        assert_eq!(tpm2_hash_alg_from_string("Sha384"), Some(TPM2_ALG_SHA384));
        assert_eq!(tpm2_hash_alg_from_string("SHA1"), Some(TPM2_ALG_SHA1));
    }

    // ── Hash algorithm sizing ────────────────────────────────────────

    #[test]
    fn test_hash_alg_to_size() {
        assert_eq!(tpm2_hash_alg_to_size(TPM2_ALG_SHA1), Some(20));
        assert_eq!(tpm2_hash_alg_to_size(TPM2_ALG_SHA256), Some(32));
        assert_eq!(tpm2_hash_alg_to_size(TPM2_ALG_SHA384), Some(48));
        assert_eq!(tpm2_hash_alg_to_size(TPM2_ALG_SHA512), Some(64));
        assert_eq!(tpm2_hash_alg_to_size(0xFFFF), None);
    }

    #[test]
    fn test_tpm2_hash_alg_enum_sizes() {
        assert_eq!(Tpm2HashAlg::Sha1.digest_size(), 20);
        assert_eq!(Tpm2HashAlg::Sha256.digest_size(), 32);
        assert_eq!(Tpm2HashAlg::Sha384.digest_size(), 48);
        assert_eq!(Tpm2HashAlg::Sha512.digest_size(), 64);
    }

    // ── Symmetric algorithm roundtrip ───────────────────────────────

    #[test]
    fn test_sym_alg_roundtrip() {
        let algs = [
            (TPM2_ALG_AES, "aes"),
            (TPM2_ALG_OAES, "oaes"),
            (TPM2_ALG_XOR, "xor"),
            (TPM2_ALG_SM4, "sm4"),
            (TPM2_ALG_CAMELLIA, "camellia"),
        ];
        for (code, name) in algs {
            assert_eq!(tpm2_sym_alg_to_string(code), Some(name));
        }
        assert!(tpm2_sym_alg_to_string(0xFFFF).is_none());
    }

    #[test]
    fn test_sym_mode_roundtrip() {
        let modes = [
            (TPM2_ALG_CFB, "cfb"),
            (TPM2_ALG_CTR, "ctr"),
            (TPM2_ALG_OFB, "ofb"),
            (TPM2_ALG_CBC, "cbc"),
            (TPM2_ALG_ECB, "ecb"),
        ];
        for (code, name) in modes {
            assert_eq!(tpm2_sym_mode_to_string(code), Some(name));
            assert_eq!(tpm2_sym_mode_from_string(name), Some(code));
        }
        assert_eq!(tpm2_sym_mode_from_string("invalid"), None);
        assert_eq!(tpm2_sym_mode_to_string(0xFFFF), None);
    }

    #[test]
    fn test_sym_mode_case_insensitive() {
        assert_eq!(tpm2_sym_mode_from_string("CFB"), Some(TPM2_ALG_CFB));
        assert_eq!(tpm2_sym_mode_from_string("Ctr"), Some(TPM2_ALG_CTR));
    }

    // ── Asymmetric algorithm roundtrip ───────────────────────────────

    #[test]
    fn test_asym_alg_roundtrip() {
        assert_eq!(tpm2_asym_alg_to_string(TPM2_ALG_RSA), Some("rsa"));
        assert_eq!(tpm2_asym_alg_to_string(TPM2_ALG_ECC), Some("ecc"));
        assert_eq!(tpm2_asym_alg_from_string("rsa"), Some(TPM2_ALG_RSA));
        assert_eq!(tpm2_asym_alg_from_string("ecc"), Some(TPM2_ALG_ECC));
        assert_eq!(tpm2_asym_alg_from_string("RSA"), Some(TPM2_ALG_RSA));
        assert!(tpm2_asym_alg_to_string(0xFFFF).is_none());
        assert!(tpm2_asym_alg_from_string("invalid").is_none());
    }

    // ── ECC curve roundtrip ─────────────────────────────────────────

    #[test]
    fn test_ecc_curve_roundtrip() {
        let curves = [
            (TPM2_ECC_NIST_P256, "nist-p256"),
            (TPM2_ECC_NIST_P384, "nist-p384"),
            (TPM2_ECC_NIST_P521, "nist-p521"),
        ];
        for (code, name) in curves {
            assert_eq!(tpm2_ecc_curve_to_string(code), Some(name));
            assert_eq!(tpm2_ecc_curve_from_string(name), Some(code));
        }
        assert_eq!(tpm2_ecc_curve_from_string("invalid"), None);
        assert_eq!(tpm2_ecc_curve_to_string(0xFFFF), None);
    }

    #[test]
    fn test_ecc_curve_case_insensitive() {
        assert_eq!(
            tpm2_ecc_curve_from_string("NIST-P256"),
            Some(TPM2_ECC_NIST_P256)
        );
    }

    // ── Enum type conversions ────────────────────────────────────────

    #[test]
    fn test_asym_alg_enum() {
        let rsa = Tpm2AsymAlg::from_code(TPM2_ALG_RSA).unwrap();
        assert_eq!(rsa, Tpm2AsymAlg::Rsa);
        assert_eq!(rsa.to_code(), TPM2_ALG_RSA);
        assert_eq!(rsa.as_str(), "rsa");

        let ecc = Tpm2AsymAlg::from_code(TPM2_ALG_ECC).unwrap();
        assert_eq!(ecc, Tpm2AsymAlg::Ecc);
        assert_eq!(ecc.to_code(), TPM2_ALG_ECC);
        assert_eq!(ecc.as_str(), "ecc");

        assert!(Tpm2AsymAlg::from_code(0xFFFF).is_none());
    }

    #[test]
    fn test_hash_alg_enum() {
        let sha = Tpm2HashAlg::from_code(TPM2_ALG_SHA256).unwrap();
        assert_eq!(sha, Tpm2HashAlg::Sha256);
        assert_eq!(sha.to_code(), TPM2_ALG_SHA256);
        assert_eq!(sha.as_str(), "sha256");
    }

    #[test]
    fn test_ecc_curve_enum() {
        let p256 = Tpm2EccCurve::from_code(TPM2_ECC_NIST_P256).unwrap();
        assert_eq!(p256, Tpm2EccCurve::NistP256);
        assert_eq!(p256.to_code(), TPM2_ECC_NIST_P256);
        assert_eq!(p256.as_str(), "nist-p256");
    }

    #[test]
    fn test_sym_mode_enum() {
        let cfb = Tpm2SymMode::from_code(TPM2_ALG_CFB).unwrap();
        assert_eq!(cfb, Tpm2SymMode::Cfb);
        assert_eq!(cfb.to_code(), TPM2_ALG_CFB);
        assert_eq!(cfb.as_str(), "cfb");
        assert_eq!(Tpm2SymMode::from_str_ci("CTR"), Some(Tpm2SymMode::Ctr));
    }

    // ── PCR mask utilities ───────────────────────────────────────────

    #[test]
    fn test_pcr_index_valid() {
        assert!(tpm2_pcr_index_valid(0));
        assert!(tpm2_pcr_index_valid(23));
        assert!(!tpm2_pcr_index_valid(24));
        assert!(!tpm2_pcr_index_valid(u32::MAX));
    }

    #[test]
    fn test_pcr_mask_valid() {
        assert!(tpm2_pcr_mask_valid(0));
        assert!(tpm2_pcr_mask_valid(TPM2_PCRS_MASK));
        assert!(!tpm2_pcr_mask_valid(TPM2_PCRS_MASK + 1));
    }

    #[test]
    fn test_pcr_mask_to_string() {
        assert_eq!(tpm2_pcr_mask_to_string(0), "");
        assert_eq!(tpm2_pcr_mask_to_string(1), "0");
        assert_eq!(tpm2_pcr_mask_to_string(3), "0+1");
        assert_eq!(tpm2_pcr_mask_to_string(0x80), "7");
        assert_eq!(tpm2_pcr_mask_to_string(0x85), "0+2+7");
    }

    #[test]
    fn test_pcr_mask_iter() {
        let indices: Vec<u32> = tpm2_pcr_mask_iter(0x85).collect();
        assert_eq!(indices, vec![0, 2, 7]);

        let empty: Vec<u32> = tpm2_pcr_mask_iter(0).collect();
        assert!(empty.is_empty());
    }

    #[test]
    fn test_pcr_selection_to_mask() {
        assert_eq!(tpm2_pcr_selection_to_mask(TPM2_ALG_SHA256, 0x85), 0x85);
        // Out-of-range bits are masked off
        assert_eq!(
            tpm2_pcr_selection_to_mask(TPM2_ALG_SHA256, 0x01FF_FFFF),
            TPM2_PCRS_MASK
        );
    }

    // ── Vendor info ──────────────────────────────────────────────────

    #[test]
    fn test_vendor_info_default() {
        let info = Tpm2VendorInfo::new();
        assert_eq!(info.level, 0);
        assert!(info.family_indicator.is_empty());
    }

    #[test]
    fn test_vendor_info_modalias() {
        let info = Tpm2VendorInfo {
            level: 2,
            revision_major: 1,
            revision_minor: 16,
            day_of_year: 42,
            year: 2024,
            vendor_tpm_type: 1,
            firmware_version_major: 7,
            firmware_version_minor: 2,
            firmware_version2: 0,
            family_indicator: "2.0".to_string(),
            manufacturer: "INTC".to_string(),
            vendor_string: "Intel".to_string(),
        };
        let modalias = info.to_modalias();
        assert!(modalias.starts_with("fi2.0:lv2:rv1.16:"));
        assert!(modalias.contains("sy2024:sd42:"));
        assert!(modalias.contains("mfINTC:"));
    }

    // ── Userspace event type ─────────────────────────────────────────

    #[test]
    fn test_userspace_event_type_roundtrip() {
        let events = [
            (Tpm2UserspaceEventType::Phase, "phase"),
            (Tpm2UserspaceEventType::Filesystem, "filesystem"),
            (Tpm2UserspaceEventType::VolumeKey, "volume-key"),
            (Tpm2UserspaceEventType::MachineId, "machine-id"),
            (Tpm2UserspaceEventType::Keyslot, "keyslot"),
            (Tpm2UserspaceEventType::OsSeparator, "os-separator"),
        ];
        for (variant, name) in events {
            assert_eq!(variant.as_str(), name);
            assert_eq!(Tpm2UserspaceEventType::from_str(name), Some(variant));
        }
        assert!(Tpm2UserspaceEventType::from_str("nonexistent").is_none());
    }

    // ── Support flags ────────────────────────────────────────────────

    #[test]
    fn test_support_flags() {
        assert_eq!(Tpm2Support::NONE.bits(), 0);
        assert!(Tpm2Support::FULL.contains(Tpm2Support::API));
        assert!(Tpm2Support::FULL.contains(Tpm2Support::LIBTSS2_ALL));
        assert!(Tpm2Support::API_PCRLOCK.contains(Tpm2Support::API));
        assert!(Tpm2Support::API_PCRLOCK.contains(Tpm2Support::AUTHORIZE_NV));
        assert!(Tpm2Support::API_PCRLOCK.contains(Tpm2Support::SHA256));
        // SOFTWARE is FULL minus FIRMWARE
        assert!(!Tpm2Support::SOFTWARE.contains(Tpm2Support::FIRMWARE));
        assert!(Tpm2Support::SOFTWARE.contains(Tpm2Support::LIBTSS2_ALL));
    }

    // ── Flags ────────────────────────────────────────────────────────

    #[test]
    fn test_tpm2_flags() {
        assert!(Tpm2Flags::USE_PIN.bits() == 1);
        assert!(Tpm2Flags::USE_PCRLOCK.bits() == 2);
        let both = Tpm2Flags::USE_PIN | Tpm2Flags::USE_PCRLOCK;
        assert!(both.contains(Tpm2Flags::USE_PIN));
        assert!(both.contains(Tpm2Flags::USE_PCRLOCK));
    }

    // ── NV index range ───────────────────────────────────────────────

    #[test]
    fn test_nv_index_range() {
        assert!(TPM2_NV_INDEX_UNASSIGNED_FIRST < TPM2_NV_INDEX_UNASSIGNED_LAST);
        assert_eq!(TPM2_NV_INDEX_UNASSIGNED_FIRST, 0x01800000);
        assert_eq!(TPM2_NV_INDEX_UNASSIGNED_LAST, 0x01BFFFFF);
    }

    // ── Library constants ────────────────────────────────────────────

    #[test]
    fn test_library_constants() {
        assert!(TPM2_TSS2_ESYS_LIB.contains("esys"));
        assert!(TPM2_TSS2_RC_LIB.contains("rc"));
        assert!(TPM2_TSS2_MU_LIB.contains("mu"));
        assert!(TPM2_DEFAULT_DEVICE.starts_with("device:"));
    }

    // ── Hex decode ───────────────────────────────────────────────────

    #[test]
    fn test_hex_decode() {
        assert_eq!(
            hex_decode("deadbeef").unwrap(),
            vec![0xde, 0xad, 0xbe, 0xef]
        );
        assert_eq!(hex_decode("").unwrap(), Vec::<u8>::new());
        assert_eq!(hex_decode("00FF").unwrap(), vec![0x00, 0xFF]);
        assert!(hex_decode("zz").is_err());
        assert!(hex_decode("abc").is_err()); // odd length
    }
}
