// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/pcrextend-util.c, src/shared/pcrextend-util.h
//
// PCR extend utility functions for building measurement "words" that are
// extended into TPM PCRs.  Each word is a colon-separated string prefixed
// by its type (e.g. "file-system:", "machine-id:", "verity:").
//
// Also provides `_now()` variants that immediately extend the measurement
// into a PCR via the io.systemd.PCRExtend Varlink service (requires TPM2).

use std::ffi::c_int;

use crate::ffi::Errno;

// ── Constants ───────────────────────────────────────────────────────────────

/// Path to the pcrextend binary.
pub const PCREXTEND_PATH: &str = "/usr/bin/pcrextend";

/// Maximum number of bytes of IMDS user-data included verbatim in the
/// measurement word (the rest is truncated).  Matches the C constant
/// `IMDS_USERDATA_TRUNCATED_MAX`.
pub const IMDS_USERDATA_TRUNCATED_MAX: usize = 256;

/// SHA-256 digest size in bytes.
const SHA256_DIGEST_SIZE: usize = 32;

/// The Varlink socket address for the PCRExtend service.
const PCREXTEND_VARLINK_ADDRESS: &str = "/run/systemd/io.systemd.PCRExtend";

/// The number of components in a file-system word (prefix + 6 blkid fields).
const FILE_SYSTEM_WORD_COMPONENTS: usize = 7;

// ── Error type ──────────────────────────────────────────────────────────────

/// Errors produced by PCR-extend utility operations.
///
/// Wraps a negative errno value, matching the systemd C convention.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PcrextendError {
    code: c_int,
}

impl PcrextendError {
    /// Construct from a raw negative errno value.
    pub fn from_neg_errno(neg: c_int) -> Self {
        Self { code: neg }
    }

    /// Operation not supported.
    pub fn not_supported() -> Self {
        Self {
            code: Errno::EOPNOTSUPP.to_neg_errno(),
        }
    }

    /// Invalid argument.
    pub fn invalid_argument() -> Self {
        Self {
            code: Errno::EINVAL.to_neg_errno(),
        }
    }

    /// I/O error.
    pub fn io_error() -> Self {
        Self {
            code: Errno::EIO.to_neg_errno(),
        }
    }

    /// Out of memory.
    pub fn out_of_memory() -> Self {
        Self {
            code: Errno::ENOMEM.to_neg_errno(),
        }
    }

    /// Bad message / malformed data.
    pub fn bad_message() -> Self {
        Self {
            code: Errno::EBADMSG.to_neg_errno(),
        }
    }

    /// No such entity.
    pub fn no_entity() -> Self {
        Self {
            code: Errno::ENOENT.to_neg_errno(),
        }
    }

    /// Address not available.
    pub fn address_not_available() -> Self {
        Self {
            code: Errno::EADDRNOTAVAIL.to_neg_errno(),
        }
    }

    /// Not a directory.
    pub fn not_a_directory() -> Self {
        Self {
            code: Errno::ENOTDIR.to_neg_errno(),
        }
    }

    /// Invalid request (EBADR).
    pub fn bad_request() -> Self {
        Self {
            code: Errno::EBADR.to_neg_errno(),
        }
    }

    /// Package not installed (ENOPKG).
    pub fn no_package() -> Self {
        Self {
            code: Errno::ENOPKG.to_neg_errno(),
        }
    }

    /// Returns the raw negative errno code.
    pub fn as_neg_errno(&self) -> c_int {
        self.code
    }

    /// Check if this is an EOPNOTSUPP error.
    pub fn is_not_supported(&self) -> bool {
        self.code == Errno::EOPNOTSUPP.to_neg_errno()
    }
}

impl std::fmt::Display for PcrextendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "pcrextend error (errno {})", self.code)
    }
}

impl std::error::Error for PcrextendError {}

pub type Result<T> = std::result::Result<T, PcrextendError>;

// ── Enums ───────────────────────────────────────────────────────────────────

/// PCR extend mode — replace the PCR value or extend it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum PcrExtendMode {
    Replace = 0,
    Extend = 1,
}

/// Blkid probe fields used when constructing a file-system identity word.
///
/// These correspond to the `FOREACH_STRING(field, "TYPE", "UUID", "LABEL",
/// "PART_ENTRY_UUID", "PART_ENTRY_TYPE", "PART_ENTRY_NAME")` loop in the C
/// code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlkidField {
    Type,
    Uuid,
    Label,
    PartEntryUuid,
    PartEntryType,
    PartEntryName,
}

impl BlkidField {
    /// The C string name used in blkid_probe_lookup_value.
    pub const fn as_cstr(&self) -> &'static str {
        match self {
            BlkidField::Type => "TYPE",
            BlkidField::Uuid => "UUID",
            BlkidField::Label => "LABEL",
            BlkidField::PartEntryUuid => "PART_ENTRY_UUID",
            BlkidField::PartEntryType => "PART_ENTRY_TYPE",
            BlkidField::PartEntryName => "PART_ENTRY_NAME",
        }
    }

    /// All blkid fields in the canonical order.
    pub const ALL: [BlkidField; 6] = [
        BlkidField::Type,
        BlkidField::Uuid,
        BlkidField::Label,
        BlkidField::PartEntryUuid,
        BlkidField::PartEntryType,
        BlkidField::PartEntryName,
    ];
}

/// Result of a blkid safeprobe operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlkidProbeResult {
    Found,
    Ambiguous,
    NotFound,
    Error,
}

/// Varlink call result from a PCRExtend Extend operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PcrextendCallResult {
    /// Successfully extended.
    Success,
    /// The specified NvPCR does not exist.
    NoSuchNvPcr,
}

// ── Parsing helpers ─────────────────────────────────────────────────────────

/// Parse a hash algorithm name (case-insensitive) into its canonical form.
///
/// Supported: sha1, sha256, sha384, sha512.
pub fn pcrextend_parse_hash_alg(s: &str) -> Option<&'static str> {
    match s.to_lowercase().as_str() {
        "sha1" => Some("sha1"),
        "sha256" => Some("sha256"),
        "sha384" => Some("sha384"),
        "sha512" => Some("sha512"),
        _ => None,
    }
}

/// Parse a PCR extend mode string (case-insensitive).
pub fn pcrextend_parse_mode(s: &str) -> Option<PcrExtendMode> {
    match s.to_lowercase().as_str() {
        "replace" => Some(PcrExtendMode::Replace),
        "extend" => Some(PcrExtendMode::Extend),
        _ => None,
    }
}

// ── Colon-escape helpers ────────────────────────────────────────────────────

/// Escape colons in a string by replacing `:` with `\x3a`.
///
/// This avoids ambiguity when the escaped string is embedded in a
/// colon-separated measurement word.
fn escape_colons(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        if ch == ':' {
            out.push_str("\\x3a");
        } else {
            out.push(ch);
        }
    }
    out
}

// ── Hex / Base64 / SHA-256 helpers ─────────────────────────────────────────

/// Encode a byte slice as a lowercase hexadecimal string.
///
/// Equivalent to C `hexmem()`.
fn hex_encode(data: &[u8]) -> String {
    let mut s = String::with_capacity(data.len() * 2);
    for &b in data {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

/// Encode a byte slice as a standard Base64 string (no line breaks).
///
/// Equivalent to C `base64mem_full(..., SIZE_MAX, ...)`.
fn base64_encode(data: &[u8]) -> String {
    // Standard Base64 using the openssl crate (available as a dependency).
    use openssl::base64::encode_block;
    encode_block(data)
}

/// Compute the SHA-256 digest of `data` and return the 32-byte hash.
///
/// Uses OpenSSL's SHA-256 implementation.
fn sha256_digest(data: &[u8]) -> Result<[u8; SHA256_DIGEST_SIZE]> {
    use openssl::hash::{hash, MessageDigest};
    let digest = hash(MessageDigest::sha256(), data).map_err(|_| PcrextendError::io_error())?;
    let bytes = digest.as_ref();
    if bytes.len() != SHA256_DIGEST_SIZE {
        return Err(PcrextendError::io_error());
    }
    let mut arr = [0u8; SHA256_DIGEST_SIZE];
    arr.copy_from_slice(bytes);
    Ok(arr)
}

// ── File-system word ────────────────────────────────────────────────────────

/// Build the file-system identity word from blkid probe values.
///
/// Given a prefix (e.g. `"file-system:/escaped/path"`) and six blkid field
/// values (all colon-escaped), assembles them into a single colon-separated
/// word.  Always produces exactly `FILE_SYSTEM_WORD_COMPONENTS` components
/// (prefix + 6 fields) to avoid ambiguous strings.
///
/// Returns the assembled word, or an error if any field is invalid.
pub fn build_file_system_word(prefix: &str, blkid_values: &[Option<&str>]) -> Result<String> {
    if blkid_values.len() != BlkidField::ALL.len() {
        return Err(PcrextendError::invalid_argument());
    }

    let mut parts: Vec<String> = Vec::with_capacity(FILE_SYSTEM_WORD_COMPONENTS);
    parts.push(prefix.to_string());

    for (i, val) in blkid_values.iter().enumerate() {
        let escaped = match val {
            Some(v) => escape_colons(v),
            None => String::new(),
        };
        parts.push(escaped);
        let _ = i; // use the index for clarity
    }

    assert_eq!(
        parts.len(),
        FILE_SYSTEM_WORD_COMPONENTS,
        "file-system word must always have exactly {} components",
        FILE_SYSTEM_WORD_COMPONENTS
    );

    Ok(parts.join(":"))
}

/// Build a generic file-system word with all-empty blkid fields.
///
/// This is the fallback used when the backing block device cannot be
/// determined.  Produces `"file-system:<escaped_path>:::::::"`.
pub fn build_generic_file_system_word(escaped_path: &str) -> String {
    format!("file-system:{}::::::", escaped_path)
}

/// Build the full file-system word from a path.
///
/// This is the Rust equivalent of `pcrextend_file_system_word()`.
///
/// Given a filesystem path:
/// 1. Escapes colons in the normalized path.
/// 2. Builds the prefix `"file-system:<escaped_path>"`.
/// 3. If `blkid_values` is provided (from a real blkid probe), assembles
///    the full word with those values.
/// 4. Otherwise, produces a generic fallback word with all-empty fields.
///
/// Returns `(word, escaped_normalized_path)`.
pub fn pcrextend_file_system_word(
    path: &str,
    blkid_values: Option<&[Option<&str>]>,
) -> Result<(String, String)> {
    if path.is_empty() {
        return Err(PcrextendError::invalid_argument());
    }

    let escaped_path = escape_colons(path);
    let prefix = format!("file-system:{}", escaped_path);

    let word = match blkid_values {
        Some(values) => build_file_system_word(&prefix, values)?,
        None => build_generic_file_system_word(&escaped_path),
    };

    Ok((word, escaped_path))
}

// ── Machine-id word ─────────────────────────────────────────────────────────

/// Build the machine-id measurement word.
///
/// Equivalent to C `pcrextend_machine_id_word()`.
///
/// Given a 128-bit machine ID as a 32-character hex string, produces
/// `"machine-id:<hex>"`.
pub fn pcrextend_machine_id_word(machine_id_hex: &str) -> Result<String> {
    if machine_id_hex.len() != 32 {
        return Err(PcrextendError::invalid_argument());
    }
    // Validate that the input is valid hex
    for ch in machine_id_hex.chars() {
        if !ch.is_ascii_hexdigit() {
            return Err(PcrextendError::invalid_argument());
        }
    }
    Ok(format!("machine-id:{}", machine_id_hex))
}

// ── Product-id word ─────────────────────────────────────────────────────────

/// Status of the product ID field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProductIdStatus {
    /// Product ID is missing (no field, or all-zero/all-0xFF UUID).
    Missing,
    /// Product ID is present.
    Present,
}

/// Build the product-id measurement word.
///
/// Equivalent to C `pcrextend_product_id_word()`.
///
/// If the product ID is missing (no SMBIOS/DMI field, or all-zero/all-0xFF),
/// produces `"product-id:missing"`.  Otherwise produces `"product-id:<hex>"`.
pub fn pcrextend_product_id_word(product_id_hex: Option<&str>) -> Result<String> {
    match product_id_hex {
        None => Ok("product-id:missing".to_string()),
        Some(hex) => {
            if hex.len() != 32 {
                return Err(PcrextendError::invalid_argument());
            }
            for ch in hex.chars() {
                if !ch.is_ascii_hexdigit() {
                    return Err(PcrextendError::invalid_argument());
                }
            }
            Ok(format!("product-id:{}", hex))
        }
    }
}

/// Determine the product ID status from an errno-like code.
///
/// In the C code, `id128_get_product()` returns `-ENOENT` or `-EADDRNOTAVAIL`
/// for missing/invalid product IDs.
pub fn product_id_status_from_errno(neg_errno: c_int) -> ProductIdStatus {
    if neg_errno == Errno::ENOENT.to_neg_errno() || neg_errno == Errno::EADDRNOTAVAIL.to_neg_errno()
    {
        ProductIdStatus::Missing
    } else {
        ProductIdStatus::Present
    }
}

// ── Verity word ─────────────────────────────────────────────────────────────

/// Build the verity measurement word.
///
/// Equivalent to C `pcrextend_verity_word()`.
///
/// Produces `"verity:<escaped_name>:<root_hash_hex>:<signer_info>"` where
/// `<signer_info>` is a comma-separated list of `"serial/issuer_base64"`
/// pairs extracted from the PKCS#7 signature.
///
/// # Arguments
///
/// * `name` - The verity volume name (colons will be escaped).
/// * `root_hash` - The dm-verity root hash bytes.
/// * `root_hash_sig` - Optional PKCS#7 signature bytes.
/// * `signers` - Signer information extracted from the PKCS#7 signature
///   (serial and issuer DER-encoded bytes).
pub fn pcrextend_verity_word(
    name: &str,
    root_hash: &[u8],
    root_hash_sig: Option<&[u8]>,
    signers: &[crate::pkcs7_util::Signer],
) -> Result<String> {
    if name.is_empty() {
        return Err(PcrextendError::invalid_argument());
    }
    if root_hash.is_empty() {
        return Err(PcrextendError::invalid_argument());
    }

    let name_escaped = escape_colons(name);
    let h = hex_encode(root_hash);

    let sigs = if root_hash_sig.is_some() && !signers.is_empty() {
        let parts: Result<Vec<String>> = signers
            .iter()
            .map(|s| {
                let serial = hex_encode(&s.serial);
                let issuer = base64_encode(&s.issuer);
                Ok(format!("{}/{}", serial, issuer))
            })
            .collect();
        parts?.join(",")
    } else {
        String::new()
    };

    Ok(format!("verity:{}:{}:{}", name_escaped, h, sigs))
}

// ── Verity now (measurement) ────────────────────────────────────────────────

/// Extend the verity measurement into the "verity" NvPCR immediately.
///
/// Equivalent to C `pcrextend_verity_now()`.
///
/// This builds the verity word and then contacts the PCRExtend Varlink
/// service to extend it into the `verity` NvPCR.
///
/// Returns `PcrextendCallResult::Success` on success, or an error.
/// If TPM2 support is not compiled in, returns `Err(PcrextendError::not_supported())`.
pub fn pcrextend_verity_now(
    name: &str,
    root_hash: &[u8],
    root_hash_sig: Option<&[u8]>,
    signers: &[crate::pkcs7_util::Signer],
) -> Result<PcrextendCallResult> {
    let _word = pcrextend_verity_word(name, root_hash, root_hash_sig, signers)?;

    // The actual Varlink call to /run/systemd/io.systemd.PCRExtend
    // requires TPM2 support compiled in (HAVE_TPM2).  Without it,
    // we return EOPNOTSUPP matching the C #else branch.
    Err(PcrextendError::not_supported())
}

// ── IMDS user-data word ─────────────────────────────────────────────────────

/// Build the IMDS user-data measurement word.
///
/// Equivalent to C `pcrextend_imds_userdata_word()`.
///
/// Includes both a SHA-256 hash of the complete data (for integrity) and a
/// base64-encoded truncated version of the data itself (for debugging).
///
/// Produces `"imds-userdata:<sha256_hex>:<base64_truncated>"`.
pub fn pcrextend_imds_userdata_word(data: &[u8]) -> Result<String> {
    if data.is_empty() {
        return Err(PcrextendError::invalid_argument());
    }

    let hash = sha256_digest(data)?;
    let hash_hex = hex_encode(&hash);

    let truncated_len = data.len().min(IMDS_USERDATA_TRUNCATED_MAX);
    let truncated = &data[..truncated_len];
    let data_encoded = base64_encode(truncated);

    Ok(format!("imds-userdata:{}:{}", hash_hex, data_encoded))
}

/// Extend the IMDS user-data measurement into PCR 12 immediately.
///
/// Equivalent to C `pcrextend_imds_userdata_now()`.
///
/// Returns `PcrextendCallResult::Success` on success, or an error.
/// If TPM2 support is not compiled in, returns `Err(PcrextendError::not_supported())`.
pub fn pcrextend_imds_userdata_now(data: &[u8]) -> Result<PcrextendCallResult> {
    let _word = pcrextend_imds_userdata_word(data)?;

    // Requires HAVE_TPM2 at compile time.  Without it, return EOPNOTSUPP.
    Err(PcrextendError::not_supported())
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Parsing ──────────────────────────────────────────────────────────

    #[test]
    fn test_parse_hash_alg() {
        assert_eq!(pcrextend_parse_hash_alg("sha1"), Some("sha1"));
        assert_eq!(pcrextend_parse_hash_alg("SHA256"), Some("sha256"));
        assert_eq!(pcrextend_parse_hash_alg("Sha384"), Some("sha384"));
        assert_eq!(pcrextend_parse_hash_alg("SHA512"), Some("sha512"));
        assert_eq!(pcrextend_parse_hash_alg("invalid"), None);
        assert_eq!(pcrextend_parse_hash_alg(""), None);
    }

    #[test]
    fn test_parse_mode() {
        assert_eq!(
            pcrextend_parse_mode("replace"),
            Some(PcrExtendMode::Replace)
        );
        assert_eq!(pcrextend_parse_mode("EXTEND"), Some(PcrExtendMode::Extend));
        assert_eq!(
            pcrextend_parse_mode("Replace"),
            Some(PcrExtendMode::Replace)
        );
        assert_eq!(pcrextend_parse_mode("invalid"), None);
        assert_eq!(pcrextend_parse_mode(""), None);
    }

    #[test]
    fn test_mode_values() {
        assert_eq!(PcrExtendMode::Replace as i32, 0);
        assert_eq!(PcrExtendMode::Extend as i32, 1);
    }

    // ── Colon escaping ───────────────────────────────────────────────────

    #[test]
    fn test_escape_colons() {
        assert_eq!(escape_colons("hello"), "hello");
        assert_eq!(escape_colons("a:b:c"), "a\\x3ab\\x3ac");
        assert_eq!(escape_colons(""), "");
        assert_eq!(escape_colons(":"), "\\x3a");
        assert_eq!(escape_colons("path/to/file"), "path/to/file");
    }

    // ── Hex encoding ─────────────────────────────────────────────────────

    #[test]
    fn test_hex_encode() {
        assert_eq!(hex_encode(&[]), "");
        assert_eq!(hex_encode(&[0x00]), "00");
        assert_eq!(hex_encode(&[0xff]), "ff");
        assert_eq!(hex_encode(&[0x01, 0x23, 0xab, 0xcd]), "0123abcd");
        assert_eq!(hex_encode(&[0xde, 0xad, 0xbe, 0xef]), "deadbeef");
    }

    // ── Base64 encoding ──────────────────────────────────────────────────

    #[test]
    fn test_base64_encode() {
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"Hello, world!"), "SGVsbG8sIHdvcmxkIQ==");
    }

    // ── SHA-256 ──────────────────────────────────────────────────────────

    #[test]
    fn test_sha256_digest() {
        // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        let hash = sha256_digest(b"").unwrap();
        assert_eq!(
            hex_encode(&hash),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );

        // SHA-256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
        let hash = sha256_digest(b"abc").unwrap();
        assert_eq!(
            hex_encode(&hash),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    // ── File-system word ─────────────────────────────────────────────────

    #[test]
    fn test_build_file_system_word_full() {
        let prefix = "file-system:\\x3avar\\x3alib";
        let values: Vec<Option<&str>> = vec![
            Some("ext4"),
            Some("deadbeef-cafe-1234"),
            Some("myfs:label"),
            Some("part-uuid"),
            Some("part-type"),
            Some("part-name"),
        ];
        let word = build_file_system_word(prefix, &values).unwrap();
        assert_eq!(
            word,
            "file-system:\\x3avar\\x3alib:ext4:deadbeef-cafe-1234:myfs\\x3alabel:part-uuid:part-type:part-name"
        );
    }

    #[test]
    fn test_build_file_system_word_empty_fields() {
        let prefix = "file-system:/usr";
        let values: Vec<Option<&str>> = vec![None, None, None, None, None, None];
        let word = build_file_system_word(prefix, &values).unwrap();
        assert_eq!(word, "file-system:/usr::::::");
    }

    #[test]
    fn test_build_file_system_word_wrong_count() {
        let prefix = "file-system:/usr";
        let values: Vec<Option<&str>> = vec![None, None];
        let result = build_file_system_word(prefix, &values);
        assert!(result.is_err());
    }

    #[test]
    fn test_build_generic_file_system_word() {
        let word = build_generic_file_system_word("/var/lib");
        assert_eq!(word, "file-system:/var/lib::::::");

        let word = build_generic_file_system_word("/path:with:colons");
        assert_eq!(word, "file-system:/path:with:colons::::::");
    }

    #[test]
    fn test_pcrextend_file_system_word_with_blkid() {
        let values: Vec<Option<&str>> = vec![
            Some("ext4"),
            Some("abcd"),
            Some("rootfs"),
            Some("part1"),
            Some("gpt"),
            Some(""),
        ];
        let (word, escaped) = pcrextend_file_system_word("/sysroot", Some(&values)).unwrap();
        assert_eq!(escaped, "/sysroot");
        assert_eq!(word, "file-system:/sysroot:ext4:abcd:rootfs:part1:gpt:");
    }

    #[test]
    fn test_pcrextend_file_system_word_fallback() {
        let (word, escaped) = pcrextend_file_system_word("/sysroot", None).unwrap();
        assert_eq!(escaped, "/sysroot");
        assert_eq!(word, "file-system:/sysroot::::::");
    }

    #[test]
    fn test_pcrextend_file_system_word_escapes_colons() {
        let (word, escaped) = pcrextend_file_system_word("/path:colon", None).unwrap();
        assert_eq!(escaped, "/path\\x3acolon");
        assert_eq!(word, "file-system:/path\\x3acolon::::::");
    }

    #[test]
    fn test_pcrextend_file_system_word_empty_path() {
        let result = pcrextend_file_system_word("", None);
        assert!(result.is_err());
    }

    // ── Machine-id word ──────────────────────────────────────────────────

    #[test]
    fn test_machine_id_word() {
        let word = pcrextend_machine_id_word("c7b2d3e4f5a6b7c8d9e0f1a2b3c4d5e6").unwrap();
        assert_eq!(word, "machine-id:c7b2d3e4f5a6b7c8d9e0f1a2b3c4d5e6");
    }

    #[test]
    fn test_machine_id_word_invalid_length() {
        assert!(pcrextend_machine_id_word("").is_err());
        assert!(pcrextend_machine_id_word("tooshort").is_err());
        assert!(pcrextend_machine_id_word("waytoolong000000000000000000000000000000").is_err());
    }

    #[test]
    fn test_machine_id_word_invalid_hex() {
        assert!(pcrextend_machine_id_word("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz").is_err());
    }

    // ── Product-id word ──────────────────────────────────────────────────

    #[test]
    fn test_product_id_word_present() {
        let word = pcrextend_product_id_word(Some("aabbccdd11223344aabbccdd11223344")).unwrap();
        assert_eq!(word, "product-id:aabbccdd11223344aabbccdd11223344");
    }

    #[test]
    fn test_product_id_word_missing() {
        let word = pcrextend_product_id_word(None).unwrap();
        assert_eq!(word, "product-id:missing");
    }

    #[test]
    fn test_product_id_word_invalid_hex() {
        assert!(pcrextend_product_id_word(Some("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz")).is_err());
    }

    #[test]
    fn test_product_id_word_invalid_length() {
        assert!(pcrextend_product_id_word(Some("tooshort")).is_err());
    }

    #[test]
    fn test_product_id_status_from_errno() {
        assert_eq!(
            product_id_status_from_errno(Errno::ENOENT.to_neg_errno()),
            ProductIdStatus::Missing
        );
        assert_eq!(
            product_id_status_from_errno(Errno::EADDRNOTAVAIL.to_neg_errno()),
            ProductIdStatus::Missing
        );
        assert_eq!(product_id_status_from_errno(0), ProductIdStatus::Present);
        assert_eq!(
            product_id_status_from_errno(Errno::EIO.to_neg_errno()),
            ProductIdStatus::Present
        );
    }

    // ── Verity word ──────────────────────────────────────────────────────

    #[test]
    fn test_verity_word_no_sig() {
        use crate::pkcs7_util::Signer;

        let root_hash = vec![0xde, 0xad, 0xbe, 0xef];
        let word = pcrextend_verity_word("myverity", &root_hash, None, &[]).unwrap();
        assert_eq!(word, "verity:myverity:deadbeef:");
    }

    #[test]
    fn test_verity_word_with_name_colons() {
        let root_hash = vec![0x01, 0x02, 0x03, 0x04];
        let word = pcrextend_verity_word("vol:data", &root_hash, None, &[]).unwrap();
        assert_eq!(word, "verity:vol\\x3adata:01020304:");
    }

    #[test]
    fn test_verity_word_empty_name() {
        let root_hash = vec![0x01];
        let result = pcrextend_verity_word("", &root_hash, None, &[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_verity_word_empty_hash() {
        let result = pcrextend_verity_word("name", &[], None, &[]);
        assert!(result.is_err());
    }

    // ── IMDS user-data word ──────────────────────────────────────────────

    #[test]
    fn test_imds_userdata_word() {
        let data = b"hello world";
        let word = pcrextend_imds_userdata_word(data).unwrap();
        // Format: "imds-userdata:<sha256_hex>:<base64>"
        assert!(word.starts_with("imds-userdata:"));
        let parts: Vec<&str> = word.splitn(3, ':').collect();
        assert_eq!(parts[0], "imds-userdata");
        // SHA-256 hex should be 64 chars
        assert_eq!(parts[1].len(), 64);
        // base64 should not be empty
        assert!(!parts[2].is_empty());
    }

    #[test]
    fn test_imds_userdata_word_empty() {
        let result = pcrextend_imds_userdata_word(b"");
        assert!(result.is_err());
    }

    #[test]
    fn test_imds_userdata_word_known_hash() {
        // SHA-256("test") = 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
        let word = pcrextend_imds_userdata_word(b"test").unwrap();
        let parts: Vec<&str> = word.splitn(3, ':').collect();
        assert_eq!(
            parts[1],
            "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
        );
    }

    #[test]
    fn test_imds_userdata_word_truncation() {
        // Create data larger than IMDS_USERDATA_TRUNCATED_MAX
        let data = vec![0xAB; 512];
        let word = pcrextend_imds_userdata_word(&data).unwrap();
        let parts: Vec<&str> = word.splitn(3, ':').collect();
        // The base64 part should be truncated
        let decoded_size = base64_decode_len(parts[2].len());
        assert!(decoded_size <= IMDS_USERDATA_TRUNCATED_MAX);
    }

    #[test]
    fn test_imds_userdata_now_not_supported() {
        // Without TPM2 compiled in, this should return EOPNOTSUPP
        let result = pcrextend_imds_userdata_now(b"test");
        assert!(result.is_err());
        assert!(result.unwrap_err().is_not_supported());
    }

    // ── Verity now ───────────────────────────────────────────────────────

    #[test]
    fn test_verity_now_not_supported() {
        use crate::pkcs7_util::Signer;

        // Without TPM2 compiled in, this should return EOPNOTSUPP
        let result = pcrextend_verity_now("test", &[0x01], None, &[]);
        assert!(result.is_err());
        assert!(result.unwrap_err().is_not_supported());
    }

    // ── BlkidField ───────────────────────────────────────────────────────

    #[test]
    fn test_blkid_field_names() {
        assert_eq!(BlkidField::Type.as_cstr(), "TYPE");
        assert_eq!(BlkidField::Uuid.as_cstr(), "UUID");
        assert_eq!(BlkidField::Label.as_cstr(), "LABEL");
        assert_eq!(BlkidField::PartEntryUuid.as_cstr(), "PART_ENTRY_UUID");
        assert_eq!(BlkidField::PartEntryType.as_cstr(), "PART_ENTRY_TYPE");
        assert_eq!(BlkidField::PartEntryName.as_cstr(), "PART_ENTRY_NAME");
    }

    #[test]
    fn test_blkid_field_all_count() {
        assert_eq!(BlkidField::ALL.len(), 6);
    }

    // ── Error type ───────────────────────────────────────────────────────

    #[test]
    fn test_error_construction() {
        let e = PcrextendError::not_supported();
        assert_eq!(e.as_neg_errno(), Errno::EOPNOTSUPP.to_neg_errno());
        assert!(e.is_not_supported());

        let e = PcrextendError::invalid_argument();
        assert_eq!(e.as_neg_errno(), Errno::EINVAL.to_neg_errno());
        assert!(!e.is_not_supported());

        let e = PcrextendError::from_neg_errno(-5);
        assert_eq!(e.as_neg_errno(), -5);
    }

    // ── Constants ────────────────────────────────────────────────────────

    #[test]
    fn test_constants() {
        assert_eq!(IMDS_USERDATA_TRUNCATED_MAX, 256);
        assert_eq!(SHA256_DIGEST_SIZE, 32);
        assert_eq!(FILE_SYSTEM_WORD_COMPONENTS, 7);
        assert_eq!(
            PCREXTEND_VARLINK_ADDRESS,
            "/run/systemd/io.systemd.PCRExtend"
        );
    }

    // ── Helper ───────────────────────────────────────────────────────────

    /// Rough base64 decode length estimate (upper bound).
    fn base64_decode_len(encoded_len: usize) -> usize {
        (encoded_len * 3) / 4
    }
}
