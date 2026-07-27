// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/openssl-util.c, src/shared/openssl-util.h
//
// OpenSSL utility functions for cryptographic operations.

use crate::ffi::Errno;

// ── Error type ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenSslError {
    pub code: i32,
}

impl OpenSslError {
    pub fn from_neg_errno(neg: i32) -> Self {
        Self { code: neg }
    }

    pub fn not_supported() -> Self {
        Self {
            code: Errno::EOPNOTSUPP.to_neg_errno(),
        }
    }

    pub fn invalid_argument() -> Self {
        Self {
            code: Errno::EINVAL.to_neg_errno(),
        }
    }

    pub fn io_error() -> Self {
        Self {
            code: Errno::EIO.to_neg_errno(),
        }
    }

    pub fn out_of_memory() -> Self {
        Self {
            code: Errno::ENOMEM.to_neg_errno(),
        }
    }

    pub fn bad_message() -> Self {
        Self {
            code: Errno::EBADMSG.to_neg_errno(),
        }
    }

    pub fn is_not_supported(&self) -> bool {
        self.code == Errno::EOPNOTSUPP.to_neg_errno()
    }

    pub fn is_invalid_argument(&self) -> bool {
        self.code == Errno::EINVAL.to_neg_errno()
    }
}

impl std::fmt::Display for OpenSslError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "OpenSSL error (errno {})", self.code)
    }
}

impl std::error::Error for OpenSslError {}

pub type Result<T> = std::result::Result<T, OpenSslError>;

// ── Constants ───────────────────────────────────────────────────────────────

pub const X509_FINGERPRINT_SIZE: usize = 32;

// ── Enums ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum CertificateSourceType {
    File = 0,
    Provider = 1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum KeySourceType {
    File = 0,
    Engine = 1,
    Provider = 2,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateSource {
    pub source: Option<String>,
    pub source_type: CertificateSourceType,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeySource {
    pub source: Option<String>,
    pub source_type: KeySourceType,
}

// ── Digest utilities ────────────────────────────────────────────────────────

static DIGEST_TABLE: &[(&str, usize)] = &[
    ("SHA256", 32),
    ("SHA-256", 32),
    ("SHA384", 48),
    ("SHA-384", 48),
    ("SHA512", 64),
    ("SHA-512", 64),
    ("SHA224", 28),
    ("SHA-224", 28),
    ("SHA1", 20),
    ("SHA-1", 20),
    ("MD5", 16),
];

pub fn digest_size(digest_alg: &str) -> Result<usize> {
    let upper = digest_alg.to_uppercase();
    for &(name, size) in DIGEST_TABLE {
        if upper == name.to_uppercase() {
            return Ok(size);
        }
    }
    Err(OpenSslError::not_supported())
}

pub fn digest_size_for_alg(alg: &str) -> Result<usize> {
    digest_size(alg)
}

pub fn hex_encode(data: &[u8]) -> String {
    let mut s = String::with_capacity(data.len() * 2);
    for b in data {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

pub fn compute_hash(data: &[u8], alg: &str) -> Result<Vec<u8>> {
    use openssl::hash::{hash, MessageDigest};

    let md = match alg.to_uppercase().as_str() {
        "SHA256" | "SHA-256" => MessageDigest::sha256(),
        "SHA384" | "SHA-384" => MessageDigest::sha384(),
        "SHA512" | "SHA-512" => MessageDigest::sha512(),
        "SHA224" | "SHA-224" => MessageDigest::sha224(),
        "SHA1" | "SHA-1" => MessageDigest::sha1(),
        "MD5" => MessageDigest::md5(),
        _ => return Err(OpenSslError::not_supported()),
    };

    let digest = hash(md, data).map_err(|_| OpenSslError::io_error())?;
    let expected = digest_size(alg)?;
    let result = digest.to_vec();
    if result.len() != expected {
        return Err(OpenSslError::io_error());
    }
    Ok(result)
}

pub fn string_hashsum(s: &str, len: usize, md_algorithm: &str) -> Result<String> {
    let data = if len == 0 || len == usize::MAX {
        s.as_bytes()
    } else {
        &s.as_bytes()[..len.min(s.len())]
    };
    let hash = compute_hash(data, md_algorithm)?;
    Ok(hex_encode(&hash))
}

pub fn string_hashsum_full(s: &str, md_algorithm: &str) -> Result<String> {
    string_hashsum(s, usize::MAX, md_algorithm)
}

// ── Argument parsing ────────────────────────────────────────────────────────

pub fn parse_certificate_source(argument: &str) -> Result<CertificateSource> {
    if argument.is_empty() {
        return Err(OpenSslError::invalid_argument());
    }
    if let Some(rest) = argument.strip_prefix("provider:") {
        Ok(CertificateSource {
            source: Some(rest.to_string()),
            source_type: CertificateSourceType::Provider,
        })
    } else if argument == "file" {
        Ok(CertificateSource {
            source: None,
            source_type: CertificateSourceType::File,
        })
    } else {
        Err(OpenSslError::invalid_argument())
    }
}

pub fn parse_key_source(argument: &str) -> Result<KeySource> {
    if argument.is_empty() {
        return Err(OpenSslError::invalid_argument());
    }
    if let Some(rest) = argument.strip_prefix("engine:") {
        Ok(KeySource {
            source: Some(rest.to_string()),
            source_type: KeySourceType::Engine,
        })
    } else if let Some(rest) = argument.strip_prefix("provider:") {
        Ok(KeySource {
            source: Some(rest.to_string()),
            source_type: KeySourceType::Provider,
        })
    } else if argument == "file" {
        Ok(KeySource {
            source: None,
            source_type: KeySourceType::File,
        })
    } else {
        Err(OpenSslError::invalid_argument())
    }
}

// ── RSA key size ────────────────────────────────────────────────────────────

pub fn rsa_pkey_to_suitable_key_size(bits: i32) -> Result<usize> {
    if bits <= 0 {
        return Err(OpenSslError::io_error());
    }
    let suitable_key_size = bits as usize / 8 / 2;
    if suitable_key_size < 1 {
        return Err(OpenSslError::io_error());
    }
    Ok(suitable_key_size)
}

// ── Public key fingerprint ──────────────────────────────────────────────────

pub fn pubkey_fingerprint(pk_data: &[u8], hash_alg: &str) -> Result<Vec<u8>> {
    compute_hash(pk_data, hash_alg)
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_digest_size_sha256_variants() {
        assert_eq!(digest_size("SHA256").unwrap(), 32);
        assert_eq!(digest_size("sha256").unwrap(), 32);
        assert_eq!(digest_size("SHA-256").unwrap(), 32);
        assert_eq!(digest_size("sha-256").unwrap(), 32);
    }

    #[test]
    fn test_digest_size_sha512_sha384_sha224() {
        assert_eq!(digest_size("SHA512").unwrap(), 64);
        assert_eq!(digest_size("SHA384").unwrap(), 48);
        assert_eq!(digest_size("SHA224").unwrap(), 28);
    }

    #[test]
    fn test_digest_size_sha1_md5() {
        assert_eq!(digest_size("SHA1").unwrap(), 20);
        assert_eq!(digest_size("SHA-1").unwrap(), 20);
        assert_eq!(digest_size("MD5").unwrap(), 16);
    }

    #[test]
    fn test_digest_size_unknown() {
        let err = digest_size("BLAKE2B").unwrap_err();
        assert!(err.is_not_supported());
        assert_eq!(err.code, Errno::EOPNOTSUPP.to_neg_errno());
    }

    #[test]
    fn test_digest_size_empty() {
        assert!(digest_size("").is_err());
    }

    #[test]
    fn test_hex_encode_basic() {
        assert_eq!(hex_encode(&[0x01, 0x23, 0xff]), "0123ff");
    }

    #[test]
    fn test_hex_encode_empty() {
        assert_eq!(hex_encode(&[]), "");
    }

    #[test]
    fn test_hex_encode_all_zeros() {
        assert_eq!(hex_encode(&[0x00, 0x00, 0x00]), "000000");
    }

    #[test]
    fn test_compute_hash_sha256_hello() {
        let result = compute_hash(b"hello", "SHA256").unwrap();
        assert_eq!(result.len(), 32);
        assert_eq!(
            hex_encode(&result),
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn test_compute_hash_sha1_hello() {
        let result = compute_hash(b"hello", "SHA1").unwrap();
        assert_eq!(result.len(), 20);
        assert_eq!(
            hex_encode(&result),
            "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"
        );
    }

    #[test]
    fn test_compute_hash_md5_hello() {
        let result = compute_hash(b"hello", "MD5").unwrap();
        assert_eq!(result.len(), 16);
        assert_eq!(hex_encode(&result), "5d41402abc4b2a76b9719d911017c592");
    }

    #[test]
    fn test_compute_hash_unknown_alg() {
        assert!(compute_hash(b"hello", "BLAKE2B").is_err());
    }

    #[test]
    fn test_string_hashsum_sha256() {
        let result = string_hashsum("hello", usize::MAX, "SHA256").unwrap();
        assert_eq!(result.len(), 64);
        assert_eq!(
            result,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn test_string_hashsum_sha512() {
        let result = string_hashsum("hello", usize::MAX, "SHA512").unwrap();
        assert_eq!(result.len(), 128);
    }

    #[test]
    fn test_string_hashsum_with_len() {
        let result = string_hashsum("hello world", 5, "SHA256").unwrap();
        assert_eq!(result.len(), 64);
        assert_eq!(
            result,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn test_string_hashsum_zero_len_hashes_full() {
        let result = string_hashsum("hello", 0, "SHA256").unwrap();
        assert_eq!(result.len(), 64);
    }

    #[test]
    fn test_string_hashsum_full() {
        let result = string_hashsum_full("hello", "SHA256").unwrap();
        assert_eq!(
            result,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn test_parse_certificate_source_file() {
        let parsed = parse_certificate_source("file").unwrap();
        assert_eq!(parsed.source, None);
        assert_eq!(parsed.source_type, CertificateSourceType::File);
    }

    #[test]
    fn test_parse_certificate_source_provider() {
        let parsed = parse_certificate_source("provider:my-provider").unwrap();
        assert_eq!(parsed.source.as_deref(), Some("my-provider"));
        assert_eq!(parsed.source_type, CertificateSourceType::Provider);
    }

    #[test]
    fn test_parse_certificate_source_empty() {
        let err = parse_certificate_source("").unwrap_err();
        assert!(err.is_invalid_argument());
    }

    #[test]
    fn test_parse_certificate_source_invalid() {
        assert!(parse_certificate_source("http://bad").is_err());
        assert!(parse_certificate_source("engine:pkcs11").is_err());
    }

    #[test]
    fn test_parse_key_source_file() {
        let parsed = parse_key_source("file").unwrap();
        assert_eq!(parsed.source, None);
        assert_eq!(parsed.source_type, KeySourceType::File);
    }

    #[test]
    fn test_parse_key_source_engine() {
        let parsed = parse_key_source("engine:pkcs11").unwrap();
        assert_eq!(parsed.source.as_deref(), Some("pkcs11"));
        assert_eq!(parsed.source_type, KeySourceType::Engine);
    }

    #[test]
    fn test_parse_key_source_provider() {
        let parsed = parse_key_source("provider:my-provider").unwrap();
        assert_eq!(parsed.source.as_deref(), Some("my-provider"));
        assert_eq!(parsed.source_type, KeySourceType::Provider);
    }

    #[test]
    fn test_parse_key_source_invalid() {
        assert!(parse_key_source("http://bad").is_err());
        assert!(parse_key_source("").is_err());
    }

    #[test]
    fn test_rsa_suitable_key_size_2048() {
        assert_eq!(rsa_pkey_to_suitable_key_size(2048).unwrap(), 128);
    }

    #[test]
    fn test_rsa_suitable_key_size_4096() {
        assert_eq!(rsa_pkey_to_suitable_key_size(4096).unwrap(), 256);
    }

    #[test]
    fn test_rsa_suitable_key_size_too_small() {
        assert!(rsa_pkey_to_suitable_key_size(8).is_err());
        assert!(rsa_pkey_to_suitable_key_size(0).is_err());
        assert!(rsa_pkey_to_suitable_key_size(-1).is_err());
    }

    #[test]
    fn test_pubkey_fingerprint_basic() {
        let data = b"test public key data";
        let result = pubkey_fingerprint(data, "SHA256").unwrap();
        assert_eq!(result.len(), 32);
    }

    #[test]
    fn test_certificate_source_type_values() {
        assert_eq!(CertificateSourceType::File as i32, 0);
        assert_eq!(CertificateSourceType::Provider as i32, 1);
    }

    #[test]
    fn test_key_source_type_values() {
        assert_eq!(KeySourceType::File as i32, 0);
        assert_eq!(KeySourceType::Engine as i32, 1);
        assert_eq!(KeySourceType::Provider as i32, 2);
    }

    #[test]
    fn test_x509_fingerprint_size() {
        assert_eq!(X509_FINGERPRINT_SIZE, 32);
    }

    #[test]
    fn test_openssl_error_constructors() {
        let err = OpenSslError::not_supported();
        assert!(err.is_not_supported());
        assert!(!err.is_invalid_argument());

        let err = OpenSslError::invalid_argument();
        assert!(err.is_invalid_argument());
        assert!(!err.is_not_supported());

        let err = OpenSslError::io_error();
        assert_eq!(err.code, Errno::EIO.to_neg_errno());

        let err = OpenSslError::out_of_memory();
        assert_eq!(err.code, Errno::ENOMEM.to_neg_errno());

        let err = OpenSslError::bad_message();
        assert_eq!(err.code, Errno::EBADMSG.to_neg_errno());
    }

    #[test]
    fn test_openssl_error_from_neg_errno() {
        let err = OpenSslError::from_neg_errno(Errno::EOPNOTSUPP.to_neg_errno());
        assert!(err.is_not_supported());
    }

    #[test]
    fn test_openssl_error_display() {
        let err = OpenSslError::not_supported();
        let msg = format!("{}", err);
        assert!(msg.contains("OpenSSL error"));
    }

    #[test]
    fn test_openssl_error_equality() {
        assert_eq!(OpenSslError::not_supported(), OpenSslError::not_supported());
        assert_ne!(
            OpenSslError::not_supported(),
            OpenSslError::invalid_argument()
        );
    }

    #[test]
    fn test_compute_hash_empty_data() {
        let result = compute_hash(b"", "SHA256").unwrap();
        assert_eq!(result.len(), 32);
    }

    #[test]
    fn test_compute_hash_sha384() {
        let result = compute_hash(b"test", "SHA384").unwrap();
        assert_eq!(result.len(), 48);
    }

    #[test]
    fn test_compute_hash_sha512() {
        let result = compute_hash(b"test", "SHA512").unwrap();
        assert_eq!(result.len(), 64);
    }

    #[test]
    fn test_compute_hash_sha224() {
        let result = compute_hash(b"test", "SHA224").unwrap();
        assert_eq!(result.len(), 28);
    }

    #[test]
    fn test_digest_size_for_alg_alias() {
        assert_eq!(digest_size_for_alg("SHA256").unwrap(), 32);
        assert_eq!(
            digest_size_for_alg("unknown").unwrap_err().code,
            Errno::EOPNOTSUPP.to_neg_errno()
        );
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests_round_trips {
    use super::*;

    #[test]
    fn test_digest_size_sha256_variants() {
        assert_eq!(digest_size("SHA256").unwrap(), 32);
        assert_eq!(digest_size("sha256").unwrap(), 32);
        assert_eq!(digest_size("SHA-256").unwrap(), 32);
        assert_eq!(digest_size("sha-256").unwrap(), 32);
    }

    #[test]
    fn test_digest_size_sha512_sha384_sha224() {
        assert_eq!(digest_size("SHA512").unwrap(), 64);
        assert_eq!(digest_size("SHA384").unwrap(), 48);
        assert_eq!(digest_size("SHA224").unwrap(), 28);
    }

    #[test]
    fn test_digest_size_sha1_md5() {
        assert_eq!(digest_size("SHA1").unwrap(), 20);
        assert_eq!(digest_size("SHA-1").unwrap(), 20);
        assert_eq!(digest_size("MD5").unwrap(), 16);
    }

    #[test]
    fn test_digest_size_unknown() {
        let err = digest_size("BLAKE2B").unwrap_err();
        assert!(err.is_not_supported());
        assert_eq!(err.code, Errno::EOPNOTSUPP.to_neg_errno());
    }

    #[test]
    fn test_digest_size_empty() {
        assert!(digest_size("").is_err());
    }

    #[test]
    fn test_hex_encode_basic() {
        assert_eq!(hex_encode(&[0x01, 0x23, 0xff]), "0123ff");
    }

    #[test]
    fn test_hex_encode_empty() {
        assert_eq!(hex_encode(&[]), "");
    }

    #[test]
    fn test_hex_encode_all_zeros() {
        assert_eq!(hex_encode(&[0x00, 0x00, 0x00]), "000000");
    }

    #[test]
    fn test_compute_hash_sha256_hello() {
        let result = compute_hash(b"hello", "SHA256").unwrap();
        assert_eq!(result.len(), 32);
        assert_eq!(
            hex_encode(&result),
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn test_compute_hash_sha1_hello() {
        let result = compute_hash(b"hello", "SHA1").unwrap();
        assert_eq!(result.len(), 20);
        assert_eq!(
            hex_encode(&result),
            "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"
        );
    }

    #[test]
    fn test_compute_hash_md5_hello() {
        let result = compute_hash(b"hello", "MD5").unwrap();
        assert_eq!(result.len(), 16);
        assert_eq!(hex_encode(&result), "5d41402abc4b2a76b9719d911017c592");
    }

    #[test]
    fn test_compute_hash_unknown_alg() {
        assert!(compute_hash(b"hello", "BLAKE2B").is_err());
    }

    #[test]
    fn test_string_hashsum_sha256() {
        let result = string_hashsum("hello", usize::MAX, "SHA256").unwrap();
        assert_eq!(result.len(), 64);
        assert_eq!(
            result,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn test_string_hashsum_sha512() {
        let result = string_hashsum("hello", usize::MAX, "SHA512").unwrap();
        assert_eq!(result.len(), 128);
    }

    #[test]
    fn test_string_hashsum_with_len() {
        let result = string_hashsum("hello world", 5, "SHA256").unwrap();
        assert_eq!(result.len(), 64);
        assert_eq!(
            result,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn test_string_hashsum_zero_len_hashes_full() {
        let result = string_hashsum("hello", 0, "SHA256").unwrap();
        assert_eq!(result.len(), 64);
    }

    #[test]
    fn test_string_hashsum_full() {
        let result = string_hashsum_full("hello", "SHA256").unwrap();
        assert_eq!(
            result,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn test_parse_certificate_source_file() {
        let parsed = parse_certificate_source("file").unwrap();
        assert_eq!(parsed.source, None);
        assert_eq!(parsed.source_type, CertificateSourceType::File);
    }

    #[test]
    fn test_parse_certificate_source_provider() {
        let parsed = parse_certificate_source("provider:my-provider").unwrap();
        assert_eq!(parsed.source.as_deref(), Some("my-provider"));
        assert_eq!(parsed.source_type, CertificateSourceType::Provider);
    }

    #[test]
    fn test_parse_certificate_source_empty() {
        let err = parse_certificate_source("").unwrap_err();
        assert!(err.is_invalid_argument());
    }

    #[test]
    fn test_parse_certificate_source_invalid() {
        assert!(parse_certificate_source("http://bad").is_err());
        assert!(parse_certificate_source("engine:pkcs11").is_err());
    }

    #[test]
    fn test_parse_key_source_file() {
        let parsed = parse_key_source("file").unwrap();
        assert_eq!(parsed.source, None);
        assert_eq!(parsed.source_type, KeySourceType::File);
    }

    #[test]
    fn test_parse_key_source_engine() {
        let parsed = parse_key_source("engine:pkcs11").unwrap();
        assert_eq!(parsed.source.as_deref(), Some("pkcs11"));
        assert_eq!(parsed.source_type, KeySourceType::Engine);
    }

    #[test]
    fn test_parse_key_source_provider() {
        let parsed = parse_key_source("provider:my-provider").unwrap();
        assert_eq!(parsed.source.as_deref(), Some("my-provider"));
        assert_eq!(parsed.source_type, KeySourceType::Provider);
    }

    #[test]
    fn test_parse_key_source_invalid() {
        assert!(parse_key_source("http://bad").is_err());
        assert!(parse_key_source("").is_err());
    }

    #[test]
    fn test_rsa_suitable_key_size_2048() {
        assert_eq!(rsa_pkey_to_suitable_key_size(2048).unwrap(), 128);
    }

    #[test]
    fn test_rsa_suitable_key_size_4096() {
        assert_eq!(rsa_pkey_to_suitable_key_size(4096).unwrap(), 256);
    }

    #[test]
    fn test_rsa_suitable_key_size_too_small() {
        assert!(rsa_pkey_to_suitable_key_size(8).is_err());
        assert!(rsa_pkey_to_suitable_key_size(0).is_err());
        assert!(rsa_pkey_to_suitable_key_size(-1).is_err());
    }

    #[test]
    fn test_pubkey_fingerprint_basic() {
        let data = b"test public key data";
        let result = pubkey_fingerprint(data, "SHA256").unwrap();
        assert_eq!(result.len(), 32);
    }

    #[test]
    fn test_certificate_source_type_values() {
        assert_eq!(CertificateSourceType::File as i32, 0);
        assert_eq!(CertificateSourceType::Provider as i32, 1);
    }

    #[test]
    fn test_key_source_type_values() {
        assert_eq!(KeySourceType::File as i32, 0);
        assert_eq!(KeySourceType::Engine as i32, 1);
        assert_eq!(KeySourceType::Provider as i32, 2);
    }

    #[test]
    fn test_x509_fingerprint_size() {
        assert_eq!(X509_FINGERPRINT_SIZE, 32);
    }

    #[test]
    fn test_openssl_error_constructors() {
        let err = OpenSslError::not_supported();
        assert!(err.is_not_supported());
        assert!(!err.is_invalid_argument());

        let err = OpenSslError::invalid_argument();
        assert!(err.is_invalid_argument());
        assert!(!err.is_not_supported());

        let err = OpenSslError::io_error();
        assert_eq!(err.code, Errno::EIO.to_neg_errno());

        let err = OpenSslError::out_of_memory();
        assert_eq!(err.code, Errno::ENOMEM.to_neg_errno());

        let err = OpenSslError::bad_message();
        assert_eq!(err.code, Errno::EBADMSG.to_neg_errno());
    }

    #[test]
    fn test_openssl_error_from_neg_errno() {
        let err = OpenSslError::from_neg_errno(Errno::EOPNOTSUPP.to_neg_errno());
        assert!(err.is_not_supported());
    }

    #[test]
    fn test_openssl_error_display() {
        let err = OpenSslError::not_supported();
        let msg = format!("{}", err);
        assert!(msg.contains("OpenSSL error"));
    }

    #[test]
    fn test_openssl_error_equality() {
        assert_eq!(OpenSslError::not_supported(), OpenSslError::not_supported());
        assert_ne!(
            OpenSslError::not_supported(),
            OpenSslError::invalid_argument()
        );
    }

    #[test]
    fn test_compute_hash_empty_data() {
        let result = compute_hash(b"", "SHA256").unwrap();
        assert_eq!(result.len(), 32);
    }

    #[test]
    fn test_compute_hash_sha384() {
        let result = compute_hash(b"test", "SHA384").unwrap();
        assert_eq!(result.len(), 48);
    }

    #[test]
    fn test_compute_hash_sha512() {
        let result = compute_hash(b"test", "SHA512").unwrap();
        assert_eq!(result.len(), 64);
    }

    #[test]
    fn test_compute_hash_sha224() {
        let result = compute_hash(b"test", "SHA224").unwrap();
        assert_eq!(result.len(), 28);
    }

    #[test]
    fn test_digest_size_for_alg_alias() {
        assert_eq!(digest_size_for_alg("SHA256").unwrap(), 32);
        assert_eq!(
            digest_size_for_alg("unknown").unwrap_err().code,
            Errno::EOPNOTSUPP.to_neg_errno()
        );
    }
}
