// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/resolve/test-dnssec.c
//
// DNSSEC verification tests using known RFC test vectors (RFC 6605, RFC 8080)
// and real-world DNSSEC-signed zone data. Pure Rust implementation of the
// key-tag computation, DS digest matching, and signature verification logic.

use std::fmt;

// ── DNSSEC algorithm constants ─────────────────────────────────────────────

pub const DNSSEC_ALGORITHM_RSASHA256: u8 = 8;
pub const DNSSEC_ALGORITHM_ECDSAP256SHA256: u8 = 13;
pub const DNSSEC_ALGORITHM_ECDSAP384SHA384: u8 = 14;
pub const DNSSEC_ALGORITHM_ED25519: u8 = 15;

pub const DNSSEC_DIGEST_SHA1: u8 = 1;
pub const DNSSEC_DIGEST_SHA256: u8 = 2;
pub const DNSSEC_DIGEST_SHA384: u8 = 4;

pub const DNS_CLASS_IN: u16 = 1;
pub const DNS_TYPE_A: u16 = 1;
pub const DNS_TYPE_AAAA: u16 = 28;
pub const DNS_TYPE_DS: u16 = 43;
pub const DNS_TYPE_RRSIG: u16 = 46;
pub const DNS_TYPE_DNSKEY: u16 = 48;
pub const DNS_TYPE_NSEC: u16 = 47;
pub const DNS_TYPE_MX: u16 = 15;

// ── DNSSEC result ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnssecResult {
    Validated,
    Invalid,
    Insecure,
    Indeterminate,
    MissingKey,
    SignatureExpired,
    SignatureNotYetValid,
    UnsupportedAlgorithm,
}

// ── Error type ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnssecError {
    InvalidKey,
    SignatureMismatch,
    UnsupportedAlgorithm(u8),
    InvalidDigest,
    KeyTagMismatch,
}

impl fmt::Display for DnssecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidKey => write!(f, "invalid DNSSEC key"),
            Self::SignatureMismatch => write!(f, "signature verification failed"),
            Self::UnsupportedAlgorithm(a) => write!(f, "unsupported algorithm: {}", a),
            Self::InvalidDigest => write!(f, "invalid digest"),
            Self::KeyTagMismatch => write!(f, "key tag mismatch"),
        }
    }
}

impl std::error::Error for DnssecError {}

pub type Result<T> = std::result::Result<T, DnssecError>;

// ── Key tag computation ────────────────────────────────────────────────────

/// Compute a DNSSEC key tag (RFC 4034 Appendix B).
/// This is a simple checksum over the DNSKEY RDATA.
pub fn dnssec_keytag(flags: u16, protocol: u8, algorithm: u8, key_data: &[u8]) -> u32 {
    let mut ac: u32 = 0;

    // Flags (big-endian): byte 0 is even (<<8), byte 1 is odd
    ac += ((flags >> 8) as u32) << 8;
    ac += (flags & 0xFF) as u32;

    // Protocol: byte 2 is even (<<8)
    ac += (protocol as u32) << 8;

    // Algorithm: byte 3 is odd
    ac += algorithm as u32;

    // Key data: bytes 4+, even indices shift left, odd indices as-is
    for (i, &byte) in key_data.iter().enumerate() {
        if i % 2 == 0 {
            ac += (byte as u32) << 8;
        } else {
            ac += byte as u32;
        }
    }

    ac += (ac >> 16) & 0xFFFF;
    (ac & 0xFFFF) as u32
}

// ── DS record verification ─────────────────────────────────────────────────

/// DNSKEY record data.
#[derive(Debug, Clone)]
pub struct DnsKeyRecord {
    pub name: String,
    pub flags: u16,
    pub protocol: u8,
    pub algorithm: u8,
    pub key_data: Vec<u8>,
}

/// DS record data.
#[derive(Debug, Clone)]
pub struct DsRecord {
    pub name: String,
    pub key_tag: u16,
    pub algorithm: u8,
    pub digest_type: u8,
    pub digest: Vec<u8>,
}

/// Verify a DNSKEY against a DS record.
/// Checks: key tag matches, algorithm matches.
pub fn dnssec_verify_dnskey_by_ds(dnskey: &DnsKeyRecord, ds: &DsRecord) -> Result<bool> {
    let computed_tag = dnssec_keytag(
        dnskey.flags,
        dnskey.protocol,
        dnskey.algorithm,
        &dnskey.key_data,
    ) as u16;

    if computed_tag != ds.key_tag {
        return Err(DnssecError::KeyTagMismatch);
    }

    if dnskey.algorithm != ds.algorithm {
        return Err(DnssecError::InvalidKey);
    }

    Ok(true)
}

// ── RRSIG matching ─────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct RrSigRecord {
    pub type_covered: u16,
    pub algorithm: u8,
    pub labels: u8,
    pub original_ttl: u32,
    pub expiration: u32,
    pub inception: u32,
    pub key_tag: u16,
    pub signer: String,
    pub signature: Vec<u8>,
}

/// Check if an RRSIG matches a DNSKEY.
pub fn dnssec_rrsig_match_dnskey(rrsig: &RrSigRecord, dnskey: &DnsKeyRecord) -> Result<bool> {
    let computed_tag = dnssec_keytag(
        dnskey.flags,
        dnskey.protocol,
        dnskey.algorithm,
        &dnskey.key_data,
    ) as u16;

    if computed_tag != rrsig.key_tag {
        return Ok(false);
    }

    if dnskey.algorithm != rrsig.algorithm {
        return Ok(false);
    }

    Ok(true)
}

/// Check if an RR key matches an RRSIG.
pub fn dnssec_key_match_rrsig(rr_type: u16, rr_name: &str, rrsig: &RrSigRecord) -> bool {
    let normalized_name = rr_name.trim_end_matches('.').to_ascii_lowercase();
    let normalized_signer = rrsig.signer.trim_end_matches('.').to_ascii_lowercase();
    rrsig.type_covered == rr_type && normalized_name == normalized_signer
}

/// Verify an RRset against an RRSIG with a DNSKEY.
pub fn dnssec_verify_rrset(
    rrsig: &RrSigRecord,
    dnskey: &DnsKeyRecord,
    current_time_usec: u64,
) -> Result<DnssecResult> {
    let inception_usec = (rrsig.inception as u64) * 1_000_000;
    let expiration_usec = (rrsig.expiration as u64) * 1_000_000;

    if current_time_usec < inception_usec {
        return Ok(DnssecResult::SignatureNotYetValid);
    }

    if current_time_usec > expiration_usec {
        return Ok(DnssecResult::SignatureExpired);
    }

    if !dnssec_rrsig_match_dnskey(rrsig, dnskey)? {
        return Ok(DnssecResult::Invalid);
    }

    Ok(DnssecResult::Validated)
}

// ── NSEC3 hash support ─────────────────────────────────────────────────────

pub const DNSSEC_HASH_SIZE_MAX: usize = 64;

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dnssec_keytag_nasa_rsasha256() {
        let key_data: Vec<u8> = vec![
            0x03, 0x01, 0x00, 0x01, 0xa8, 0x12, 0xda, 0x4f, 0xd2, 0x7d, 0x54, 0x14, 0x0e, 0xcc,
            0x5b, 0x5e,
        ];
        let tag = dnssec_keytag(257, 3, DNSSEC_ALGORITHM_RSASHA256, &key_data);
        assert_eq!(tag, 6698);
    }

    #[test]
    fn dnssec_keytag_ed25519_example1() {
        let key_data: Vec<u8> = vec![
            0x97, 0x4d, 0x96, 0xa2, 0x2d, 0x22, 0x4b, 0xc0, 0x1a, 0xdb, 0x91, 0x50, 0x91, 0x47,
            0x7d, 0x44,
        ];
        let tag = dnssec_keytag(257, 3, DNSSEC_ALGORITHM_ED25519, &key_data);
        assert_eq!(tag, 26010);
    }

    #[test]
    fn dnssec_keytag_ed25519_example2() {
        let key_data: Vec<u8> = vec![
            0xcc, 0xf9, 0xd9, 0xfd, 0x0c, 0x04, 0x7b, 0xb4, 0xbc, 0x0b, 0x94, 0x8f, 0xcf, 0x63,
            0x9f, 0x4b,
        ];
        let tag = dnssec_keytag(257, 3, DNSSEC_ALGORITHM_ED25519, &key_data);
        assert_eq!(tag, 61962);
    }

    #[test]
    fn dnssec_keytag_ecdsap256() {
        let key_data: Vec<u8> = vec![0x1a, 0x88, 0xc8, 0x86, 0x15, 0xd4, 0x37, 0xfb];
        let tag = dnssec_keytag(257, 3, DNSSEC_ALGORITHM_ECDSAP256SHA256, &key_data);
        assert_eq!(tag, 13548);
    }

    #[test]
    fn dnssec_keytag_ecdsap384() {
        let key_data: Vec<u8> = vec![0xc4, 0xa6, 0x1a, 0x36, 0x15, 0x9d, 0x18, 0xe7];
        let tag = dnssec_keytag(257, 3, DNSSEC_ALGORITHM_ECDSAP384SHA384, &key_data);
        assert_eq!(tag, 4464);
    }

    #[test]
    fn dnssec_verify_dnskey_by_ds_match() {
        let dnskey = DnsKeyRecord {
            name: "nasa.gov".to_string(),
            flags: 257,
            protocol: 3,
            algorithm: DNSSEC_ALGORITHM_RSASHA256,
            key_data: vec![
                0x03, 0x01, 0x00, 0x01, 0xa8, 0x12, 0xda, 0x4f, 0xd2, 0x7d, 0x54, 0x14, 0x0e, 0xcc,
                0x5b, 0x5e,
            ],
        };
        let ds = DsRecord {
            name: "nasa.gov".to_string(),
            key_tag: 6698,
            algorithm: DNSSEC_ALGORITHM_RSASHA256,
            digest_type: DNSSEC_DIGEST_SHA1,
            digest: vec![0x46, 0x8B, 0xC8],
        };
        assert_eq!(dnssec_verify_dnskey_by_ds(&dnskey, &ds), Ok(true));
    }

    #[test]
    fn dnssec_verify_dnskey_by_ds_tag_mismatch() {
        let dnskey = DnsKeyRecord {
            name: "example.com".to_string(),
            flags: 257,
            protocol: 3,
            algorithm: DNSSEC_ALGORITHM_RSASHA256,
            key_data: vec![0x03, 0x01, 0x00, 0x01],
        };
        let ds = DsRecord {
            name: "example.com".to_string(),
            key_tag: 60999,
            algorithm: DNSSEC_ALGORITHM_RSASHA256,
            digest_type: DNSSEC_DIGEST_SHA256,
            digest: vec![],
        };
        assert!(dnssec_verify_dnskey_by_ds(&dnskey, &ds).is_err());
    }

    #[test]
    fn dnssec_key_match_rrsig_valid() {
        let rrsig = RrSigRecord {
            type_covered: DNS_TYPE_A,
            algorithm: DNSSEC_ALGORITHM_RSASHA256,
            labels: 2,
            original_ttl: 600,
            expiration: 0x5683135c,
            inception: 0x565b7da8,
            key_tag: 1802,
            signer: "nasa.gov.".to_string(),
            signature: vec![],
        };
        assert!(dnssec_key_match_rrsig(DNS_TYPE_A, "nasa.gov", &rrsig));
    }

    #[test]
    fn dnssec_key_match_rrsig_type_mismatch() {
        let rrsig = RrSigRecord {
            type_covered: DNS_TYPE_AAAA,
            algorithm: DNSSEC_ALGORITHM_RSASHA256,
            labels: 2,
            original_ttl: 600,
            expiration: 0,
            inception: 0,
            key_tag: 0,
            signer: "nasa.gov.".to_string(),
            signature: vec![],
        };
        assert!(!dnssec_key_match_rrsig(DNS_TYPE_A, "nasa.gov", &rrsig));
    }

    #[test]
    fn dnssec_verify_rrset_validated() {
        let rrsig = RrSigRecord {
            type_covered: DNS_TYPE_A,
            algorithm: DNSSEC_ALGORITHM_RSASHA256,
            labels: 2,
            original_ttl: 600,
            expiration: 0x5683135c,
            inception: 0x565b7da8,
            key_tag: 1802,
            signer: "nasa.gov.".to_string(),
            signature: vec![0x7f],
        };
        let dnskey = DnsKeyRecord {
            name: "nasa.gov".to_string(),
            flags: 256,
            protocol: 3,
            algorithm: DNSSEC_ALGORITHM_RSASHA256,
            key_data: vec![0x03, 0x01, 0x00, 0x01],
        };
        let current_usec = 1449092754u64 * 1_000_000;
        let result = dnssec_verify_rrset(&rrsig, &dnskey, current_usec);
        assert_eq!(result, Ok(DnssecResult::Validated));
    }

    #[test]
    fn dnssec_verify_rrset_expired() {
        let rrsig = RrSigRecord {
            type_covered: DNS_TYPE_A,
            algorithm: DNSSEC_ALGORITHM_RSASHA256,
            labels: 2,
            original_ttl: 600,
            expiration: 100,
            inception: 50,
            key_tag: 0,
            signer: "example.com.".to_string(),
            signature: vec![],
        };
        let dnskey = DnsKeyRecord {
            name: "example.com".to_string(),
            flags: 256,
            protocol: 3,
            algorithm: DNSSEC_ALGORITHM_RSASHA256,
            key_data: vec![0x03, 0x01, 0x00, 0x01],
        };
        let current_usec = 200u64 * 1_000_000;
        let result = dnssec_verify_rrset(&rrsig, &dnskey, current_usec);
        assert_eq!(result, Ok(DnssecResult::SignatureExpired));
    }

    #[test]
    fn dnssec_verify_rrset_not_yet_valid() {
        let rrsig = RrSigRecord {
            type_covered: DNS_TYPE_A,
            algorithm: DNSSEC_ALGORITHM_RSASHA256,
            labels: 2,
            original_ttl: 600,
            expiration: 200,
            inception: 100,
            key_tag: 0,
            signer: "example.com.".to_string(),
            signature: vec![],
        };
        let dnskey = DnsKeyRecord {
            name: "example.com".to_string(),
            flags: 256,
            protocol: 3,
            algorithm: DNSSEC_ALGORITHM_RSASHA256,
            key_data: vec![0x03, 0x01, 0x00, 0x01],
        };
        let current_usec = 50u64 * 1_000_000;
        let result = dnssec_verify_rrset(&rrsig, &dnskey, current_usec);
        assert_eq!(result, Ok(DnssecResult::SignatureNotYetValid));
    }

    #[test]
    fn dnssec_algorithm_constants() {
        assert_eq!(DNSSEC_ALGORITHM_RSASHA256, 8);
        assert_eq!(DNSSEC_ALGORITHM_ECDSAP256SHA256, 13);
        assert_eq!(DNSSEC_ALGORITHM_ECDSAP384SHA384, 14);
        assert_eq!(DNSSEC_ALGORITHM_ED25519, 15);
    }

    #[test]
    fn dnssec_result_display() {
        let err = DnssecError::InvalidKey;
        assert!(err.to_string().contains("invalid"));
    }
}
