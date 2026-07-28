// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/libsystemd/sd-id128/sd-id128.c, src/libsystemd/sd-id128/id128-util.c
//
// 128-bit ID utilities.

use crate::sha256_hmac::sha256;

// ── Constants ─────────────────────────────────────────────────────────────

pub const SD_ID128_STRING_MAX: usize = 33;
pub const SD_ID128_UUID_STRING_MAX: usize = 37;

// ── Types ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct SdId128(pub [u8; 16]);

impl SdId128 {
    pub const NULL: Self = Self([0; 16]);
    pub const ALLF: Self = Self([0xff; 16]);

    pub fn is_null(self) -> bool {
        self == Self::NULL
    }

    pub fn is_allf(self) -> bool {
        self == Self::ALLF
    }

    pub fn compare(self, other: Self) -> i32 {
        for (a, b) in self.0.iter().zip(other.0.iter()) {
            if a != b {
                return i32::from(*a) - i32::from(*b);
            }
        }
        0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Id128Error {
    InvalidArgument,
    NoSuchDevice,
}

impl std::fmt::Display for Id128Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidArgument => write!(f, "invalid 128-bit identifier"),
            Self::NoSuchDevice => write!(f, "null 128-bit identifier rejected"),
        }
    }
}

impl std::error::Error for Id128Error {}

// ── Helpers ───────────────────────────────────────────────────────────────

#[inline]
fn hexchar(x: u8) -> u8 {
    if x < 10 { b'0' + x } else { b'a' + (x - 10) }
}

#[inline]
fn unhexchar(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

// ── Formatting ────────────────────────────────────────────────────────────

pub fn id128_to_string(id: SdId128) -> String {
    let mut out = [0u8; SD_ID128_STRING_MAX - 1];

    for (i, b) in id.0.iter().enumerate() {
        out[i * 2] = hexchar(b >> 4);
        out[i * 2 + 1] = hexchar(b & 0x0f);
    }

    String::from_utf8(out.to_vec()).expect("hex output is valid UTF-8")
}

pub fn id128_to_uuid_string(id: SdId128) -> String {
    let mut out = [0u8; SD_ID128_UUID_STRING_MAX - 1];
    let mut k = 0;

    for (n, b) in id.0.iter().enumerate() {
        if matches!(n, 4 | 6 | 8 | 10) {
            out[k] = b'-';
            k += 1;
        }

        out[k] = hexchar(b >> 4);
        out[k + 1] = hexchar(b & 0x0f);
        k += 2;
    }

    String::from_utf8(out.to_vec()).expect("uuid output is valid UTF-8")
}

// ── Parsing ───────────────────────────────────────────────────────────────

pub fn id128_from_string(s: &str) -> Result<SdId128, Id128Error> {
    let bytes = s.as_bytes();
    let mut t = [0u8; 16];
    let mut n = 0usize;
    let mut i = 0usize;
    let mut is_guid = false;

    while n < t.len() {
        let Some(&c) = bytes.get(i) else {
            return Err(Id128Error::InvalidArgument);
        };

        if c == b'-' {
            if i == 8 {
                is_guid = true;
            } else if matches!(i, 13 | 18 | 23) {
                if !is_guid {
                    return Err(Id128Error::InvalidArgument);
                }
            } else {
                return Err(Id128Error::InvalidArgument);
            }

            i += 1;
            continue;
        }

        let a = unhexchar(c).ok_or(Id128Error::InvalidArgument)?;
        i += 1;

        let b = bytes
            .get(i)
            .copied()
            .and_then(unhexchar)
            .ok_or(Id128Error::InvalidArgument)?;
        i += 1;

        t[n] = (a << 4) | b;
        n += 1;
    }

    let expected = if is_guid {
        SD_ID128_UUID_STRING_MAX - 1
    } else {
        SD_ID128_STRING_MAX - 1
    };

    if i != expected || i != bytes.len() {
        return Err(Id128Error::InvalidArgument);
    }

    Ok(SdId128(t))
}

pub fn id128_from_string_nonzero(s: &str) -> Result<SdId128, Id128Error> {
    let id = id128_from_string(s)?;
    if id.is_null() {
        return Err(Id128Error::NoSuchDevice);
    }
    Ok(id)
}

pub fn id128_is_valid(s: &str) -> bool {
    let plain_len = SD_ID128_STRING_MAX - 1;
    let uuid_len = SD_ID128_UUID_STRING_MAX - 1;

    match s.len() {
        len if len == plain_len => s.as_bytes().iter().all(|c| unhexchar(*c).is_some()),
        len if len == uuid_len => s.as_bytes().iter().enumerate().all(|(i, c)| {
            if matches!(i, 8 | 13 | 18 | 23) {
                *c == b'-'
            } else {
                unhexchar(*c).is_some()
            }
        }),
        _ => false,
    }
}

pub fn id128_string_equal(s: Option<&str>, id: SdId128) -> Result<bool, Id128Error> {
    let s = s.ok_or(Id128Error::InvalidArgument)?;
    Ok(id128_from_string(s)? == id)
}

// ── Mutation and digest ───────────────────────────────────────────────────

pub fn id128_make_v4_uuid(mut id: SdId128) -> SdId128 {
    id.0[6] = (id.0[6] & 0x0f) | 0x40;
    id.0[8] = (id.0[8] & 0x3f) | 0x80;
    id
}

pub fn id128_digest(data: &[u8]) -> SdId128 {
    let hash = sha256(data);
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&hash[..16]);
    id128_make_v4_uuid(SdId128(bytes))
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_id() -> SdId128 {
        SdId128([
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
            0x32, 0x10,
        ])
    }

    #[test]
    fn string_roundtrip_plain() {
        let id = sample_id();
        let s = id128_to_string(id);
        assert_eq!(s, "0123456789abcdeffedcba9876543210");
        assert_eq!(id128_from_string(&s).unwrap(), id);
    }

    #[test]
    fn string_roundtrip_uuid() {
        let id = sample_id();
        let s = id128_to_uuid_string(id);
        assert_eq!(s, "01234567-89ab-cdef-fedc-ba9876543210");
        assert_eq!(id128_from_string(&s).unwrap(), id);
    }

    #[test]
    fn from_string_rejects_bad_lengths() {
        assert_eq!(id128_from_string(""), Err(Id128Error::InvalidArgument));
        assert_eq!(
            id128_from_string("0123456789abcdef"),
            Err(Id128Error::InvalidArgument)
        );
    }

    #[test]
    fn from_string_rejects_bad_characters() {
        assert_eq!(
            id128_from_string("0123456789abcdef0123456789abcdeg"),
            Err(Id128Error::InvalidArgument)
        );
        assert_eq!(
            id128_from_string("01234567-89ab-cdef-0123-456789abcdeg"),
            Err(Id128Error::InvalidArgument)
        );
    }

    #[test]
    fn from_string_nonzero_rejects_null() {
        assert_eq!(
            id128_from_string_nonzero("00000000000000000000000000000000"),
            Err(Id128Error::NoSuchDevice)
        );
    }

    #[test]
    fn validity_matches_c_rules() {
        assert!(id128_is_valid("0123456789abcdef0123456789abcdef"));
        assert!(id128_is_valid("01234567-89ab-cdef-0123-456789abcdef"));
        assert!(!id128_is_valid("01234567_89ab_cdef_0123_456789abcdef"));
        assert!(!id128_is_valid("g123456789abcdef0123456789abcdef"));
    }

    #[test]
    fn string_equal_is_fallible() {
        let id = sample_id();
        assert!(id128_string_equal(Some("0123456789abcdeffedcba9876543210"), id).unwrap());
        assert_eq!(
            id128_string_equal(None, id),
            Err(Id128Error::InvalidArgument)
        );
        assert_eq!(
            id128_string_equal(Some("invalid"), id),
            Err(Id128Error::InvalidArgument)
        );
    }

    #[test]
    fn compare_matches_memcmp_ordering() {
        let a = SdId128([1; 16]);
        let b = SdId128([1; 16]);
        let c = SdId128([2; 16]);
        assert_eq!(a.compare(b), 0);
        assert!(a.compare(c) < 0);
        assert!(c.compare(a) > 0);
    }

    #[test]
    fn make_v4_uuid_sets_version_and_variant() {
        let id = id128_make_v4_uuid(SdId128([0xff; 16]));
        assert_eq!(id.0[6] & 0xf0, 0x40);
        assert_eq!(id.0[8] & 0xc0, 0x80);
    }

    #[test]
    fn digest_matches_sha256_prefix() {
        let digest = id128_digest(b"abc");
        let expected = sha256(b"abc");
        assert_eq!(&digest.0[..6], &expected[..6]);
        assert_eq!(digest.0[6] & 0xf0, 0x40);
        assert_eq!(digest.0[8] & 0xc0, 0x80);
    }
}
