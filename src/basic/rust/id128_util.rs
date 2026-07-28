// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: scope=basic.id128-util; authority=src/libsystemd/sd-id128/sd-id128.c,src/libsystemd/sd-id128/id128-util.c,src/libsystemd/sd-id128/id128-util.h,src/systemd/sd-id128.h,src/fundamental/sha256.c,src/fundamental/sha256.h
//
// 128-bit ID utilities.

use crate::ffi;
use crate::sha256_hmac::sha256;
use std::ffi::{CStr, c_char, c_void};
use std::mem::{align_of, size_of};
use std::ptr;

// ── Constants ─────────────────────────────────────────────────────────────

pub const SD_ID128_STRING_MAX: usize = 33;
pub const SD_ID128_UUID_STRING_MAX: usize = 37;

// ── Types ─────────────────────────────────────────────────────────────────

/// ABI representation of C's `sd_id128_t` union.
///
/// C exposes the same sixteen bytes both as `uint8_t[16]` and as
/// `uint64_t[2]`. The zero-sized trailing field keeps this Rust `repr(C)`
/// struct aligned exactly like the C union's `uint64_t` member without
/// changing its sixteen-byte size. Consequently it is safe to pass this type
/// by value across the C ABI on every target supported by the corresponding C
/// headers.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct SdId128 {
    pub bytes: [u8; 16],
    _qword_alignment: [u64; 0],
}

const _: () = {
    assert!(size_of::<SdId128>() == 16);
    assert!(align_of::<SdId128>() == align_of::<u64>());
};

impl SdId128 {
    pub const NULL: Self = Self::from_bytes([0; 16]);
    pub const ALLF: Self = Self::from_bytes([0xff; 16]);

    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self {
            bytes,
            _qword_alignment: [],
        }
    }

    pub fn is_null(self) -> bool {
        self == Self::NULL
    }

    pub fn is_allf(self) -> bool {
        self == Self::ALLF
    }

    pub fn compare(self, other: Self) -> i32 {
        for (a, b) in self.bytes.iter().zip(other.bytes.iter()) {
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

    for (i, b) in id.bytes.iter().enumerate() {
        out[i * 2] = hexchar(b >> 4);
        out[i * 2 + 1] = hexchar(b & 0x0f);
    }

    String::from_utf8(out.to_vec()).expect("hex output is valid UTF-8")
}

pub fn id128_to_uuid_string(id: SdId128) -> String {
    let mut out = [0u8; SD_ID128_UUID_STRING_MAX - 1];
    let mut k = 0;

    for (n, b) in id.bytes.iter().enumerate() {
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

fn id128_from_bytes(bytes: &[u8]) -> Result<SdId128, Id128Error> {
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

    Ok(SdId128::from_bytes(t))
}

pub fn id128_from_string(s: &str) -> Result<SdId128, Id128Error> {
    id128_from_bytes(s.as_bytes())
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
    id.bytes[6] = (id.bytes[6] & 0x0f) | 0x40;
    id.bytes[8] = (id.bytes[8] & 0x3f) | 0x80;
    id
}

pub fn id128_digest(data: &[u8]) -> SdId128 {
    let hash = sha256(data);
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&hash[..16]);
    id128_make_v4_uuid(SdId128::from_bytes(bytes))
}

// ── C ABI facades ────────────────────────────────────────────────────────

fn write_id128_string(id: SdId128, output: &mut [u8], uuid: bool) {
    let mut k = 0;

    for (n, byte) in id.bytes.into_iter().enumerate() {
        if uuid && matches!(n, 4 | 6 | 8 | 10) {
            output[k] = b'-';
            k += 1;
        }

        output[k] = hexchar(byte >> 4);
        output[k + 1] = hexchar(byte & 0x0f);
        k += 2;
    }

    output[k] = 0;
}

/// ABI facade for `sd_id128_to_string()`.
///
/// # Safety
/// When non-null, `s` must designate a writable C buffer of at least
/// `SD_ID128_STRING_MAX` bytes. The returned pointer is the caller-owned
/// input buffer; no allocation occurs.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_sd_id128_to_string(id: SdId128, s: *mut c_char) -> *mut c_char {
    if s.is_null() {
        return ptr::null_mut();
    }

    // SAFETY: the entry point contract guarantees this exact writable buffer.
    let output = unsafe { &mut *s.cast::<[u8; SD_ID128_STRING_MAX]>() };
    write_id128_string(id, output, false);
    s
}

/// ABI facade for `sd_id128_to_uuid_string()`.
///
/// # Safety
/// When non-null, `s` must designate a writable C buffer of at least
/// `SD_ID128_UUID_STRING_MAX` bytes. The returned pointer is the caller-owned
/// input buffer; no allocation occurs.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_sd_id128_to_uuid_string(id: SdId128, s: *mut c_char) -> *mut c_char {
    if s.is_null() {
        return ptr::null_mut();
    }

    // SAFETY: the entry point contract guarantees this exact writable buffer.
    let output = unsafe { &mut *s.cast::<[u8; SD_ID128_UUID_STRING_MAX]>() };
    write_id128_string(id, output, true);
    s
}

/// ABI facade for `sd_id128_from_string()`.
///
/// # Safety
/// A non-null `s` must point to a live NUL-terminated C byte string. A
/// non-null `ret` must point to writable `sd_id128_t`-layout storage. As in C,
/// `ret` is optional and is written only after successful parsing.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_sd_id128_from_string(s: *const c_char, ret: *mut SdId128) -> i32 {
    if s.is_null() {
        return -libc::EINVAL;
    }

    // SAFETY: the entry point contract guarantees a live NUL-terminated input.
    let parsed = match id128_from_bytes(unsafe { CStr::from_ptr(s) }.to_bytes()) {
        Ok(parsed) => parsed,
        Err(Id128Error::InvalidArgument | Id128Error::NoSuchDevice) => return -libc::EINVAL,
    };

    if !ret.is_null() {
        // SAFETY: the entry point contract guarantees writable output storage.
        unsafe { ret.write(parsed) };
    }

    0
}

/// ABI facade for `sd_id128_string_equal()`.
///
/// # Safety
/// When non-null, `s` must point to a live NUL-terminated C byte string for
/// the duration of the call. A null string is accepted and compares unequal,
/// exactly as the C function does.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_sd_id128_string_equal(s: *const c_char, id: SdId128) -> i32 {
    if s.is_null() {
        return 0;
    }

    // SAFETY: the entry point contract guarantees a live NUL-terminated input.
    match id128_from_bytes(unsafe { CStr::from_ptr(s) }.to_bytes()) {
        Ok(parsed) => i32::from(parsed == id),
        Err(Id128Error::InvalidArgument | Id128Error::NoSuchDevice) => -libc::EINVAL,
    }
}

/// ABI facade for `id128_from_string_nonzero()`.
///
/// # Safety
/// A non-null `s` must point to a live NUL-terminated C byte string. A
/// non-null `ret` must point to writable `sd_id128_t`-layout storage. C
/// asserts both pointers; this safe ABI boundary instead rejects either null
/// pointer with `-EINVAL` and does not publish output.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_id128_from_string_nonzero(s: *const c_char, ret: *mut SdId128) -> i32 {
    if s.is_null() || ret.is_null() {
        return -libc::EINVAL;
    }

    // SAFETY: the entry point contract guarantees a live NUL-terminated input.
    let parsed = match id128_from_bytes(unsafe { CStr::from_ptr(s) }.to_bytes()) {
        Ok(parsed) => parsed,
        Err(Id128Error::InvalidArgument | Id128Error::NoSuchDevice) => return -libc::EINVAL,
    };
    if parsed.is_null() {
        return -libc::ENXIO;
    }

    // SAFETY: the entry point contract guarantees writable output storage.
    unsafe { ret.write(parsed) };
    0
}

/// ABI facade for `id128_make_v4_uuid()`.
#[unsafe(no_mangle)]
pub extern "C" fn rs_id128_make_v4_uuid(id: SdId128) -> SdId128 {
    id128_make_v4_uuid(id)
}

/// ABI facade for `id128_compare_func()`.
///
/// # Safety
/// `a` and `b` must each point to at least sixteen readable bytes with the C
/// `sd_id128_t` layout. C delegates directly to `memcmp`; the same libc call
/// is retained so its exact result value, not merely its sign, is preserved.
/// Invalid null inputs are outside C's contract and return zero here rather
/// than dereferencing an invalid pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_id128_compare_func(a: *const SdId128, b: *const SdId128) -> i32 {
    if a.is_null() || b.is_null() {
        return 0;
    }

    // SAFETY: the entry point contract guarantees both sixteen-byte regions.
    unsafe { ffi::memcmp(a.cast::<c_void>(), b.cast::<c_void>(), size_of::<SdId128>()) }
}

/// ABI facade for the inline `sd_id128_equal()` accessor.
#[unsafe(no_mangle)]
pub extern "C" fn rs_sd_id128_equal(a: SdId128, b: SdId128) -> i32 {
    i32::from(a == b)
}

/// ABI facade for the inline `sd_id128_is_null()` accessor.
#[unsafe(no_mangle)]
pub extern "C" fn rs_sd_id128_is_null(a: SdId128) -> i32 {
    i32::from(a.is_null())
}

/// ABI facade for `id128_digest()`.
///
/// # Safety
/// For a finite `size`, a non-null `data` must point to at least `size`
/// readable bytes. For `size == SIZE_MAX`, `data` must instead be a live
/// NUL-terminated C byte string, matching C's sentinel-length rule. A null
/// pointer is valid only with a zero size; other null inputs violate C's
/// assertion and return `SD_ID128_NULL` here without dereferencing them.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_id128_digest(data: *const c_void, size: usize) -> SdId128 {
    if size == 0 {
        return id128_digest(&[]);
    }
    if data.is_null() {
        return SdId128::NULL;
    }

    let input = if size == usize::MAX {
        // SAFETY: the entry point contract guarantees a live NUL-terminated input.
        unsafe { CStr::from_ptr(data.cast::<c_char>()) }.to_bytes()
    } else {
        // SAFETY: the entry point contract guarantees this readable byte range.
        unsafe { std::slice::from_raw_parts(data.cast::<u8>(), size) }
    };

    id128_digest(input)
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_id() -> SdId128 {
        SdId128::from_bytes([
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
        let a = SdId128::from_bytes([1; 16]);
        let b = SdId128::from_bytes([1; 16]);
        let c = SdId128::from_bytes([2; 16]);
        assert_eq!(a.compare(b), 0);
        assert!(a.compare(c) < 0);
        assert!(c.compare(a) > 0);
    }

    #[test]
    fn make_v4_uuid_sets_version_and_variant() {
        let id = id128_make_v4_uuid(SdId128::from_bytes([0xff; 16]));
        assert_eq!(id.bytes[6] & 0xf0, 0x40);
        assert_eq!(id.bytes[8] & 0xc0, 0x80);
    }

    #[test]
    fn digest_matches_sha256_prefix() {
        let digest = id128_digest(b"abc");
        let expected = sha256(b"abc");
        assert_eq!(&digest.bytes[..6], &expected[..6]);
        assert_eq!(digest.bytes[6] & 0xf0, 0x40);
        assert_eq!(digest.bytes[8] & 0xc0, 0x80);
    }
}
