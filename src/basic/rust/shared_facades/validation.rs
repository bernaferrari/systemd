// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/compare-operator.c,src/shared/compare-operator.h,
//           src/shared/web-util.c,src/shared/web-util.h,src/shared/color-util.c,
//           src/shared/color-util.h,src/shared/boot-entry.c,src/shared/boot-entry.h,
//           src/shared/pkcs11-util.c,src/shared/pkcs11-util.h,src/shared/user-record.c,
//           src/shared/user-record.h
//
// Shared validation and conversion facades.

// Centralized unsafe expression boundary for this module.
macro_rules! unsafe_ffi {
    ($expression:expr) => {{
        // SAFETY: the enclosing helper documents and validates this operation.
        unsafe { $expression }
    }};
}
use libc::{c_char, c_int};
use std::ffi::CStr;

// ── Compare operators ─────────────────────────────────────────────────────

pub const COMPARE_ALLOW_FNMATCH: u32 = 1 << 0;
pub const COMPARE_EQUAL_BY_STRING: u32 = 1 << 1;
pub const COMPARE_ALLOW_TEXTUAL: u32 = 1 << 2;

#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompareOperator {
    StringEqual,
    StringUnequal,
    FnmatchEqual,
    FnmatchUnequal,
    LowerOrEqual,
    GreaterOrEqual,
    Lower,
    Greater,
    Equal,
    Unequal,
}

impl CompareOperator {
    const fn from_raw(value: c_int) -> Option<Self> {
        match value {
            0 => Some(Self::StringEqual),
            1 => Some(Self::StringUnequal),
            2 => Some(Self::FnmatchEqual),
            3 => Some(Self::FnmatchUnequal),
            4 => Some(Self::LowerOrEqual),
            5 => Some(Self::GreaterOrEqual),
            6 => Some(Self::Lower),
            7 => Some(Self::Greater),
            8 => Some(Self::Equal),
            9 => Some(Self::Unequal),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SharedValidatorsError {
    InvalidArgument,
    OutOfRange,
}

impl std::fmt::Display for SharedValidatorsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidArgument => write!(f, "invalid argument"),
            Self::OutOfRange => write!(f, "value out of range"),
        }
    }
}

impl std::error::Error for SharedValidatorsError {}

fn parse_compare_operator_bytes(s: &[u8], flags: u32) -> Option<(CompareOperator, usize)> {
    const TABLE: &[(CompareOperator, &[u8], u32, u32)] = &[
        (
            CompareOperator::FnmatchEqual,
            b"$=",
            COMPARE_ALLOW_FNMATCH,
            0,
        ),
        (
            CompareOperator::FnmatchUnequal,
            b"!$=",
            COMPARE_ALLOW_FNMATCH,
            0,
        ),
        (CompareOperator::Unequal, b"<>", 0, 0),
        (CompareOperator::LowerOrEqual, b"<=", 0, 0),
        (CompareOperator::GreaterOrEqual, b">=", 0, 0),
        (CompareOperator::Lower, b"<", 0, 0),
        (CompareOperator::Greater, b">", 0, 0),
        (CompareOperator::Equal, b"==", 0, 0),
        (
            CompareOperator::StringEqual,
            b"=",
            0,
            COMPARE_EQUAL_BY_STRING,
        ),
        (CompareOperator::Equal, b"=", 0, 0),
        (
            CompareOperator::StringUnequal,
            b"!=",
            0,
            COMPARE_EQUAL_BY_STRING,
        ),
        (CompareOperator::Unequal, b"!=", 0, 0),
        (CompareOperator::Lower, b"lt", COMPARE_ALLOW_TEXTUAL, 0),
        (
            CompareOperator::LowerOrEqual,
            b"le",
            COMPARE_ALLOW_TEXTUAL,
            0,
        ),
        (CompareOperator::Equal, b"eq", COMPARE_ALLOW_TEXTUAL, 0),
        (CompareOperator::Unequal, b"ne", COMPARE_ALLOW_TEXTUAL, 0),
        (
            CompareOperator::GreaterOrEqual,
            b"ge",
            COMPARE_ALLOW_TEXTUAL,
            0,
        ),
        (CompareOperator::Greater, b"gt", COMPARE_ALLOW_TEXTUAL, 0),
    ];

    for (op, token, valid_mask, need_mask) in TABLE {
        if *need_mask != 0 && flags & need_mask == 0 {
            continue;
        }
        if s.starts_with(token) {
            if *valid_mask != 0 && flags & valid_mask == 0 {
                return None;
            }
            return Some((*op, token.len()));
        }
    }

    None
}

pub fn parse_compare_operator(s: &str, flags: u32) -> Option<(CompareOperator, &str)> {
    let (operator, consumed) = parse_compare_operator_bytes(s.as_bytes(), flags)?;
    Some((operator, &s[consumed..]))
}

pub fn test_order(k: i32, op: CompareOperator) -> Result<bool, SharedValidatorsError> {
    match op {
        CompareOperator::Lower => Ok(k < 0),
        CompareOperator::LowerOrEqual => Ok(k <= 0),
        CompareOperator::Equal => Ok(k == 0),
        CompareOperator::Unequal => Ok(k != 0),
        CompareOperator::GreaterOrEqual => Ok(k >= 0),
        CompareOperator::Greater => Ok(k > 0),
        _ => Err(SharedValidatorsError::InvalidArgument),
    }
}

/// Parse a comparison operator and advance the caller's byte cursor.
///
/// # Safety
///
/// `s` must point to writable pointer storage. A non-null `*s` must point to
/// a live NUL-terminated byte string. The returned pointer always aliases the
/// original string and is never retained.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_parse_compare_operator(s: *mut *const c_char, flags: c_int) -> c_int {
    assert!(!s.is_null());

    // SAFETY: required by the entry-point contract and checked for null below.
    let input = unsafe_ffi!(*s);
    if input.is_null() {
        return -libc::EINVAL;
    }

    // SAFETY: the caller guarantees a live NUL-terminated byte string.
    let bytes = unsafe_ffi!(CStr::from_ptr(input)).to_bytes();
    let Some((operator, consumed)) = parse_compare_operator_bytes(bytes, flags as u32) else {
        return -libc::EINVAL;
    };

    // SAFETY: consumed is the length of an ASCII prefix within the same live
    // C string, and s points to writable pointer storage.
    unsafe_ffi!(*s = input.add(consumed));
    operator as c_int
}

#[unsafe(no_mangle)]
pub extern "C" fn rs_test_order(k: c_int, operator: c_int) -> c_int {
    let Some(operator) = CompareOperator::from_raw(operator) else {
        return -libc::EINVAL;
    };
    match test_order(k, operator) {
        Ok(value) => c_int::from(value),
        Err(SharedValidatorsError::InvalidArgument) => -libc::EINVAL,
        Err(SharedValidatorsError::OutOfRange) => -libc::ERANGE,
    }
}

// ── URL validators ────────────────────────────────────────────────────────

fn ascii_is_valid(s: &[u8]) -> bool {
    s.is_ascii()
}

pub fn http_etag_is_valid(etag: &str) -> bool {
    http_etag_is_valid_bytes(etag.as_bytes())
}

fn http_etag_is_valid_bytes(etag: &[u8]) -> bool {
    !etag.is_empty()
        && etag.ends_with(b"\"")
        && (etag.starts_with(b"\"") || etag.starts_with(b"W/\""))
}

pub fn http_url_is_valid(url: &str) -> bool {
    http_url_is_valid_bytes(url.as_bytes())
}

fn http_url_is_valid_bytes(url: &[u8]) -> bool {
    if url.is_empty() {
        return false;
    }

    let Some(rest) = url
        .strip_prefix(b"http://")
        .or_else(|| url.strip_prefix(b"https://"))
    else {
        return false;
    };

    !rest.is_empty() && ascii_is_valid(rest)
}

pub fn file_url_is_valid(url: &str) -> bool {
    file_url_is_valid_bytes(url.as_bytes())
}

fn file_url_is_valid_bytes(url: &[u8]) -> bool {
    let Some(rest) = url.strip_prefix(b"file:/") else {
        return false;
    };

    !rest.is_empty() && ascii_is_valid(rest)
}

pub fn documentation_url_is_valid(url: &str) -> bool {
    documentation_url_is_valid_bytes(url.as_bytes())
}

fn documentation_url_is_valid_bytes(url: &[u8]) -> bool {
    if url.is_empty() {
        return false;
    }
    if http_url_is_valid_bytes(url) || file_url_is_valid_bytes(url) {
        return true;
    }

    url.strip_prefix(b"info:")
        .or_else(|| url.strip_prefix(b"man:"))
        .is_some_and(|rest| !rest.is_empty() && ascii_is_valid(rest))
}

/// # Safety
/// A non-null `value` must point to a live NUL-terminated byte string for the
/// duration of `predicate`; the borrowed bytes cannot escape this call.
unsafe fn c_bytes_match(value: *const c_char, predicate: impl FnOnce(&[u8]) -> bool) -> bool {
    if value.is_null() {
        return false;
    }
    // SAFETY: callers uphold the live NUL-terminated input contract. The
    // borrowed bytes cannot escape this helper.
    predicate(unsafe_ffi!(CStr::from_ptr(value)).to_bytes())
}

/// # Safety
/// `etag` must be null or point to a live NUL-terminated byte string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_http_etag_is_valid(etag: *const c_char) -> bool {
    // SAFETY: forwarded from the entry-point contract.
    unsafe_ffi!(c_bytes_match(etag, http_etag_is_valid_bytes))
}

/// # Safety
/// `url` must be null or point to a live NUL-terminated byte string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_http_url_is_valid(url: *const c_char) -> bool {
    // SAFETY: forwarded from the entry-point contract.
    unsafe_ffi!(c_bytes_match(url, http_url_is_valid_bytes))
}

/// # Safety
/// `url` must be null or point to a live NUL-terminated byte string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_file_url_is_valid(url: *const c_char) -> bool {
    // SAFETY: forwarded from the entry-point contract.
    unsafe_ffi!(c_bytes_match(url, file_url_is_valid_bytes))
}

/// # Safety
/// `url` must be null or point to a live NUL-terminated byte string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_documentation_url_is_valid(url: *const c_char) -> bool {
    // SAFETY: forwarded from the entry-point contract.
    unsafe_ffi!(c_bytes_match(url, documentation_url_is_valid_bytes))
}

// ── Color conversion ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Hsv {
    pub h: f64,
    pub s: f64,
    pub v: f64,
}

pub fn rgb_to_hsv(r: f64, g: f64, b: f64) -> Result<Hsv, SharedValidatorsError> {
    if !(0.0..=1.0).contains(&r) || !(0.0..=1.0).contains(&g) || !(0.0..=1.0).contains(&b) {
        return Err(SharedValidatorsError::OutOfRange);
    }

    let max_color = r.max(g).max(b);
    let min_color = r.min(g).min(b);
    let delta = max_color - min_color;

    let v = max_color * 100.0;
    if max_color <= 0.0 {
        return Ok(Hsv {
            h: f64::NAN,
            s: 0.0,
            v,
        });
    }

    let s = delta / max_color * 100.0;
    let h = if delta > 0.0 {
        let raw = if r >= max_color {
            60.0 * ((g - b) / delta).rem_euclid(6.0)
        } else if g >= max_color {
            60.0 * (((b - r) / delta) + 2.0)
        } else {
            60.0 * (((r - g) / delta) + 4.0)
        };
        raw.rem_euclid(360.0)
    } else {
        f64::NAN
    };

    Ok(Hsv { h, s, v })
}

pub fn hsv_to_rgb(h: f64, s: f64, v: f64) -> Result<(u8, u8, u8), SharedValidatorsError> {
    if !(0.0..=360.0).contains(&h) || !(0.0..=100.0).contains(&s) || !(0.0..=100.0).contains(&v) {
        return Err(SharedValidatorsError::OutOfRange);
    }

    let h = h % 360.0;
    let c = (s / 100.0) * (v / 100.0);
    let x = c * (1.0 - ((h / 60.0).rem_euclid(2.0) - 1.0).abs());
    let m = (v / 100.0) - c;

    let (r, g, b) = if (0.0..60.0).contains(&h) {
        (c, x, 0.0)
    } else if (60.0..120.0).contains(&h) {
        (x, c, 0.0)
    } else if (120.0..180.0).contains(&h) {
        (0.0, c, x)
    } else if (180.0..240.0).contains(&h) {
        (0.0, x, c)
    } else if (240.0..300.0).contains(&h) {
        (x, 0.0, c)
    } else {
        (c, 0.0, x)
    };

    Ok((
        ((r + m) * 255.0) as u8,
        ((g + m) * 255.0) as u8,
        ((b + m) * 255.0) as u8,
    ))
}

/// # Safety
/// Each non-null output must point to writable `double` storage.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_rgb_to_hsv(
    r: f64,
    g: f64,
    b: f64,
    ret_h: *mut f64,
    ret_s: *mut f64,
    ret_v: *mut f64,
) {
    assert!((0.0..=1.0).contains(&r));
    assert!((0.0..=1.0).contains(&g));
    assert!((0.0..=1.0).contains(&b));
    let hsv = rgb_to_hsv(r, g, b).expect("checked RGB inputs must be in range");
    // Preserve C's publication order when optional output pointers alias.
    if !ret_v.is_null() {
        // SAFETY: guaranteed by the entry-point contract.
        unsafe_ffi!(*ret_v = hsv.v);
    }
    if !ret_s.is_null() {
        // SAFETY: guaranteed by the entry-point contract.
        unsafe_ffi!(*ret_s = hsv.s);
    }
    if !ret_h.is_null() {
        // SAFETY: guaranteed by the entry-point contract.
        unsafe_ffi!(*ret_h = hsv.h);
    }
}

/// # Safety
/// All three output pointers must reference writable byte storage.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_hsv_to_rgb(
    h: f64,
    s: f64,
    v: f64,
    ret_r: *mut u8,
    ret_g: *mut u8,
    ret_b: *mut u8,
) {
    assert!((0.0..=360.0).contains(&h));
    assert!((0.0..=100.0).contains(&s));
    assert!((0.0..=100.0).contains(&v));
    assert!(!ret_r.is_null());
    assert!(!ret_g.is_null());
    assert!(!ret_b.is_null());
    let (r, g, b) = hsv_to_rgb(h, s, v).expect("checked HSV inputs must be in range");
    // SAFETY: checked non-null above and required writable by the contract.
    unsafe_ffi!({
        *ret_r = r;
        *ret_g = g;
        *ret_b = b;
    })
}

// ── Misc validators ───────────────────────────────────────────────────────

fn filename_is_valid_bytes(name: &[u8]) -> bool {
    !name.is_empty()
        && name.len() <= 255
        && !matches!(name, b"." | b"..")
        && !name.contains(&b'/')
        && !name.contains(&0)
}

fn filename_is_valid(name: &str) -> bool {
    filename_is_valid_bytes(name.as_bytes())
}

fn string_is_safe(s: &str) -> bool {
    string_is_safe_bytes(s.as_bytes())
}

/// Byte-oriented mirror of `string_is_safe(p, STRING_FILENAME)`'s baseline
/// checks. The C helper requires valid UTF-8 and rejects quotes, backslashes,
/// and glob metacharacters unless explicitly allowed by flags.
fn string_is_safe_bytes(s: &[u8]) -> bool {
    std::str::from_utf8(s).is_ok()
        && !s.is_empty()
        && s.iter().copied().all(|b| {
            !(b > 0 && b < 0x20)
                && b != b'"'
                && b != b'\''
                && b != b'\\'
                && !b"*?[".contains(&b)
                && b != 0x7f
        })
}

pub fn boot_entry_token_valid(token: &str) -> bool {
    string_is_safe(token) && filename_is_valid(token)
}

fn boot_entry_token_valid_bytes(token: &[u8]) -> bool {
    string_is_safe_bytes(token) && filename_is_valid_bytes(token)
}

pub fn pkcs11_uri_valid(uri: &str) -> bool {
    let Some(rest) = uri.strip_prefix("pkcs11:") else {
        return false;
    };

    !rest.is_empty()
        && rest
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b".~/-_?;&%=".contains(&b))
}

fn pkcs11_uri_valid_bytes(uri: &[u8]) -> bool {
    let Some(rest) = uri.strip_prefix(b"pkcs11:") else {
        return false;
    };
    !rest.is_empty()
        && rest
            .iter()
            .copied()
            .all(|b| b.is_ascii_alphanumeric() || b".~/-_?;&%=".contains(&b))
}

/// # Safety
/// `token` must be null or point to a live NUL-terminated byte string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_boot_entry_token_valid(token: *const c_char) -> bool {
    // SAFETY: forwarded from the entry-point contract.
    unsafe_ffi!(c_bytes_match(token, boot_entry_token_valid_bytes))
}

/// # Safety
/// `uri` must be null or point to a live NUL-terminated byte string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_pkcs11_uri_valid(uri: *const c_char) -> bool {
    // SAFETY: forwarded from the entry-point contract.
    unsafe_ffi!(c_bytes_match(uri, pkcs11_uri_valid_bytes))
}

pub fn suitable_blob_filename(name: &str) -> bool {
    suitable_blob_filename_bytes(name.as_bytes())
}

/// Byte-oriented core of C's `suitable_blob_filename()`.
///
/// The C authority accepts a NUL-terminated byte string, not a Rust UTF-8
/// string. URI_UNRESERVED is ASCII-only, so validating bytes directly both
/// preserves that contract and fails closed for malformed UTF-8.
fn suitable_blob_filename_bytes(name: &[u8]) -> bool {
    filename_is_valid_bytes(name)
        && !name.starts_with(b".")
        && name
            .iter()
            .copied()
            .all(|b| b.is_ascii_alphanumeric() || b"-._~".contains(&b))
}

/// C ABI mirror of `suitable_blob_filename()` from `user-record.c`.
///
/// # Safety
///
/// `name` must be null or point to a live NUL-terminated C string for the
/// duration of this call. The input is borrowed and never retained. A null
/// pointer returns zero, matching `filename_is_valid(NULL)` in the C helper.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_suitable_blob_filename(name: *const c_char) -> i32 {
    let Some(name) = (!name.is_null()).then(|| {
        // SAFETY: the entry-point contract guarantees a live NUL-terminated
        // string after the explicit null check above.
        unsafe_ffi!(CStr::from_ptr(name))
    }) else {
        return 0;
    };

    i32::from(suitable_blob_filename_bytes(name.to_bytes()))
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn etag_validation_matches_c_shape() {
        assert!(http_etag_is_valid("\"abc\""));
        assert!(http_etag_is_valid("W/\"abc\""));
        assert!(!http_etag_is_valid("abc"));
        assert!(!http_etag_is_valid("\"abc"));
    }

    #[test]
    fn http_and_file_urls_require_ascii_payload() {
        assert!(http_url_is_valid("http://example.com"));
        assert!(http_url_is_valid("https://example.com"));
        assert!(!http_url_is_valid("http://"));
        assert!(file_url_is_valid("file:///tmp/x"));
        assert!(!file_url_is_valid("file:/"));
    }

    #[test]
    fn documentation_urls_accept_expected_schemes() {
        assert!(documentation_url_is_valid("http://example.com"));
        assert!(documentation_url_is_valid("file:///tmp/x"));
        assert!(documentation_url_is_valid("info:systemd"));
        assert!(documentation_url_is_valid("man:systemd.unit(5)"));
        assert!(!documentation_url_is_valid("ftp://example.com"));
    }

    #[test]
    fn rgb_to_hsv_matches_primary_colors() {
        let red = rgb_to_hsv(1.0, 0.0, 0.0).unwrap();
        let green = rgb_to_hsv(0.0, 1.0, 0.0).unwrap();
        let blue = rgb_to_hsv(0.0, 0.0, 1.0).unwrap();
        assert!((red.h - 0.0).abs() < 0.01);
        assert!((green.h - 120.0).abs() < 0.01);
        assert!((blue.h - 240.0).abs() < 0.01);
    }

    #[test]
    fn hsv_to_rgb_wraps_like_c() {
        assert_eq!(hsv_to_rgb(0.0, 100.0, 100.0).unwrap(), (255, 0, 0));
        assert_eq!(hsv_to_rgb(120.0, 100.0, 100.0).unwrap(), (0, 255, 0));
        assert_eq!(hsv_to_rgb(240.0, 100.0, 100.0).unwrap(), (0, 0, 255));
        assert_eq!(hsv_to_rgb(360.0, 100.0, 100.0).unwrap(), (255, 0, 0));
        assert_eq!(
            hsv_to_rgb(361.0, 100.0, 100.0),
            Err(SharedValidatorsError::OutOfRange)
        );
    }

    #[test]
    fn parse_compare_operator_obeys_flags() {
        assert_eq!(
            parse_compare_operator("==rest", 0),
            Some((CompareOperator::Equal, "rest"))
        );
        assert_eq!(parse_compare_operator("eq rest", 0), None);
        assert_eq!(
            parse_compare_operator("eq rest", COMPARE_ALLOW_TEXTUAL),
            Some((CompareOperator::Equal, " rest"))
        );
        assert_eq!(parse_compare_operator("$=glob", 0), None);
    }

    #[test]
    fn test_order_rejects_non_order_ops() {
        assert!(test_order(-1, CompareOperator::Lower).unwrap());
        assert!(test_order(0, CompareOperator::Equal).unwrap());
        assert_eq!(
            test_order(0, CompareOperator::StringEqual),
            Err(SharedValidatorsError::InvalidArgument)
        );
    }

    #[test]
    fn boot_entry_token_validation_matches_helpers() {
        assert!(boot_entry_token_valid("good-token"));
        assert!(boot_entry_token_valid("café"));
        assert!(!boot_entry_token_valid("bad/token"));
        assert!(!boot_entry_token_valid("bad\"token"));
        assert!(!boot_entry_token_valid("bad*glob"));
        assert!(!boot_entry_token_valid_bytes(b"bad\xfftoken"));
    }

    #[test]
    fn pkcs11_uri_validation_is_superficial() {
        assert!(pkcs11_uri_valid("pkcs11:token=foo;id=01"));
        assert!(!pkcs11_uri_valid("pkcs11:"));
        assert!(!pkcs11_uri_valid("http://example.com"));
    }

    #[test]
    fn suitable_blob_filename_follows_uri_unreserved_rule() {
        assert!(suitable_blob_filename("alpha-._~09"));
        assert!(!suitable_blob_filename(".hidden"));
        assert!(!suitable_blob_filename("name/with/slash"));
    }
}
