// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: scope=basic.percent-util; authority=src/basic/percent-util.c,src/basic/percent-util.h
//
// Percentage, permille, and permyriad parsing and scaling functions.
//
// Supports whole-number and decimal parsing of percent (%),
// permille (‰), and permyriad (‱) values. Also provides
// UINT32_SCALE_FROM/TO helpers for converting to/from 2^32-1 scale.

// Centralized unsafe expression boundary for this module.
macro_rules! unsafe_ffi {
    ($expression:expr) => {{
        // SAFETY: the enclosing helper documents and validates this operation.
        unsafe { $expression }
    }};
}
use std::ffi::{CStr, CString};

use crate::ffi::{clear_errno, get_errno};

// ── Error constants ───────────────────────────────────────────────────────

const EINVAL: i32 = -22;
const ERANGE: i32 = -34;

// ── Internal helpers ──────────────────────────────────────────────────────

/// Check whether a byte string ends with `suffix`, returning the preceding
/// bytes without interpreting either side as Unicode.
fn endswith_bytes<'a>(s: &'a [u8], suffix: &[u8]) -> Option<&'a [u8]> {
    if s.ends_with(suffix) {
        Some(&s[..s.len() - suffix.len()])
    } else {
        None
    }
}

#[inline]
fn is_systemd_whitespace(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\n' | b'\r')
}

/// Safe byte-level equivalent of the `safe_atoi()` subset used by
/// percent-util.c.
///
/// The ordering matters: systemd first skips `WHITESPACE`, then recognizes its
/// Python-style `0b`/`0o` prefixes. The remaining grammar deliberately stays
/// with the target libc's `strtol()`: accepted base-zero syntax, locale
/// whitespace, and newer libc extensions are part of the current C authority
/// and must not be duplicated by a subtly different Rust parser.
fn safe_atoi_bytes(s: &[u8]) -> Result<i32, i32> {
    let mut cursor = 0;
    while cursor < s.len() && is_systemd_whitespace(s[cursor]) {
        cursor += 1;
    }

    let mut base = 0_u8;
    if s[cursor..].starts_with(b"0b") || s[cursor..].starts_with(b"0B") {
        cursor += 2;
        base = 2;
    } else if s[cursor..].starts_with(b"0o") || s[cursor..].starts_with(b"0O") {
        cursor += 2;
        base = 8;
    }

    let numeric = CString::new(&s[cursor..]).map_err(|_| EINVAL)?;
    let start = numeric.as_ptr();
    let mut end = std::ptr::null_mut();

    clear_errno();
    // SAFETY: `numeric` is a live NUL-terminated string, `end` is writable,
    // and mangle_base above supplies only libc-supported bases 0, 2, or 8.
    let value = unsafe_ffi!(libc::strtol(start, &mut end, base as libc::c_int));
    let errno = get_errno();
    if errno > 0 {
        return Err(-errno);
    }
    if end.is_null() || end == start.cast_mut() {
        return Err(EINVAL);
    }

    // SAFETY: strtol returned `end` inside `numeric`, whose storage is still
    // live. A successful safe_atoi conversion must consume the entire string.
    if unsafe_ffi!(*end) != 0 {
        return Err(EINVAL);
    }
    if value as libc::c_int as libc::c_long != value {
        return Err(ERANGE);
    }

    Ok(value as libc::c_int)
}

// ── parse_parts_value_whole ───────────────────────────────────────────────

fn parse_parts_value_whole(p: &[u8], symbol: &[u8]) -> Result<i32, i32> {
    let prefix = endswith_bytes(p, symbol).ok_or(EINVAL)?;
    let v = safe_atoi_bytes(prefix)?;
    if v < 0 {
        return Err(ERANGE);
    }
    Ok(v)
}

// ── parse_parts_value_with_tenths_place ───────────────────────────────────

fn parse_parts_value_with_tenths_place(p: &[u8], symbol: &[u8]) -> Result<i32, i32> {
    let prefix = endswith_bytes(p, symbol).ok_or(EINVAL)?;

    let (integer, q) = if let Some(dot) = prefix.iter().position(|&byte| byte == b'.') {
        if dot + 2 != prefix.len() {
            return Err(EINVAL);
        }
        let digit = prefix[dot + 1];
        if !digit.is_ascii_digit() {
            return Err(EINVAL);
        }
        (&prefix[..dot], (digit - b'0') as i32)
    } else {
        (prefix, 0)
    };

    let v = safe_atoi_bytes(integer)?;
    if v < 0 || v > (i32::MAX - q) / 10 {
        return Err(ERANGE);
    }
    Ok(v * 10 + q)
}

// ── parse_parts_value_with_hundredths_place ───────────────────────────────

fn parse_parts_value_with_hundredths_place(p: &[u8], symbol: &[u8]) -> Result<i32, i32> {
    let prefix = endswith_bytes(p, symbol).ok_or(EINVAL)?;

    let (integer, q) = if let Some(dot) = prefix.iter().position(|&byte| byte == b'.') {
        let fractional = &prefix[dot + 1..];
        let q = match fractional {
            [first, second] => {
                if !first.is_ascii_digit() || !second.is_ascii_digit() {
                    return Err(EINVAL);
                }
                ((first - b'0') as i32) * 10 + (second - b'0') as i32
            }
            [first] => {
                if !first.is_ascii_digit() {
                    return Err(EINVAL);
                }
                ((first - b'0') as i32) * 10
            }
            _ => {
                return Err(EINVAL);
            }
        };
        (&prefix[..dot], q)
    } else {
        (prefix, 0)
    };

    let v = safe_atoi_bytes(integer)?;
    if v < 0 || v > (i32::MAX - q) / 100 {
        return Err(ERANGE);
    }
    Ok(v * 100 + q)
}

// ── Public API: percent/permille/permyriad parsing ────────────────────────

/// Parse a percentage string (e.g. "42%") without upper bound.
pub fn parse_percent_unbounded(p: &str) -> Result<i32, i32> {
    parse_percent_unbounded_bytes(p.as_bytes())
}

/// Parse a percentage string, bounded to 0..100.
pub fn parse_percent(p: &str) -> Result<i32, i32> {
    parse_percent_bytes(p.as_bytes())
}

fn parse_percent_unbounded_bytes(p: &[u8]) -> Result<i32, i32> {
    parse_parts_value_whole(p, b"%")
}

fn parse_percent_bytes(p: &[u8]) -> Result<i32, i32> {
    let v = parse_percent_unbounded_bytes(p)?;
    if v > 100 {
        return Err(ERANGE);
    }
    Ok(v)
}

/// Parse a permille string (e.g. "105‰" or "10.5%") without upper bound.
pub fn parse_permille_unbounded(p: &str) -> Result<i32, i32> {
    parse_permille_unbounded_bytes(p.as_bytes())
}

fn parse_permille_unbounded_bytes(p: &[u8]) -> Result<i32, i32> {
    if endswith_bytes(p, "‰".as_bytes()).is_some() {
        return parse_parts_value_whole(p, "‰".as_bytes());
    }
    parse_parts_value_with_tenths_place(p, b"%")
}

/// Parse a permille string, bounded to 0..1000.
pub fn parse_permille(p: &str) -> Result<i32, i32> {
    parse_permille_bytes(p.as_bytes())
}

fn parse_permille_bytes(p: &[u8]) -> Result<i32, i32> {
    let v = parse_permille_unbounded_bytes(p)?;
    if v > 1000 {
        return Err(ERANGE);
    }
    Ok(v)
}

/// Parse a permyriad string (e.g. "1055‱", "105.5‰", or "10.55%") without upper bound.
pub fn parse_permyriad_unbounded(p: &str) -> Result<i32, i32> {
    parse_permyriad_unbounded_bytes(p.as_bytes())
}

fn parse_permyriad_unbounded_bytes(p: &[u8]) -> Result<i32, i32> {
    if endswith_bytes(p, "‱".as_bytes()).is_some() {
        return parse_parts_value_whole(p, "‱".as_bytes());
    }
    if endswith_bytes(p, "‰".as_bytes()).is_some() {
        return parse_parts_value_with_tenths_place(p, "‰".as_bytes());
    }
    parse_parts_value_with_hundredths_place(p, b"%")
}

/// Parse a permyriad string, bounded to 0..10000.
pub fn parse_permyriad(p: &str) -> Result<i32, i32> {
    parse_permyriad_bytes(p.as_bytes())
}

fn parse_permyriad_bytes(p: &[u8]) -> Result<i32, i32> {
    let v = parse_permyriad_unbounded_bytes(p)?;
    if v > 10000 {
        return Err(ERANGE);
    }
    Ok(v)
}

// ── C ABI: parsers ────────────────────────────────────────────────────────

/// Borrow and parse one C string without transferring ownership.
///
/// # Safety
/// A non-null `p` must point to a readable NUL-terminated C string for the
/// duration of the call.
unsafe fn parse_c_string(p: *const libc::c_char, parser: fn(&[u8]) -> Result<i32, i32>) -> i32 {
    if p.is_null() {
        return EINVAL;
    }

    // SAFETY: upheld by the caller of the public C ABI entry point.
    let bytes = unsafe_ffi!(CStr::from_ptr(p)).to_bytes();
    parser(bytes).unwrap_or_else(|error| error)
}

/// C ABI for `parse_percent_unbounded()`.
///
/// # Safety
/// `p` may be null; otherwise it must point to a readable NUL-terminated C
/// string for the duration of this call. The input is borrowed and never
/// retained or freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_parse_percent_unbounded(p: *const libc::c_char) -> i32 {
    // SAFETY: this entry point forwards its documented C-string contract.
    unsafe_ffi!(parse_c_string(p, parse_percent_unbounded_bytes))
}

/// C ABI for `parse_percent()`.
///
/// # Safety
/// `p` may be null; otherwise it must point to a readable NUL-terminated C
/// string for the duration of this call. The input is borrowed and never
/// retained or freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_parse_percent(p: *const libc::c_char) -> i32 {
    // SAFETY: this entry point forwards its documented C-string contract.
    unsafe_ffi!(parse_c_string(p, parse_percent_bytes))
}

/// C ABI for `parse_permille_unbounded()`.
///
/// # Safety
/// `p` may be null; otherwise it must point to a readable NUL-terminated C
/// string for the duration of this call. The input is borrowed and never
/// retained or freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_parse_permille_unbounded(p: *const libc::c_char) -> i32 {
    // SAFETY: this entry point forwards its documented C-string contract.
    unsafe_ffi!(parse_c_string(p, parse_permille_unbounded_bytes))
}

/// C ABI for `parse_permille()`.
///
/// # Safety
/// `p` may be null; otherwise it must point to a readable NUL-terminated C
/// string for the duration of this call. The input is borrowed and never
/// retained or freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_parse_permille(p: *const libc::c_char) -> i32 {
    // SAFETY: this entry point forwards its documented C-string contract.
    unsafe_ffi!(parse_c_string(p, parse_permille_bytes))
}

/// C ABI for `parse_permyriad_unbounded()`.
///
/// # Safety
/// `p` may be null; otherwise it must point to a readable NUL-terminated C
/// string for the duration of this call. The input is borrowed and never
/// retained or freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_parse_permyriad_unbounded(p: *const libc::c_char) -> i32 {
    // SAFETY: this entry point forwards its documented C-string contract.
    unsafe_ffi!(parse_c_string(p, parse_permyriad_unbounded_bytes))
}

/// C ABI for `parse_permyriad()`.
///
/// # Safety
/// `p` may be null; otherwise it must point to a readable NUL-terminated C
/// string for the duration of this call. The input is borrowed and never
/// retained or freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_parse_permyriad(p: *const libc::c_char) -> i32 {
    // SAFETY: this entry point forwards its documented C-string contract.
    unsafe_ffi!(parse_c_string(p, parse_permyriad_bytes))
}

// ── UINT32_SCALE helpers ──────────────────────────────────────────────────

/// Convert a percent value to a value relative to 100% == 2^32-1.
pub fn uint32_scale_from_percent(percent: i32) -> u32 {
    let p = percent.clamp(0, 100) as u64;
    ((p * u32::MAX as u64 + 50) / 100) as u32
}

/// Convert a permille value to a value relative to 1000‰ == 2^32-1.
pub fn uint32_scale_from_permille(permille: i32) -> u32 {
    let p = permille.clamp(0, 1000) as u64;
    ((p * u32::MAX as u64 + 500) / 1000) as u32
}

/// Convert a permyriad value to a value relative to 10000‱ == 2^32-1.
pub fn uint32_scale_from_permyriad(permyriad: i32) -> u32 {
    let p = permyriad.clamp(0, 10000) as u64;
    ((p * u32::MAX as u64 + 5000) / 10000) as u32
}

/// Convert a 2^32-1 scale value back to percent.
pub fn uint32_scale_to_percent(scale: u32) -> Result<i32, i32> {
    let u = ((scale as u64 * 100 + (u32::MAX as u64 / 2)) / u32::MAX as u64) as u32;
    if u > i32::MAX as u32 {
        return Err(ERANGE);
    }
    Ok(u as i32)
}

/// Convert a 2^32-1 scale value back to permille.
pub fn uint32_scale_to_permille(scale: u32) -> Result<i32, i32> {
    let u = ((scale as u64 * 1000 + (u32::MAX as u64 / 2)) / u32::MAX as u64) as u32;
    if u > i32::MAX as u32 {
        return Err(ERANGE);
    }
    Ok(u as i32)
}

/// Convert a 2^32-1 scale value back to permyriad.
pub fn uint32_scale_to_permyriad(scale: u32) -> Result<i32, i32> {
    let u = ((scale as u64 * 10000 + (u32::MAX as u64 / 2)) / u32::MAX as u64) as u32;
    if u > i32::MAX as u32 {
        return Err(ERANGE);
    }
    Ok(u as i32)
}

// ── C ABI: UINT32_SCALE helpers ───────────────────────────────────────────

/// C ABI façade for `UINT32_SCALE_FROM_PERCENT()`.
///
/// This preserves the inline C helper's `int` input domain, saturation to
/// `[0, 100]`, 64-bit intermediate arithmetic, and round-to-nearest offset.
#[unsafe(no_mangle)]
pub extern "C" fn rs_UINT32_SCALE_FROM_PERCENT(percent: i32) -> u32 {
    uint32_scale_from_percent(percent)
}

/// C ABI façade for `UINT32_SCALE_FROM_PERMILLE()`.
///
/// This preserves the inline C helper's `int` input domain, saturation to
/// `[0, 1000]`, 64-bit intermediate arithmetic, and round-to-nearest offset.
#[unsafe(no_mangle)]
pub extern "C" fn rs_UINT32_SCALE_FROM_PERMILLE(permille: i32) -> u32 {
    uint32_scale_from_permille(permille)
}

/// C ABI façade for `UINT32_SCALE_FROM_PERMYRIAD()`.
///
/// This preserves the inline C helper's `int` input domain, saturation to
/// `[0, 10000]`, 64-bit intermediate arithmetic, and round-to-nearest offset.
#[unsafe(no_mangle)]
pub extern "C" fn rs_UINT32_SCALE_FROM_PERMYRIAD(permyriad: i32) -> u32 {
    uint32_scale_from_permyriad(permyriad)
}

/// C ABI façade for `UINT32_SCALE_TO_PERCENT()`.
///
/// The integer-only calculation has the same `UINT32_MAX / 2` rounding term
/// and the same `-ERANGE` fallback as the C inline helper.
#[unsafe(no_mangle)]
pub extern "C" fn rs_UINT32_SCALE_TO_PERCENT(scale: u32) -> i32 {
    uint32_scale_to_percent(scale).unwrap_or(ERANGE)
}

/// C ABI façade for `UINT32_SCALE_TO_PERMILLE()`.
///
/// The integer-only calculation has the same `UINT32_MAX / 2` rounding term
/// and the same `-ERANGE` fallback as the C inline helper.
#[unsafe(no_mangle)]
pub extern "C" fn rs_UINT32_SCALE_TO_PERMILLE(scale: u32) -> i32 {
    uint32_scale_to_permille(scale).unwrap_or(ERANGE)
}

/// C ABI façade for `UINT32_SCALE_TO_PERMYRIAD()`.
///
/// The integer-only calculation has the same `UINT32_MAX / 2` rounding term
/// and the same `-ERANGE` fallback as the C inline helper.
#[unsafe(no_mangle)]
pub extern "C" fn rs_UINT32_SCALE_TO_PERMYRIAD(scale: u32) -> i32 {
    uint32_scale_to_permyriad(scale).unwrap_or(ERANGE)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_percent_success() {
        assert_eq!(parse_percent("42%"), Ok(42));
        assert_eq!(parse_percent("0%"), Ok(0));
        assert_eq!(parse_percent("100%"), Ok(100));
    }

    #[test]
    fn test_parse_percent_too_big() {
        assert_eq!(parse_percent("101%"), Err(ERANGE));
    }

    #[test]
    fn test_parse_percent_no_symbol() {
        assert_eq!(parse_percent("42"), Err(EINVAL));
    }

    #[test]
    fn test_parse_percent_empty() {
        assert_eq!(parse_percent(""), Err(EINVAL));
        assert_eq!(parse_percent("%"), Err(EINVAL));
    }

    #[test]
    fn test_parse_permille_from_percent() {
        assert_eq!(parse_permille("10.5%"), Ok(105));
        assert_eq!(parse_permille("100%"), Ok(1000));
    }

    #[test]
    fn test_parse_permille_from_symbol() {
        assert_eq!(parse_permille("105\u{2030}"), Ok(105));
        assert_eq!(parse_permille("1000\u{2030}"), Ok(1000));
    }

    #[test]
    fn test_parse_permille_too_big() {
        assert_eq!(parse_permille("1001\u{2030}"), Err(ERANGE));
    }

    #[test]
    fn test_parse_permyriad_from_percent() {
        assert_eq!(parse_permyriad("10.55%"), Ok(1055));
        assert_eq!(parse_permyriad("10.5%"), Ok(1050));
    }

    #[test]
    fn test_parse_permyriad_from_permille() {
        assert_eq!(parse_permyriad("105.5\u{2030}"), Ok(1055));
    }

    #[test]
    fn test_parse_permyriad_from_symbol() {
        assert_eq!(parse_permyriad("1055\u{2031}"), Ok(1055));
    }

    #[test]
    fn test_parse_permyriad_too_big() {
        assert_eq!(parse_permyriad("10001\u{2031}"), Err(ERANGE));
    }

    #[test]
    fn test_uint32_scale_from_percent() {
        assert_eq!(uint32_scale_from_percent(-1), 0);
        assert_eq!(uint32_scale_from_percent(0), 0);
        assert_eq!(uint32_scale_from_percent(100), u32::MAX);
    }

    #[test]
    fn test_uint32_scale_from_permille() {
        assert_eq!(uint32_scale_from_permille(0), 0);
        assert_eq!(uint32_scale_from_permille(1000), u32::MAX);
    }

    #[test]
    fn test_uint32_scale_from_permyriad() {
        assert_eq!(uint32_scale_from_permyriad(0), 0);
        assert_eq!(uint32_scale_from_permyriad(10000), u32::MAX);
    }

    #[test]
    fn test_uint32_scale_to_percent() {
        assert_eq!(uint32_scale_to_percent(0), Ok(0));
        assert_eq!(uint32_scale_to_percent(u32::MAX), Ok(100));
    }

    #[test]
    fn test_uint32_scale_to_permille() {
        assert_eq!(uint32_scale_to_permille(u32::MAX), Ok(1000));
    }

    #[test]
    fn test_uint32_scale_to_permyriad() {
        assert_eq!(uint32_scale_to_permyriad(u32::MAX), Ok(10000));
    }

    #[test]
    fn test_roundtrip_percent() {
        for p in [0, 25, 50, 75, 100] {
            let scaled = uint32_scale_from_percent(p);
            let back = uint32_scale_to_percent(scaled).unwrap();
            assert_eq!(back, p);
        }
    }

    #[test]
    fn test_parse_percent_negative() {
        assert_eq!(parse_percent("-1%"), Err(ERANGE));
    }

    #[test]
    fn safe_atoi_grammar_matches_percent_c_authority() {
        assert_eq!(parse_percent_unbounded("  +010%"), Ok(8));
        assert_eq!(parse_percent_unbounded("0x10%"), Ok(16));
        assert_eq!(parse_percent_unbounded("0b  +10%"), Ok(2));
        assert_eq!(parse_percent_unbounded("0o10%"), Ok(8));
        assert_eq!(parse_percent_unbounded("\u{b}10%"), Ok(10));
        assert_eq!(parse_percent_unbounded("-0%"), Ok(0));
        assert_eq!(parse_percent_unbounded("10 %"), Err(EINVAL));
        assert_eq!(parse_percent_unbounded("2147483648%"), Err(ERANGE));
    }

    #[test]
    fn fractional_width_and_overflow_match_c_authority() {
        assert_eq!(parse_permille_unbounded("214748364.7%"), Ok(i32::MAX));
        assert_eq!(parse_permille_unbounded("214748364.8%"), Err(ERANGE));
        assert_eq!(parse_permille_unbounded(".5%"), Err(EINVAL));
        assert_eq!(parse_permyriad_unbounded("21474836.47%"), Ok(i32::MAX));
        assert_eq!(parse_permyriad_unbounded("21474836.48%"), Err(ERANGE));
        assert_eq!(parse_permyriad_unbounded("12.%"), Err(EINVAL));
        assert_eq!(parse_permyriad_unbounded(".25%"), Err(EINVAL));
    }
}
