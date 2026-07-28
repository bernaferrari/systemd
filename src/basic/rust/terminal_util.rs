// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: scope=basic.terminal-util; authority=src/basic/terminal-util.c,src/basic/terminal-util.h,src/shared/pretty-print.c
//
// Pure terminal utility functions — no I/O or syscalls. The safe core is
// byte-oriented so the C adapters preserve C-string semantics exactly.

use std::ffi::CStr;

use libc::{c_char, c_int, c_uint};

use crate::ffi::Errno;
use crate::path_util::skip_dev_prefix_offset;

// ── Constants ─────────────────────────────────────────────────────────────

/// Maximum valid virtual terminal number (matching C VTNR_MAX).
pub const VTNR_MAX: u32 = 63;

/// Maximum URL length suitable for OSC 8 terminal sequences (ECMA-48).
const OSC8_URL_MAX_LEN: usize = 2000;

// ── Character validation ──────────────────────────────────────────────────

/// Check if a byte is a valid OSC (Operating System Command) character.
///
/// Valid range is printable ASCII: `32..127` (space through tilde).
/// This corresponds to `osc_char_is_valid()` in terminal-util.h.
pub fn osc_char_is_valid(c: u8) -> bool {
    c >= 32 && c < 127
}

// ── VT number validation ──────────────────────────────────────────────────

/// Check if a virtual terminal number is valid (1 through 63).
///
/// Corresponds to `vtnr_is_valid()` in terminal-util.h.
pub fn vtnr_is_valid(n: u32) -> bool {
    n >= 1 && n <= VTNR_MAX
}

// ── VT number extraction ──────────────────────────────────────────────────

/// Parse the `safe_atou(..., base=0)` subset used by `vtnr_from_tty_raw()`.
///
/// This intentionally accepts C's leading ASCII whitespace and `+` sign,
/// recognizes hexadecimal, binary, and octal prefixes, rejects trailing bytes, and
/// reports a result that does not fit `unsigned` as `ERANGE`.
fn safe_atou_base0(bytes: &[u8]) -> Result<u32, Errno> {
    let mut cursor = 0;
    while matches!(bytes.get(cursor), Some(b' ' | b'\t' | b'\n' | b'\r')) {
        cursor += 1;
    }

    let signed = matches!(bytes.get(cursor), Some(b'+' | b'-'));
    let negative = match bytes.get(cursor) {
        Some(b'+') => {
            cursor += 1;
            false
        }
        Some(b'-') => {
            cursor += 1;
            true
        }
        _ => false,
    };

    let (base, digits_start) = if !signed
        && bytes.get(cursor) == Some(&b'0')
        && matches!(bytes.get(cursor + 1), Some(b'b' | b'B'))
    {
        (2, cursor + 2)
    } else if !signed
        && bytes.get(cursor) == Some(&b'0')
        && matches!(bytes.get(cursor + 1), Some(b'o' | b'O'))
    {
        (8, cursor + 2)
    } else if bytes.get(cursor) == Some(&b'0') && matches!(bytes.get(cursor + 1), Some(b'x' | b'X'))
    {
        (16, cursor + 2)
    } else if bytes.get(cursor) == Some(&b'0') {
        (8, cursor)
    } else {
        (10, cursor)
    };

    let mut value = 0_u32;
    let mut digits = 0;
    for &byte in &bytes[digits_start..] {
        let digit = match byte {
            b'0'..=b'9' => u32::from(byte - b'0'),
            b'a'..=b'f' => u32::from(byte - b'a') + 10,
            b'A'..=b'F' => u32::from(byte - b'A') + 10,
            _ => return Err(Errno::EINVAL),
        };
        if digit >= base {
            return Err(Errno::EINVAL);
        }
        value = value
            .checked_mul(base)
            .and_then(|current| current.checked_add(digit))
            .ok_or(Errno::ERANGE)?;
        digits += 1;
    }

    if digits == 0 {
        return Err(Errno::EINVAL);
    }
    if negative && value != 0 {
        return Err(Errno::ERANGE);
    }

    Ok(value)
}

/// Internal helper: extracts VT number from a TTY string, without range validation.
///
/// Skips a component-aware optional `/dev/` prefix, requires `tty`, then
/// parses the remaining bytes with C's base-zero unsigned grammar.
/// Returns the raw parsed value on success, or an `Errno` on failure.
fn vtnr_from_tty_raw_bytes(tty: &[u8]) -> Result<u32, Errno> {
    let stripped = &tty[skip_dev_prefix_offset(tty)..];

    // Check for "tty" prefix
    let rest = stripped.strip_prefix(b"tty").ok_or(Errno::EINVAL)?;

    safe_atou_base0(rest)
}

/// Extract the VT number from a TTY name string.
///
/// Accepts formats like `"tty1"`, `"tty63"`, `"/dev/tty1"`, `"/dev/tty63"`.
/// Returns the VT number (1–63) on success.
/// Returns `Err(EINVAL)` for malformed strings, `Err(ERANGE)` for out-of-range values.
///
/// Corresponds to `vtnr_from_tty()` in terminal-util.c.
pub fn vtnr_from_tty(tty: &str) -> Result<u32, Errno> {
    let val = vtnr_from_tty_raw_bytes(tty.as_bytes())?;
    if !vtnr_is_valid(val) {
        return Err(Errno::ERANGE);
    }
    Ok(val)
}

// ── tty_is_vc ─────────────────────────────────────────────────────────────

/// Check if the specified TTY is a virtual console (e.g. `"tty0"`, `"/dev/tty7"`).
///
/// Returns `true` if the TTY string matches the pattern `tty<N>` or `/dev/tty<N>`.
/// Corresponds to `tty_is_vc()` in terminal-util.c.
pub fn tty_is_vc(tty: &str) -> bool {
    vtnr_from_tty_raw_bytes(tty.as_bytes()).is_ok()
}

// ── tty_is_console ────────────────────────────────────────────────────────

/// Check if the specified TTY is the system console.
///
/// Returns `true` if the string (after stripping an optional `/dev/` prefix)
/// is exactly `"console"`.
/// Corresponds to `tty_is_console()` in terminal-util.c.
pub fn tty_is_console(tty: &str) -> bool {
    let bytes = tty.as_bytes();
    &bytes[skip_dev_prefix_offset(bytes)..] == b"console"
}

// ── url_suitable_for_osc8 ────────────────────────────────────────────────

/// Check if a URL is safe for inclusion in an OSC 8 terminal sequence.
///
/// A URL is suitable if its length is ≤ 2000 characters and every character
/// is in the printable ASCII range `32..127` (per ECMA-48).
/// Corresponds to the helper in `pretty-print.c` that uses terminal-util.h's
/// OSC character policy.
pub fn url_suitable_for_osc8(url: &str) -> bool {
    url_suitable_for_osc8_bytes(url.as_bytes())
}

/// Byte-oriented core for `url_suitable_for_osc8()` from pretty-print.c.
fn url_suitable_for_osc8_bytes(url: &[u8]) -> bool {
    url.len() <= OSC8_URL_MAX_LEN && url.iter().copied().all(osc_char_is_valid)
}

/// Borrow visible C-string bytes for one FFI call.
///
/// # Safety
/// `input` must be null or point to a readable NUL-terminated C string.
unsafe fn input_bytes<'a>(input: *const c_char) -> Option<&'a [u8]> {
    if input.is_null() {
        return None;
    }

    // SAFETY: the entry-point contract guarantees the terminating NUL.
    Some(unsafe { CStr::from_ptr(input) }.to_bytes())
}

/// C ABI for terminal-util.c's `tty_is_vc()`.
///
/// # Safety
/// `tty` must be null or a readable NUL-terminated C string. C asserts a
/// non-null input; this boundary instead fails closed for null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_tty_is_vc(tty: *const c_char) -> bool {
    // SAFETY: the entry-point contract is exactly input_bytes' contract.
    let Some(bytes) = (unsafe { input_bytes(tty) }) else {
        return false;
    };
    vtnr_from_tty_raw_bytes(bytes).is_ok()
}

/// C ABI for terminal-util.c's `tty_is_console()`.
///
/// # Safety
/// `tty` must be null or a readable NUL-terminated C string. C asserts a
/// non-null input; this boundary instead fails closed for null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_tty_is_console(tty: *const c_char) -> bool {
    // SAFETY: the entry-point contract is exactly input_bytes' contract.
    let Some(bytes) = (unsafe { input_bytes(tty) }) else {
        return false;
    };
    &bytes[skip_dev_prefix_offset(bytes)..] == b"console"
}

/// C ABI for terminal-util.c's `vtnr_from_tty()`.
///
/// # Safety
/// `tty` must be null or a readable NUL-terminated C string. C asserts a
/// non-null input; this boundary reports `-EINVAL` for null instead.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_vtnr_from_tty(tty: *const c_char) -> c_int {
    // SAFETY: the entry-point contract is exactly input_bytes' contract.
    let Some(bytes) = (unsafe { input_bytes(tty) }) else {
        return Errno::EINVAL.to_neg_errno();
    };

    match vtnr_from_tty_raw_bytes(bytes) {
        Ok(number) if vtnr_is_valid(number) => number as c_int,
        Ok(_) => Errno::ERANGE.to_neg_errno(),
        Err(error) => error.to_neg_errno(),
    }
}

/// C ABI for pretty-print.c's `url_suitable_for_osc8()` helper.
///
/// # Safety
/// `url` must be null or a readable NUL-terminated C string. C asserts a
/// non-null input; this boundary instead fails closed for null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_url_suitable_for_osc8(url: *const c_char) -> bool {
    // SAFETY: the entry-point contract is exactly input_bytes' contract.
    let Some(bytes) = (unsafe { input_bytes(url) }) else {
        return false;
    };
    url_suitable_for_osc8_bytes(bytes)
}

/// C ABI for terminal-util.h's `osc_char_is_valid()` inline helper.
#[unsafe(no_mangle)]
pub extern "C" fn rs_osc_char_is_valid(c: c_char) -> bool {
    osc_char_is_valid(c as u8)
}

/// C ABI for terminal-util.h's `vtnr_is_valid()` inline helper.
#[unsafe(no_mangle)]
pub extern "C" fn rs_vtnr_is_valid(number: c_uint) -> bool {
    vtnr_is_valid(number)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── osc_char_is_valid ──────────────────────────────────────────────

    #[test]
    fn test_osc_char_valid_printable() {
        assert!(osc_char_is_valid(b'A'));
        assert!(osc_char_is_valid(b'z'));
        assert!(osc_char_is_valid(b'0'));
        assert!(osc_char_is_valid(b'9'));
        assert!(osc_char_is_valid(b' '));
        assert!(osc_char_is_valid(b'~'));
    }

    #[test]
    fn test_osc_char_invalid_control() {
        assert!(!osc_char_is_valid(0));
        assert!(!osc_char_is_valid(1));
        assert!(!osc_char_is_valid(10));
        assert!(!osc_char_is_valid(13));
        assert!(!osc_char_is_valid(31));
    }

    #[test]
    fn test_osc_char_invalid_high() {
        assert!(!osc_char_is_valid(127));
        assert!(!osc_char_is_valid(128));
        assert!(!osc_char_is_valid(255));
    }

    #[test]
    fn test_osc_char_boundary() {
        assert!(osc_char_is_valid(32));
        assert!(!osc_char_is_valid(31));
        assert!(osc_char_is_valid(126));
        assert!(!osc_char_is_valid(127));
    }

    // ── vtnr_is_valid ──────────────────────────────────────────────────

    #[test]
    fn test_vtnr_valid_range() {
        assert!(vtnr_is_valid(1));
        assert!(vtnr_is_valid(2));
        assert!(vtnr_is_valid(7));
        assert!(vtnr_is_valid(63));
    }

    #[test]
    fn test_vtnr_invalid_zero() {
        assert!(!vtnr_is_valid(0));
    }

    #[test]
    fn test_vtnr_invalid_too_high() {
        assert!(!vtnr_is_valid(64));
        assert!(!vtnr_is_valid(100));
        assert!(!vtnr_is_valid(u32::MAX));
    }

    // ── vtnr_from_tty ──────────────────────────────────────────────────

    #[test]
    fn test_vtnr_from_tty_plain() {
        assert_eq!(vtnr_from_tty("tty1"), Ok(1));
        assert_eq!(vtnr_from_tty("tty7"), Ok(7));
        assert_eq!(vtnr_from_tty("tty63"), Ok(63));
        assert_eq!(vtnr_from_tty("tty12"), Ok(12));
    }

    #[test]
    fn test_vtnr_from_tty_with_dev_prefix() {
        assert_eq!(vtnr_from_tty("/dev/tty1"), Ok(1));
        assert_eq!(vtnr_from_tty("/dev/tty7"), Ok(7));
        assert_eq!(vtnr_from_tty("/dev/tty63"), Ok(63));
    }

    #[test]
    fn test_vtnr_from_tty_empty() {
        assert!(vtnr_from_tty("").is_err());
    }

    #[test]
    fn test_vtnr_from_tty_invalid_no_tty_prefix() {
        assert!(vtnr_from_tty("console").is_err());
        assert!(vtnr_from_tty("pts/0").is_err());
    }

    #[test]
    fn test_vtnr_from_tty_invalid_no_number() {
        assert!(vtnr_from_tty("tty").is_err());
    }

    #[test]
    fn test_vtnr_from_tty_out_of_range() {
        // tty0 parses but vtnr_is_valid requires 1-63
        assert_eq!(vtnr_from_tty("tty0"), Err(Errno::ERANGE));
        assert_eq!(vtnr_from_tty("tty64"), Err(Errno::ERANGE));
        assert_eq!(vtnr_from_tty("tty999"), Err(Errno::ERANGE));
    }

    #[test]
    fn test_vtnr_from_tty_invalid_string() {
        assert!(vtnr_from_tty("notatty").is_err());
    }

    #[test]
    fn vtnr_uses_c_safe_atou_base_zero_grammar() {
        assert_eq!(vtnr_from_tty("tty010"), Ok(8));
        assert_eq!(vtnr_from_tty("tty0x3f"), Ok(63));
        assert_eq!(vtnr_from_tty("tty0b111"), Ok(7));
        assert_eq!(vtnr_from_tty("tty0o10"), Ok(8));
        assert_eq!(vtnr_from_tty("tty+7"), Ok(7));
        assert_eq!(vtnr_from_tty("tty\t7"), Ok(7));
        assert_eq!(vtnr_from_tty("tty-0"), Err(Errno::ERANGE));
        assert_eq!(vtnr_from_tty("tty-1"), Err(Errno::ERANGE));
        assert_eq!(vtnr_from_tty("tty09"), Err(Errno::EINVAL));
        assert_eq!(vtnr_from_tty("tty+0b1"), Err(Errno::EINVAL));
        assert_eq!(vtnr_from_tty("tty\x0b7"), Err(Errno::EINVAL));
        assert_eq!(vtnr_from_tty("tty7junk"), Err(Errno::EINVAL));
        assert_eq!(vtnr_from_tty("tty4294967296"), Err(Errno::ERANGE));
    }

    #[test]
    fn tty_prefix_is_component_aware_like_skip_dev_prefix() {
        assert_eq!(vtnr_from_tty("//dev//tty7"), Ok(7));
        assert_eq!(vtnr_from_tty("/./dev/tty7"), Ok(7));
        assert!(tty_is_console("//dev//console"));
    }

    // ── tty_is_vc ──────────────────────────────────────────────────────

    #[test]
    fn test_tty_is_vc_valid() {
        assert!(tty_is_vc("tty1"));
        assert!(tty_is_vc("tty7"));
        assert!(tty_is_vc("/dev/tty1"));
        assert!(tty_is_vc("/dev/tty63"));
    }

    #[test]
    fn test_tty_is_vc_invalid() {
        assert!(!tty_is_vc("console"));
        assert!(!tty_is_vc("pts/0"));
        assert!(!tty_is_vc("tty"));
        assert!(!tty_is_vc("notatty"));
    }

    #[test]
    fn test_tty_is_vc_empty() {
        assert!(!tty_is_vc(""));
    }

    #[test]
    fn tty_is_vc_rejects_partial_numeric_suffixes() {
        assert!(!tty_is_vc("tty7junk"));
        assert!(!tty_is_vc("tty09"));
        assert!(tty_is_vc("tty999"));
        assert!(tty_is_vc("tty0x3f"));
    }

    // ── tty_is_console ─────────────────────────────────────────────────

    #[test]
    fn test_tty_is_console_plain() {
        assert!(tty_is_console("console"));
    }

    #[test]
    fn test_tty_is_console_with_dev_prefix() {
        assert!(tty_is_console("/dev/console"));
    }

    #[test]
    fn test_tty_is_console_not_console() {
        assert!(!tty_is_console("tty1"));
        assert!(!tty_is_console("/dev/tty1"));
        assert!(!tty_is_console("pts/0"));
    }

    #[test]
    fn test_tty_is_console_empty() {
        assert!(!tty_is_console(""));
    }

    #[test]
    fn test_tty_is_console_partial_match() {
        assert!(!tty_is_console("consol"));
        assert!(!tty_is_console("consoled"));
    }

    // ── url_suitable_for_osc8 ──────────────────────────────────────────

    #[test]
    fn test_url_suitable_valid() {
        assert!(url_suitable_for_osc8("https://example.com"));
        assert!(url_suitable_for_osc8("http://localhost:8080/path"));
        assert!(url_suitable_for_osc8("file:///tmp/test"));
    }

    #[test]
    fn test_url_suitable_empty() {
        assert!(url_suitable_for_osc8(""));
    }

    #[test]
    fn test_url_suitable_too_long() {
        let long_url = "a".repeat(2001);
        assert!(!url_suitable_for_osc8(&long_url));
    }

    #[test]
    fn test_url_suitable_boundary_length() {
        let url_2000 = "a".repeat(2000);
        assert!(url_suitable_for_osc8(&url_2000));

        let url_2001 = "a".repeat(2001);
        assert!(!url_suitable_for_osc8(&url_2001));
    }

    #[test]
    fn test_url_suitable_invalid_chars() {
        assert!(!url_suitable_for_osc8("http://example.com/\x01"));
        assert!(!url_suitable_for_osc8("http://example.com/\n"));
        assert!(!url_suitable_for_osc8("http://example.com/\t"));
        assert!(!url_suitable_for_osc8("http://example.com/\x7f"));
    }

    #[test]
    fn test_url_suitable_valid_special_chars() {
        assert!(url_suitable_for_osc8("https://example.com/path?q=1&b=2"));
        assert!(url_suitable_for_osc8("https://example.com/path#frag"));
        assert!(url_suitable_for_osc8("https://example.com/~user"));
    }
}
