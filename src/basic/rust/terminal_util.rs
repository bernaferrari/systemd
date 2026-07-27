// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/basic/terminal-util.c (tty_is_vc, tty_is_console, vtnr_from_tty,
//            url_suitable_for_osc8, osc_char_is_valid)
//            src/basic/terminal-util.h (vtnr_is_valid, VTNR_MAX)
//
// Pure terminal utility functions — no I/O, no syscalls, no raw pointers.
// All functions operate on Rust string slices and return Result types.

use crate::ffi::Errno;

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

/// Skip the `/dev/` prefix from a TTY path.
///
/// If the string starts with `/dev/`, returns the remainder.
/// Otherwise returns the original string unchanged.
/// Corresponds to the inline `path_startswith(p, "/dev/")` in C.
fn skip_dev_prefix(tty: &str) -> &str {
    tty.strip_prefix("/dev/").unwrap_or(tty)
}

/// Parse a decimal `u32` from the beginning of a string.
///
/// Returns `Some(value)` if the string starts with one or more ASCII digits
/// forming a valid `u32`, or `None` otherwise.
fn parse_u32_prefix(s: &str) -> Option<u32> {
    if s.is_empty() {
        return None;
    }
    let end = s
        .bytes()
        .position(|b| !b.is_ascii_digit())
        .unwrap_or(s.len());
    if end == 0 {
        return None;
    }
    s[..end].parse().ok()
}

/// Internal helper: extracts VT number from a TTY string, without range validation.
///
/// Skips optional `/dev/` prefix, requires `tty` prefix, then parses a decimal number.
/// Returns the raw parsed value on success, or an `Errno` on failure.
fn vtnr_from_tty_raw(tty: &str) -> Result<u32, Errno> {
    let stripped = skip_dev_prefix(tty);

    // Check for "tty" prefix
    let rest = stripped.strip_prefix("tty").ok_or(Errno::EINVAL)?;

    // Parse the number after "tty"
    parse_u32_prefix(rest).ok_or(Errno::EINVAL)
}

/// Extract the VT number from a TTY name string.
///
/// Accepts formats like `"tty1"`, `"tty63"`, `"/dev/tty1"`, `"/dev/tty63"`.
/// Returns the VT number (1–63) on success.
/// Returns `Err(EINVAL)` for malformed strings, `Err(ERANGE)` for out-of-range values.
///
/// Corresponds to `vtnr_from_tty()` in terminal-util.c.
pub fn vtnr_from_tty(tty: &str) -> Result<u32, Errno> {
    let val = vtnr_from_tty_raw(tty)?;
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
    vtnr_from_tty_raw(tty).is_ok()
}

// ── tty_is_console ────────────────────────────────────────────────────────

/// Check if the specified TTY is the system console.
///
/// Returns `true` if the string (after stripping an optional `/dev/` prefix)
/// is exactly `"console"`.
/// Corresponds to `tty_is_console()` in terminal-util.c.
pub fn tty_is_console(tty: &str) -> bool {
    let stripped = skip_dev_prefix(tty);
    stripped == "console"
}

// ── url_suitable_for_osc8 ────────────────────────────────────────────────

/// Check if a URL is safe for inclusion in an OSC 8 terminal sequence.
///
/// A URL is suitable if its length is ≤ 2000 characters and every character
/// is in the printable ASCII range `32..127` (per ECMA-48).
/// Corresponds to `url_suitable_for_osc8()` in terminal-util.c.
pub fn url_suitable_for_osc8(url: &str) -> bool {
    if url.len() > OSC8_URL_MAX_LEN {
        return false;
    }
    url.bytes().all(|c| c >= 32 && c < 127)
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
