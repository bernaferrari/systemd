// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: scope=basic.extract-word; authority=src/basic/extract-word.c,src/basic/extract-word.h
//
// Word extraction from strings with quoting and escaping support.
// Pure Rust — cunescape and UTF-8 encoding implemented inline.

use libc::c_char;

use crate::ffi::Errno;

// ── Extract flags (mirrors C ExtractFlags) ─────────────────────────────────

pub const EXTRACT_RELAX: u32 = 1 << 0;
pub const EXTRACT_CUNESCAPE: u32 = 1 << 1;
pub const EXTRACT_UNESCAPE_RELAX: u32 = 1 << 2;
pub const EXTRACT_UNESCAPE_SEPARATORS: u32 = 1 << 3;
pub const EXTRACT_KEEP_QUOTE: u32 = 1 << 4;
pub const EXTRACT_UNQUOTE: u32 = 1 << 5;
pub const EXTRACT_DONT_COALESCE_SEPARATORS: u32 = 1 << 6;
pub const EXTRACT_RETAIN_ESCAPE: u32 = 1 << 7;
pub const EXTRACT_RETAIN_SEPARATORS: u32 = 1 << 8;

const DEFAULT_SEPARATORS: &[u8] = b" \t\n\r";

// ── Pure Rust cunescape_one ────────────────────────────────────────────────

fn unhexchar(c: u8) -> Option<i32> {
    match c {
        b'0'..=b'9' => Some((c - b'0') as i32),
        b'a'..=b'f' => Some((c - b'a' + 10) as i32),
        b'A'..=b'F' => Some((c - b'A' + 10) as i32),
        _ => None,
    }
}

fn unoctchar(c: u8) -> Option<i32> {
    match c {
        b'0'..=b'7' => Some((c - b'0') as i32),
        _ => None,
    }
}

/// Result of a single C-escape decode.
enum CunescapeOut {
    /// Single raw byte (eight_bit in C)
    Byte(u8),
    /// Unicode codepoint to be UTF-8 encoded
    Char(u32),
}

/// Decode one C escape sequence starting at `input[0]` (the char *after* the backslash).
/// Returns (bytes_consumed, decoded_output) or None on invalid sequence.
fn cunescape_one(input: &[u8], accept_nul: bool) -> Option<(usize, CunescapeOut)> {
    if input.is_empty() {
        return None;
    }
    let c = input[0];

    match c {
        b'a' => Some((1, CunescapeOut::Byte(0x07))),
        b'b' => Some((1, CunescapeOut::Byte(0x08))),
        b'f' => Some((1, CunescapeOut::Byte(0x0C))),
        b'n' => Some((1, CunescapeOut::Byte(0x0A))),
        b'r' => Some((1, CunescapeOut::Byte(0x0D))),
        b't' => Some((1, CunescapeOut::Byte(0x09))),
        b'v' => Some((1, CunescapeOut::Byte(0x0B))),
        b'\\' => Some((1, CunescapeOut::Byte(0x5C))),
        b'"' => Some((1, CunescapeOut::Byte(0x22))),
        b'\'' => Some((1, CunescapeOut::Byte(0x27))),
        b's' => Some((1, CunescapeOut::Byte(0x20))),
        b'x' => {
            if input.len() < 3 {
                return None;
            }
            let a = unhexchar(input[1])?;
            let b = unhexchar(input[2])?;
            let val = ((a << 4) | b) as u8;
            if val == 0 && !accept_nul {
                return None;
            }
            Some((3, CunescapeOut::Byte(val)))
        }
        b'u' => {
            if input.len() < 5 {
                return None;
            }
            let mut val: u32 = 0;
            for i in 0..4 {
                let d = unhexchar(input[1 + i])?;
                val = (val << 4) | (d as u32);
            }
            if val == 0 && !accept_nul {
                return None;
            }
            Some((5, CunescapeOut::Char(val)))
        }
        b'U' => {
            if input.len() < 9 {
                return None;
            }
            let mut val: u32 = 0;
            for i in 0..8 {
                let d = unhexchar(input[1 + i])?;
                val = (val << 4) | (d as u32);
            }
            if val == 0 && !accept_nul {
                return None;
            }
            if !unichar_is_valid(val) {
                return None;
            }
            Some((9, CunescapeOut::Char(val)))
        }
        b'0'..=b'7' => {
            if input.len() < 3 {
                return None;
            }
            let a = unoctchar(input[0])?;
            let b = unoctchar(input[1])?;
            let c_val = unoctchar(input[2])?;
            let m: u32 = ((a as u32) << 6) | ((b as u32) << 3) | (c_val as u32);
            if m > 255 {
                return None;
            }
            if m == 0 && !accept_nul {
                return None;
            }
            Some((3, CunescapeOut::Byte(m as u8)))
        }
        _ => None,
    }
}

fn unichar_is_valid(ch: u32) -> bool {
    if ch >= 0x110000 {
        return false;
    }
    if (ch & 0xFFFFF800) == 0xD800 {
        return false;
    }
    if (0xFDD0..=0xFDEF).contains(&ch) {
        return false;
    }
    if ch < 0x10000 && (ch & 0xFFFE) == 0xFFFE {
        return false;
    }
    true
}

/// Encode a Unicode codepoint as UTF-8 bytes.
fn utf8_encode_unichar(g: u32) -> Vec<u8> {
    if g < (1 << 7) {
        vec![g as u8]
    } else if g < (1 << 11) {
        vec![0xC0 | ((g >> 6) & 0x1F) as u8, 0x80 | (g & 0x3F) as u8]
    } else if g < (1 << 16) {
        vec![
            0xE0 | ((g >> 12) & 0x0F) as u8,
            0x80 | ((g >> 6) & 0x3F) as u8,
            0x80 | (g & 0x3F) as u8,
        ]
    } else if g < (1 << 21) {
        vec![
            0xF0 | ((g >> 18) & 0x07) as u8,
            0x80 | ((g >> 12) & 0x3F) as u8,
            0x80 | ((g >> 6) & 0x3F) as u8,
            0x80 | (g & 0x3F) as u8,
        ]
    } else {
        Vec::new()
    }
}

// ── Helper predicates ──────────────────────────────────────────────────────

#[inline]
fn flags_set(v: u32, flag: u32) -> bool {
    (v & flag) != 0
}

fn is_separator(c: u8, sep: &[u8]) -> bool {
    sep.contains(&c)
}

// ── extract_first_word ─────────────────────────────────────────────────────

/// Parse the first word from `input`, handling quotes and escapes.
/// Mirrors C `extract_first_word()`.
///
/// Returns:
/// - `Ok(Some((word, remaining)))` — word extracted, `remaining` is what's left
/// - `Ok(None)` — end of input
/// - `Err(Errno)` — parse error
pub fn extract_first_word<'a>(
    input: &'a str,
    separators: Option<&str>,
    flags: u32,
) -> Result<Option<(String, &'a str)>, Errno> {
    let sep = separators
        .map(|s| s.as_bytes())
        .unwrap_or(DEFAULT_SEPARATORS);

    let bytes = input.as_bytes();
    let len = bytes.len();

    if len == 0 {
        return Ok(None);
    }

    let mut pos: usize = 0;
    let mut buf: Vec<u8> = Vec::new();
    let mut quote: u8 = 0;
    let mut backslash = false;

    if flags_set(flags, EXTRACT_DONT_COALESCE_SEPARATORS) {
        buf.reserve(1);
    }

    // Skip leading separators
    loop {
        if pos >= len {
            return Ok(None);
        }
        let c = bytes[pos];
        if is_separator(c, sep) {
            if flags_set(flags, EXTRACT_DONT_COALESCE_SEPARATORS) {
                if !flags_set(flags, EXTRACT_RETAIN_SEPARATORS) {
                    pos += 1;
                }
                buf.push(0);
                let word = String::from_utf8_lossy(&buf[..buf.len() - 1]).into_owned();
                return Ok(Some((word, &input[pos..])));
            }
            pos += 1;
        } else {
            buf.reserve(1);
            break;
        }
    }

    // Main parsing loop
    loop {
        if backslash {
            buf.reserve(7);

            if pos >= len {
                if flags_set(flags, EXTRACT_UNESCAPE_RELAX)
                    && (quote == 0 || flags_set(flags, EXTRACT_RELAX))
                {
                    buf.push(b'\\');
                    let word = String::from_utf8(buf).map_err(|_| Errno::EINVAL)?;
                    return Ok(Some((word, "")));
                }
                if flags_set(flags, EXTRACT_RELAX) {
                    let word = String::from_utf8(buf).map_err(|_| Errno::EINVAL)?;
                    return Ok(Some((word, "")));
                }
                return Err(Errno::EINVAL);
            }

            let c = bytes[pos];

            if flags_set(flags, EXTRACT_CUNESCAPE | EXTRACT_UNESCAPE_SEPARATORS) {
                if flags_set(flags, EXTRACT_CUNESCAPE) {
                    if let Some((consumed, out)) = cunescape_one(&bytes[pos..], false) {
                        match out {
                            CunescapeOut::Byte(b) => buf.push(b),
                            CunescapeOut::Char(ch) => {
                                buf.extend_from_slice(&utf8_encode_unichar(ch))
                            }
                        }
                        pos += consumed;
                        backslash = false;
                        if pos < len {
                            pos += 1;
                        }
                        continue;
                    }
                }

                if flags_set(flags, EXTRACT_UNESCAPE_SEPARATORS)
                    && (is_separator(c, sep) || c == b'\\')
                {
                    buf.push(c);
                } else if flags_set(flags, EXTRACT_UNESCAPE_RELAX) {
                    buf.push(b'\\');
                    buf.push(c);
                } else {
                    return Err(Errno::EINVAL);
                }
            } else {
                buf.push(c);
            }

            backslash = false;
        } else if quote != 0 {
            loop {
                if pos >= len {
                    if flags_set(flags, EXTRACT_RELAX) {
                        let word = String::from_utf8(buf).map_err(|_| Errno::EINVAL)?;
                        return Ok(Some((word, "")));
                    }
                    return Err(Errno::EINVAL);
                }
                let c = bytes[pos];
                if c == quote {
                    quote = 0;
                    if flags_set(flags, EXTRACT_UNQUOTE) {
                        pos += 1;
                        break;
                    }
                } else if c == b'\\' && !flags_set(flags, EXTRACT_RETAIN_ESCAPE) {
                    backslash = true;
                    pos += 1;
                    break;
                }

                buf.reserve(2);
                buf.push(c);

                if quote == 0 {
                    pos += 1;
                    break;
                }

                pos += 1;
            }
        } else {
            loop {
                if pos >= len {
                    let word = String::from_utf8(buf).map_err(|_| Errno::EINVAL)?;
                    return Ok(Some((word, "")));
                }
                let c = bytes[pos];
                if c == b'\'' || c == b'"' {
                    quote = c;
                    if !flags_set(flags, EXTRACT_KEEP_QUOTE) {
                        pos += 1;
                        break;
                    }
                } else if c == b'\\' && !flags_set(flags, EXTRACT_RETAIN_ESCAPE) {
                    backslash = true;
                    pos += 1;
                    break;
                } else if is_separator(c, sep) {
                    if flags_set(flags, EXTRACT_DONT_COALESCE_SEPARATORS) {
                        if !flags_set(flags, EXTRACT_RETAIN_SEPARATORS) {
                            pos += 1;
                        }
                        let word = String::from_utf8(buf).map_err(|_| Errno::EINVAL)?;
                        return Ok(Some((word, &input[pos..])));
                    }
                    if !flags_set(flags, EXTRACT_RETAIN_SEPARATORS) {
                        pos += 1;
                        while pos < len && is_separator(bytes[pos], sep) {
                            pos += 1;
                        }
                        if pos >= len {
                            let word = String::from_utf8(buf).map_err(|_| Errno::EINVAL)?;
                            return Ok(Some((word, "")));
                        }
                    }
                    let word = String::from_utf8(buf).map_err(|_| Errno::EINVAL)?;
                    return Ok(Some((word, &input[pos..])));
                }

                buf.reserve(2);
                buf.push(c);

                if quote != 0 {
                    pos += 1;
                    break;
                }

                pos += 1;
            }
        }

        if pos >= len && !backslash {
            let word = String::from_utf8(buf).map_err(|_| Errno::EINVAL)?;
            return Ok(Some((word, "")));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_single_word() {
        let (word, rest) = extract_first_word("hello", None, 0).unwrap().unwrap();
        assert_eq!(word, "hello");
        assert_eq!(rest, "");
    }

    #[test]
    fn test_extract_two_words() {
        let (word, rest) = extract_first_word("hello world", None, 0).unwrap().unwrap();
        assert_eq!(word, "hello");
        let (word2, rest2) = extract_first_word(rest, None, 0).unwrap().unwrap();
        assert_eq!(word2, "world");
        assert_eq!(rest2, "");
        assert!(extract_first_word(rest2, None, 0).unwrap().is_none());
    }

    #[test]
    fn test_extract_leading_whitespace() {
        let (word, _) = extract_first_word("   hello", None, 0).unwrap().unwrap();
        assert_eq!(word, "hello");
    }

    #[test]
    fn test_extract_empty_string() {
        assert!(extract_first_word("", None, 0).unwrap().is_none());
    }

    #[test]
    fn test_extract_whitespace_only() {
        assert!(extract_first_word("   \t\n  ", None, 0).unwrap().is_none());
    }

    #[test]
    fn test_extract_quoted_single() {
        let (word, rest) = extract_first_word("'hello world' rest", None, EXTRACT_UNQUOTE)
            .unwrap()
            .unwrap();
        assert_eq!(word, "hello world");
        let (word2, _) = extract_first_word(rest, None, EXTRACT_UNQUOTE)
            .unwrap()
            .unwrap();
        assert_eq!(word2, "rest");
    }

    #[test]
    fn test_extract_quoted_double() {
        let (word, _) = extract_first_word("\"hello world\" rest", None, EXTRACT_UNQUOTE)
            .unwrap()
            .unwrap();
        assert_eq!(word, "hello world");
    }

    #[test]
    fn test_extract_custom_separators() {
        let (word, rest) = extract_first_word("hello,world", Some(","), 0)
            .unwrap()
            .unwrap();
        assert_eq!(word, "hello");
        let (word2, _) = extract_first_word(rest, Some(","), 0).unwrap().unwrap();
        assert_eq!(word2, "world");
    }

    #[test]
    fn test_extract_dont_coalesce_separators() {
        let (w1, r1) = extract_first_word("a  b", None, EXTRACT_DONT_COALESCE_SEPARATORS)
            .unwrap()
            .unwrap();
        assert_eq!(w1, "a");
        let (w2, r2) = extract_first_word(r1, None, EXTRACT_DONT_COALESCE_SEPARATORS)
            .unwrap()
            .unwrap();
        assert_eq!(w2, "");
        let (w3, _) = extract_first_word(r2, None, EXTRACT_DONT_COALESCE_SEPARATORS)
            .unwrap()
            .unwrap();
        assert_eq!(w3, "b");
    }

    #[test]
    fn test_extract_keep_quote() {
        let (word, _) = extract_first_word("\"hello\"", None, EXTRACT_KEEP_QUOTE)
            .unwrap()
            .unwrap();
        assert_eq!(word, "\"hello\"");
    }

    #[test]
    fn test_extract_trailing_whitespace() {
        let (word, rest) = extract_first_word("hello   ", None, 0).unwrap().unwrap();
        assert_eq!(word, "hello");
        assert!(extract_first_word(rest, None, 0).unwrap().is_none());
    }

    #[test]
    fn test_extract_unclosed_quote_no_relax() {
        assert!(extract_first_word("\"hello", None, 0).is_err());
    }

    #[test]
    fn test_extract_relax_unclosed_quote() {
        let (word, _) = extract_first_word("\"hello", None, EXTRACT_RELAX)
            .unwrap()
            .unwrap();
        assert_eq!(word, "hello");
    }

    #[test]
    fn test_extract_retain_escape() {
        let (word, _) = extract_first_word("hel\\lo", None, EXTRACT_RETAIN_ESCAPE)
            .unwrap()
            .unwrap();
        assert_eq!(word, "hel\\lo");
    }

    #[test]
    fn test_extract_backslash_at_end_no_relax() {
        assert!(extract_first_word("hello\\", None, 0).is_err());
    }

    #[test]
    fn test_extract_multiple_whitespace() {
        let (w1, r1) = extract_first_word("hello    world", None, 0)
            .unwrap()
            .unwrap();
        assert_eq!(w1, "hello");
        let (w2, _) = extract_first_word(r1, None, 0).unwrap().unwrap();
        assert_eq!(w2, "world");
    }

    // ── cunescape unit tests ────────────────────────────────────────────

    #[test]
    fn test_cunescape_newline() {
        let (consumed, out) = cunescape_one(b"n", false).unwrap();
        assert_eq!(consumed, 1);
        assert!(matches!(out, CunescapeOut::Byte(0x0A)));
    }

    #[test]
    fn test_cunescape_hex() {
        let (consumed, out) = cunescape_one(b"x41", false).unwrap();
        assert_eq!(consumed, 3);
        assert!(matches!(out, CunescapeOut::Byte(0x41)));
    }

    #[test]
    fn test_cunescape_unicode_4digit() {
        let (consumed, out) = cunescape_one(b"u0041", false).unwrap();
        assert_eq!(consumed, 5);
        assert!(matches!(out, CunescapeOut::Char(0x41)));
    }

    #[test]
    fn test_cunescape_octal() {
        let (consumed, out) = cunescape_one(b"101", false).unwrap();
        assert_eq!(consumed, 3);
        assert!(matches!(out, CunescapeOut::Byte(65)));
    }

    #[test]
    fn test_cunescape_invalid() {
        assert!(cunescape_one(b"z", false).is_none());
    }

    // ── utf8_encode_unichar tests ──────────────────────────────────────

    #[test]
    fn test_utf8_encode_ascii() {
        assert_eq!(utf8_encode_unichar(0x41), vec![b'A']);
    }

    #[test]
    fn test_utf8_encode_2byte() {
        let bytes = utf8_encode_unichar(0x00E9); // é
        assert_eq!(bytes.len(), 2);
    }

    #[test]
    fn test_utf8_encode_3byte() {
        let bytes = utf8_encode_unichar(0x2026); // …
        assert_eq!(bytes.len(), 3);
    }

    #[test]
    fn test_utf8_encode_4byte() {
        let bytes = utf8_encode_unichar(0x1F600); // 😀
        assert_eq!(bytes.len(), 4);
    }

    #[test]
    fn test_unichar_is_valid() {
        assert!(unichar_is_valid(0x41));
        assert!(unichar_is_valid(0x10FFFF));
        assert!(!unichar_is_valid(0x110000));
        assert!(!unichar_is_valid(0xD800));
        assert!(!unichar_is_valid(0xFFFE));
    }
}

use std::ffi::CStr;
use std::ptr;

/// Byte-oriented result used at the C ABI boundary.  Unlike the ergonomic
/// Rust API above, this never treats a C string as UTF-8: C accepts arbitrary
/// non-NUL bytes in both input and output words.
enum ExtractBytesResult {
    NoWord,
    Word { word: Vec<u8>, next: Option<usize> },
}

/// Implement the pointer-visible part of C `extract_first_word()` over the
/// bytes before a C string's terminating NUL.  `Err` carries the input offset
/// at which C leaves `*p` on a parsing failure.
fn extract_first_word_bytes(
    input: &[u8],
    separators: &[u8],
    flags: u32,
) -> Result<ExtractBytesResult, (Errno, usize)> {
    if flags_set(flags, EXTRACT_KEEP_QUOTE) && flags_set(flags, EXTRACT_UNQUOTE) {
        return Err((Errno::EINVAL, 0));
    }

    let mut p = 0usize;
    let mut word = Vec::new();

    /* This follows the two loops in extract-word.c rather than using the
     * UTF-8 `String` facade.  In particular, quoting is active only for
     * EXTRACT_KEEP_QUOTE/EXTRACT_UNQUOTE, as in C. */
    loop {
        if p == input.len() {
            return Ok(ExtractBytesResult::NoWord);
        }
        if separators.contains(&input[p]) {
            if flags_set(flags, EXTRACT_DONT_COALESCE_SEPARATORS) {
                if !flags_set(flags, EXTRACT_RETAIN_SEPARATORS) {
                    p += 1;
                }
                return Ok(ExtractBytesResult::Word {
                    word,
                    next: (p < input.len()).then_some(p),
                });
            }
            p += 1;
        } else {
            break;
        }
    }

    let mut quote = 0u8;
    let mut backslash = false;
    loop {
        if backslash {
            if p == input.len() {
                if (flags_set(flags, EXTRACT_UNESCAPE_RELAX)
                    && (quote == 0 || flags_set(flags, EXTRACT_RELAX)))
                    || flags_set(flags, EXTRACT_RELAX)
                {
                    if flags_set(flags, EXTRACT_UNESCAPE_RELAX) {
                        word.push(b'\\');
                    }
                    return Ok(ExtractBytesResult::Word { word, next: None });
                }
                return Err((Errno::EINVAL, p));
            }

            let c = input[p];
            if flags_set(flags, EXTRACT_CUNESCAPE | EXTRACT_UNESCAPE_SEPARATORS) {
                if flags_set(flags, EXTRACT_CUNESCAPE) {
                    if let Some((consumed, output)) = cunescape_one(&input[p..], false) {
                        match output {
                            CunescapeOut::Byte(byte) => word.push(byte),
                            CunescapeOut::Char(ch) => {
                                word.extend_from_slice(&utf8_encode_unichar(ch))
                            }
                        }
                        p += consumed;
                        backslash = false;
                        continue;
                    }
                }

                if flags_set(flags, EXTRACT_UNESCAPE_SEPARATORS)
                    && (separators.contains(&c) || c == b'\\')
                {
                    word.push(c);
                } else if flags_set(flags, EXTRACT_UNESCAPE_RELAX) {
                    word.extend_from_slice(&[b'\\', c]);
                } else {
                    return Err((Errno::EINVAL, p));
                }
            } else {
                word.push(c);
            }

            backslash = false;
            p += 1;
            continue;
        }

        if quote != 0 {
            if p == input.len() {
                if flags_set(flags, EXTRACT_RELAX) {
                    return Ok(ExtractBytesResult::Word { word, next: None });
                }
                return Err((Errno::EINVAL, p));
            }

            let c = input[p];
            if c == quote {
                quote = 0;
                if flags_set(flags, EXTRACT_UNQUOTE) {
                    p += 1;
                    continue;
                }
                word.push(c);
                p += 1;
                continue;
            }
            if c == b'\\' && !flags_set(flags, EXTRACT_RETAIN_ESCAPE) {
                backslash = true;
                p += 1;
                continue;
            }
            word.push(c);
            p += 1;
            continue;
        }

        if p == input.len() {
            return Ok(ExtractBytesResult::Word { word, next: None });
        }
        let c = input[p];
        if (c == b'\'' || c == b'"') && flags_set(flags, EXTRACT_KEEP_QUOTE | EXTRACT_UNQUOTE) {
            quote = c;
            if flags_set(flags, EXTRACT_UNQUOTE) {
                p += 1;
                continue;
            }
            word.push(c);
            p += 1;
            continue;
        }
        if c == b'\\' && !flags_set(flags, EXTRACT_RETAIN_ESCAPE) {
            backslash = true;
            p += 1;
            continue;
        }
        if separators.contains(&c) {
            if flags_set(flags, EXTRACT_DONT_COALESCE_SEPARATORS) {
                if !flags_set(flags, EXTRACT_RETAIN_SEPARATORS) {
                    p += 1;
                }
                return Ok(ExtractBytesResult::Word {
                    word,
                    next: (p < input.len()).then_some(p),
                });
            }
            if !flags_set(flags, EXTRACT_RETAIN_SEPARATORS) {
                while p < input.len() && separators.contains(&input[p]) {
                    p += 1;
                }
            }
            return Ok(ExtractBytesResult::Word {
                word,
                next: (p < input.len()).then_some(p),
            });
        }
        word.push(c);
        p += 1;
    }
}

/// C-compatible byte-preserving wrapper around `extract_first_word`.
/// Returns C-allocator storage in `*word` on success and publishes neither
/// output pointer on parsing/allocation failure, matching extract-word.c.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_extract_first_word(
    p: *mut *const c_char,
    word: *mut *mut c_char,
    separators: *const c_char,
    flags: u32,
) -> i32 {
    if p.is_null() || word.is_null() {
        return Errno::EINVAL.to_neg_errno();
    }
    // SAFETY: `p` and `word` are writable under this export's contract.
    let input = unsafe { *p };
    if input.is_null() {
        // SAFETY: successful end-of-input clears both C outputs.
        unsafe { *word = ptr::null_mut() };
        return 0;
    }
    // SAFETY: the contract supplies live NUL-terminated C strings.
    let input_bytes = unsafe { CStr::from_ptr(input) }.to_bytes();
    let separator_bytes = if separators.is_null() {
        DEFAULT_SEPARATORS
    } else {
        // SAFETY: the contract supplies a live NUL-terminated separator string.
        unsafe { CStr::from_ptr(separators) }.to_bytes()
    };

    match extract_first_word_bytes(input_bytes, separator_bytes, flags) {
        Ok(ExtractBytesResult::NoWord) => {
            // SAFETY: successful end-of-input clears both C outputs.
            unsafe {
                *p = ptr::null();
                *word = ptr::null_mut();
            }
            0
        }
        Ok(ExtractBytesResult::Word { word: bytes, next }) => {
            let Some(allocation) = bytes.len().checked_add(1) else {
                return Errno::ENOMEM.to_neg_errno();
            };
            let allocated = crate::ffi::malloc(allocation).cast::<c_char>();
            if allocated.is_null() {
                return Errno::ENOMEM.to_neg_errno();
            }
            // SAFETY: `allocated` names `bytes.len() + 1` writable C-allocator
            // bytes, and `bytes` has no interior NUL because the parser rejects
            // escaped NUL.  The input pointer is advanced only after allocation.
            unsafe {
                ptr::copy_nonoverlapping(bytes.as_ptr(), allocated.cast::<u8>(), bytes.len());
                *allocated.add(bytes.len()) = 0;
                *word = allocated;
                *p = next.map_or(ptr::null(), |offset| input.add(offset));
            }
            1
        }
        Err((error, offset)) => {
            // SAFETY: the reported offset is within the source C string.
            unsafe { *p = input.add(offset) };
            error.to_neg_errno()
        }
    }
}
