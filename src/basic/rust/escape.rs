// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/basic/escape.c, src/basic/escape.h
//
// C-style string escaping and unescaping.
//
// cescape: escape special chars to \nnn octal notation.
// cunescape: unescape \xNN, \uNNNN, \UNNNNNNNN, \nnn sequences back to chars.
// Also provides octescape, decescape, shell_escape, shell_maybe_quote,
// xescape_full, and quote_command_line.

use libc::c_char;

mod allocating;
mod core_abi;
mod full_abi;

pub use allocating::{
    decescape, octescape, rs_decescape, rs_octescape, rs_shell_escape, shell_escape,
};
pub(crate) use allocating::{malloc_c_string, try_strcpy_backslash_escaped};

// ── Error constants ───────────────────────────────────────────────────────

const EINVAL: i32 = -22;
const ENOMEM: i32 = -12;
const ENOBUFS: i32 = -105;

// ── Unescape flags ────────────────────────────────────────────────────────

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct UnescapeFlags: u32 {
        const RELAX = 1 << 0;
        const ACCEPT_NUL = 1 << 1;
    }
}

// ── XEscape flags ─────────────────────────────────────────────────────────

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct XEscapeFlags: u32 {
        const XESCAPE_8_BIT = 1 << 0;
        const XESCAPE_FORCE_ELLIPSIS = 1 << 1;
    }
}

// ── Shell escape flags ────────────────────────────────────────────────────

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct ShellEscapeFlags: u32 {
        const SHELL_ESCAPE_POSIX = 1 << 1;
        const SHELL_ESCAPE_EMPTY = 1 << 2;
    }
}

// ── Internal helpers ──────────────────────────────────────────────────────

/// Convert low 3 bits to octal digit.
fn octchar(c: u8) -> u8 {
    b'0' + (c & 7)
}

/// Convert 4-bit value to hex digit.
fn hexchar(x: u8) -> u8 {
    if x < 10 { b'0' + x } else { b'a' + (x - 10) }
}

/// Parse a hex digit, returning its value or None.
fn unhexchar(c: u8) -> Option<i32> {
    match c {
        b'0'..=b'9' => Some((c - b'0') as i32),
        b'a'..=b'f' => Some((c - b'a' + 10) as i32),
        b'A'..=b'F' => Some((c - b'A' + 10) as i32),
        _ => None,
    }
}

/// Parse an octal digit, returning its value or None.
fn unoctchar(c: u8) -> Option<i32> {
    match c {
        b'0'..=b'7' => Some((c - b'0') as i32),
        _ => None,
    }
}

/// Check if a Unicode codepoint is valid (not surrogate, not out of range).
fn unichar_is_valid(c: u32) -> bool {
    c <= 0x10FFFF
        && !(0xD800..=0xDFFF).contains(&c)
        // Match utf8.c: systemd rejects Unicode noncharacters, not merely
        // malformed UTF-8 or UTF-16 surrogate code points.
        && !(0xFDD0..=0xFDEF).contains(&c)
        && c & 0xFFFE != 0xFFFE
}

/// Encode a Unicode codepoint into a caller-owned UTF-8 buffer.
///
/// `cunescape_one()` has already validated Unicode inputs before this helper
/// is used, so every accepted codepoint has a one-to-four-byte encoding.
fn utf8_encode_unichar_into(g: u32, buf: &mut [u8; 4]) -> usize {
    if g < 0x80 {
        buf[0] = g as u8;
        1
    } else if g < 0x800 {
        buf[0] = (g >> 6) as u8 | 0xC0;
        buf[1] = (g & 0x3F) as u8 | 0x80;
        2
    } else if g < 0x10000 {
        buf[0] = (g >> 12) as u8 | 0xE0;
        buf[1] = ((g >> 6) & 0x3F) as u8 | 0x80;
        buf[2] = (g & 0x3F) as u8 | 0x80;
        3
    } else {
        buf[0] = (g >> 18) as u8 | 0xF0;
        buf[1] = ((g >> 12) & 0x3F) as u8 | 0x80;
        buf[2] = ((g >> 6) & 0x3F) as u8 | 0x80;
        buf[3] = (g & 0x3F) as u8 | 0x80;
        4
    }
}

/// Encode a Unicode codepoint to an owned UTF-8 byte sequence.
fn utf8_encode_unichar(g: u32) -> Vec<u8> {
    let mut buf = [0u8; 4];
    let len = utf8_encode_unichar_into(g, &mut buf);
    buf[..len].to_vec()
}

/// Return byte length of the first valid UTF-8 character in `s`, or -1 if invalid.
fn utf8_encoded_valid_unichar(s: &[u8]) -> i32 {
    if s.is_empty() {
        return -1;
    }
    let first = s[0];
    let len: usize = if first < 0x80 {
        1
    } else if first < 0xC0 {
        return -1;
    } else if first < 0xE0 {
        2
    } else if first < 0xF0 {
        3
    } else if first < 0xF8 {
        4
    } else {
        return -1;
    };
    if s.len() < len {
        return -1;
    }
    // Verify continuation bytes
    for i in 1..len {
        if s[i] & 0xC0 != 0x80 {
            return -1;
        }
    }
    // Verify codepoint range
    let codepoint = match len {
        1 => first as u32,
        2 => ((first & 0x1F) as u32) << 6 | ((s[1] & 0x3F) as u32),
        3 => ((first & 0x0F) as u32) << 12 | ((s[1] & 0x3F) as u32) << 6 | ((s[2] & 0x3F) as u32),
        4 => {
            ((first & 0x07) as u32) << 18
                | ((s[1] & 0x3F) as u32) << 12
                | ((s[2] & 0x3F) as u32) << 6
                | ((s[3] & 0x3F) as u32)
        }
        _ => return -1,
    };
    if !unichar_is_valid(codepoint) {
        return -1;
    }
    // Overlong check for 2-byte: must be >= 0x80
    if len == 2 && codepoint < 0x80 {
        return -1;
    }
    // Overlong check for 3-byte: must be >= 0x800
    if len == 3 && codepoint < 0x800 {
        return -1;
    }
    // Overlong check for 4-byte: must be >= 0x10000
    if len == 4 && codepoint < 0x10000 {
        return -1;
    }
    len as i32
}

/// Check if byte is a C0/C1 control character.
fn char_is_cc(c: u8) -> bool {
    c < b' ' || c == 0x7F
}

// ── cescape_char ──────────────────────────────────────────────────────────

/// Escape a single byte to C string notation.
/// Returns the escaped bytes (1-4 bytes).
pub fn cescape_char(c: u8) -> Vec<u8> {
    let mut escaped = [0; 4];
    let length = cescape_char_into(c, &mut escaped);
    escaped[..length].to_vec()
}

/// Write C-style escaping for one byte into a caller-owned fixed buffer.
///
/// The result is always one to four bytes, so this is allocation-free and is
/// the primitive used by the fixed-size C ABI `cescape_char()` adapter.
pub(crate) fn cescape_char_into(c: u8, output: &mut [u8; 4]) -> usize {
    let bytes: &[u8] = match c {
        0x07 => b"\\a",
        0x08 => b"\\b",
        0x0C => b"\\f",
        0x0A => b"\\n",
        0x0D => b"\\r",
        0x09 => b"\\t",
        0x0B => b"\\v",
        0x5C => b"\\\\",
        0x22 => b"\\\"",
        0x27 => b"\\'",
        _ if c < b' ' || c >= 127 => {
            *output = [b'\\', octchar(c >> 6), octchar(c >> 3), octchar(c)];
            return 4;
        }
        _ => {
            output[0] = c;
            return 1;
        }
    };
    output[..bytes.len()].copy_from_slice(bytes);
    bytes.len()
}

fn append_cescape_char(output: &mut Vec<u8>, c: u8) {
    let mut escaped = [0; 4];
    let length = cescape_char_into(c, &mut escaped);
    output.extend_from_slice(&escaped[..length]);
}

// ── cescape ───────────────────────────────────────────────────────────────

/// C-style string escaping. Returns the escaped string.
pub fn cescape(s: &[u8]) -> Vec<u8> {
    let mut result = Vec::with_capacity(s.len());
    for &byte in s {
        result.extend_from_slice(&cescape_char(byte));
    }
    result
}

/// C-style string escaping with explicit length.
pub fn cescape_length(s: &[u8], n: usize) -> Vec<u8> {
    let len = n.min(s.len());
    cescape(&s[..len])
}

// ── cunescape_one ─────────────────────────────────────────────────────────

/// Result of unescaping a single escape sequence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CUnescapeResult {
    /// The unescaped Unicode codepoint.
    pub ch: u32,
    /// Whether this was an 8-bit byte escape (hex or octal).
    pub eight_bit: bool,
    /// Number of bytes consumed from input after the backslash.
    pub consumed: usize,
}

/// Unescape a single C-style escape sequence starting after the backslash.
/// `p` is the remaining input after the `\`.
/// Returns `CUnescapeResult` on success, or negative errno on failure.
pub fn cunescape_one(p: &[u8], accept_nul: bool) -> Result<CUnescapeResult, i32> {
    if p.is_empty() {
        return Err(EINVAL);
    }

    let c = p[0];

    match c {
        b'a' => Ok(CUnescapeResult {
            ch: 0x07,
            eight_bit: false,
            consumed: 1,
        }),
        b'b' => Ok(CUnescapeResult {
            ch: 0x08,
            eight_bit: false,
            consumed: 1,
        }),
        b'f' => Ok(CUnescapeResult {
            ch: 0x0C,
            eight_bit: false,
            consumed: 1,
        }),
        b'n' => Ok(CUnescapeResult {
            ch: 0x0A,
            eight_bit: false,
            consumed: 1,
        }),
        b'r' => Ok(CUnescapeResult {
            ch: 0x0D,
            eight_bit: false,
            consumed: 1,
        }),
        b't' => Ok(CUnescapeResult {
            ch: 0x09,
            eight_bit: false,
            consumed: 1,
        }),
        b'v' => Ok(CUnescapeResult {
            ch: 0x0B,
            eight_bit: false,
            consumed: 1,
        }),
        b'\\' => Ok(CUnescapeResult {
            ch: 0x5C,
            eight_bit: false,
            consumed: 1,
        }),
        b'"' => Ok(CUnescapeResult {
            ch: 0x22,
            eight_bit: false,
            consumed: 1,
        }),
        b'\'' => Ok(CUnescapeResult {
            ch: 0x27,
            eight_bit: false,
            consumed: 1,
        }),
        b's' => Ok(CUnescapeResult {
            ch: 0x20,
            eight_bit: false,
            consumed: 1,
        }),
        b'x' => {
            if p.len() < 3 {
                return Err(EINVAL);
            }
            let a = unhexchar(p[1]).ok_or(EINVAL)?;
            let b_val = unhexchar(p[2]).ok_or(EINVAL)?;
            if a == 0 && b_val == 0 && !accept_nul {
                return Err(EINVAL);
            }
            Ok(CUnescapeResult {
                ch: ((a << 4) | b_val) as u32,
                eight_bit: true,
                consumed: 3,
            })
        }
        b'u' => {
            if p.len() < 5 {
                return Err(EINVAL);
            }
            let mut c_val: u32 = 0;
            for i in 0..4 {
                let a = unhexchar(p[1 + i]).ok_or(EINVAL)?;
                c_val = (c_val << 4) | (a as u32);
            }
            if c_val == 0 && !accept_nul {
                return Err(EINVAL);
            }
            // Current C permits Unicode noncharacters in its 16-bit `\\u`
            // form but rejects UTF-16 surrogates because they have no valid
            // UTF-8 encoding. (`\\U` deliberately uses the stricter helper.)
            if (0xD800..=0xDFFF).contains(&c_val) {
                return Err(EINVAL);
            }
            Ok(CUnescapeResult {
                ch: c_val,
                eight_bit: false,
                consumed: 5,
            })
        }
        b'U' => {
            if p.len() < 9 {
                return Err(EINVAL);
            }
            let mut c_val: u32 = 0;
            for i in 0..8 {
                let a = unhexchar(p[1 + i]).ok_or(EINVAL)?;
                c_val = (c_val << 4) | (a as u32);
            }
            if c_val == 0 && !accept_nul {
                return Err(EINVAL);
            }
            if !unichar_is_valid(c_val) {
                return Err(EINVAL);
            }
            Ok(CUnescapeResult {
                ch: c_val,
                eight_bit: false,
                consumed: 9,
            })
        }
        b'0'..=b'7' => {
            if p.len() < 3 {
                return Err(EINVAL);
            }
            let a = unoctchar(p[0]).ok_or(EINVAL)?;
            let b_val = unoctchar(p[1]).ok_or(EINVAL)?;
            let c_val = unoctchar(p[2]).ok_or(EINVAL)?;
            if a == 0 && b_val == 0 && c_val == 0 && !accept_nul {
                return Err(EINVAL);
            }
            let m: u32 = ((a as u32) << 6) | ((b_val as u32) << 3) | (c_val as u32);
            if m > 255 {
                return Err(EINVAL);
            }
            Ok(CUnescapeResult {
                ch: m,
                eight_bit: true,
                consumed: 3,
            })
        }
        _ => Err(EINVAL),
    }
}

// ── cunescape ─────────────────────────────────────────────────────────────

/// Undo C-style string escaping. Returns the unescaped bytes.
pub fn cunescape(s: &[u8], flags: UnescapeFlags) -> Result<Vec<u8>, i32> {
    try_cunescape_bytes(s, &[], flags)
}

/// Decode C-style escaping into caller-owned storage without allocating.
///
/// `output` must have room for `prefix.len() + source.len()` bytes, the exact
/// maximum output length of current C's unescape algorithm. The function
/// validates and measures the complete source before writing any byte, so a
/// parse or capacity error leaves `output` untouched. On success all unused
/// bytes in `output` are zeroed; callers can therefore safely use a zeroed
/// secret buffer without exposing a partially decoded value.
pub fn try_cunescape_into(
    source: &[u8],
    prefix: &[u8],
    flags: UnescapeFlags,
    output: &mut [u8],
) -> Result<usize, i32> {
    let relax = flags.contains(UnescapeFlags::RELAX);
    let accept_nul = flags.contains(UnescapeFlags::ACCEPT_NUL);
    let maximum = prefix.len().checked_add(source.len()).ok_or(ENOMEM)?;
    if output.len() < maximum {
        return Err(ENOBUFS);
    }
    // A second pass validates every escape and computes the actual decoded
    // length before the output buffer is touched.
    let mut required = prefix.len();
    let mut index = 0;
    while index < source.len() {
        if source[index] != b'\\' {
            required = required.checked_add(1).ok_or(ENOMEM)?;
            index += 1;
            continue;
        }
        let remaining = source.len() - index;
        if remaining == 1 {
            if !relax {
                return Err(EINVAL);
            }
            required = required.checked_add(1).ok_or(ENOMEM)?;
            index += 1;
            continue;
        }
        match cunescape_one(&source[index + 1..], accept_nul) {
            Ok(unescaped) => {
                let width = if unescaped.eight_bit {
                    1
                } else {
                    let mut encoded = [0; 4];
                    utf8_encode_unichar_into(unescaped.ch, &mut encoded)
                };
                required = required.checked_add(width).ok_or(ENOMEM)?;
                index += unescaped.consumed + 1;
            }
            Err(_) if relax => {
                required = required.checked_add(1).ok_or(ENOMEM)?;
                index += 1;
            }
            Err(error) => return Err(error),
        }
    }
    output.fill(0);
    output[..prefix.len()].copy_from_slice(prefix);
    let mut written = prefix.len();
    let mut index = 0;
    while index < source.len() {
        if source[index] != b'\\' {
            output[written] = source[index];
            written += 1;
            index += 1;
            continue;
        }
        let remaining = source.len() - index;
        if remaining == 1 {
            debug_assert!(relax);
            output[written] = b'\\';
            written += 1;
            break;
        }
        match cunescape_one(&source[index + 1..], accept_nul) {
            Ok(unescaped) => {
                index += unescaped.consumed + 1;
                if unescaped.eight_bit {
                    output[written] = unescaped.ch as u8;
                    written += 1;
                } else {
                    let mut encoded = [0; 4];
                    let width = utf8_encode_unichar_into(unescaped.ch, &mut encoded);
                    output[written..written + width].copy_from_slice(&encoded[..width]);
                    written += width;
                }
            }
            Err(_) if relax => {
                output[written] = b'\\';
                written += 1;
                index += 1;
            }
            Err(_) => unreachable!("first pass validated every escape"),
        }
    }
    debug_assert_eq!(written, required);
    Ok(written)
}

/// Fallibly undo C-style escaping from arbitrary bytes, optionally prepending
/// arbitrary bytes to the output.
///
/// This allocating convenience wrapper delegates all parsing and writes to
/// `try_cunescape_into()`. It reports allocation failure as `-ENOMEM`.
pub fn try_cunescape_bytes(
    source: &[u8],
    prefix: &[u8],
    flags: UnescapeFlags,
) -> Result<Vec<u8>, i32> {
    let capacity = prefix.len().checked_add(source.len()).ok_or(ENOMEM)?;
    let mut output = Vec::new();
    output.try_reserve_exact(capacity).map_err(|_| ENOMEM)?;
    output.resize(capacity, 0);
    let length = try_cunescape_into(source, prefix, flags, &mut output)?;
    output.truncate(length);
    Ok(output)
}

/// Undo C-style string escaping with a UTF-8 convenience prefix.
pub fn cunescape_with_prefix(s: &[u8], prefix: &str, flags: UnescapeFlags) -> Result<Vec<u8>, i32> {
    try_cunescape_bytes(s, prefix.as_bytes(), flags)
}

// ── xescape_full ──────────────────────────────────────────────────────────

/// Escape all chars in `bad` plus \ and control chars in \xFF style.
/// Truncates with "..." if console_width is reached.
pub fn xescape_full(s: &str, bad: &str, console_width: usize, flags: XEscapeFlags) -> String {
    if console_width == 0 {
        return String::new();
    }

    let s_bytes = s.as_bytes();
    let bad_bytes = bad.as_bytes();
    let force_ellipsis = flags.contains(XEscapeFlags::XESCAPE_FORCE_ELLIPSIS);
    let allow_8bit = flags.contains(XEscapeFlags::XESCAPE_8_BIT);

    let alloc_size = s_bytes.len().min(console_width) * 4 + 1;
    let mut ans = vec![b'_'; alloc_size];

    let mut t: usize = 0;
    let mut prev: usize = 0;
    let mut prev2: usize = 0;
    let mut fi: usize = 0;

    loop {
        let tmp_t = t;

        if fi >= s_bytes.len() {
            if force_ellipsis {
                break;
            }
            ans.truncate(t);
            return String::from_utf8_lossy(&ans).into_owned();
        }

        let uc = s_bytes[fi];
        let need_escape =
            uc < b' ' || (!allow_8bit && uc >= 127) || uc == b'\\' || bad_bytes.contains(&uc);

        if need_escape {
            if t + 4 + 3 * (force_ellipsis as usize) > console_width {
                break;
            }
            ans[t] = b'\\';
            ans[t + 1] = b'x';
            ans[t + 2] = hexchar(uc >> 4);
            ans[t + 3] = hexchar(uc & 0xF);
            t += 4;
        } else {
            if t + 1 + 3 * (force_ellipsis as usize) > console_width {
                break;
            }
            ans[t] = uc;
            t += 1;
        }

        prev2 = prev;
        prev = tmp_t;
        fi += 1;
    }

    let c = if console_width < 3 { console_width } else { 3 };
    let off = if console_width - c >= t {
        t
    } else if console_width - c >= prev {
        prev
    } else if console_width - c >= prev2 {
        prev2
    } else {
        console_width - c
    };

    ans.truncate(off + c);
    for i in 0..c {
        if off + i < ans.len() {
            ans[off + i] = b'.';
        }
    }
    String::from_utf8_lossy(&ans[..off + c]).into_owned()
}

// ── shell_maybe_quote ─────────────────────────────────────────────────────

/// Encloses a string in quotes if necessary for shell safety.
pub fn shell_maybe_quote(s: &str, flags: ShellEscapeFlags) -> String {
    let s_bytes = s.as_bytes();

    if flags.contains(ShellEscapeFlags::SHELL_ESCAPE_EMPTY) && s.is_empty() {
        return "\"\"".to_string();
    }

    // Scan for chars that need quoting
    let mut pi: usize = 0;
    while pi < s_bytes.len() {
        let l = utf8_encoded_valid_unichar(&s_bytes[pi..]);
        let uc = s_bytes[pi];
        if l < 0 || char_is_cc(uc) {
            break;
        }
        let needs_quote = uc == b' '
            || uc == b'\t'
            || uc == b'\n'
            || uc == b'\r'
            || uc == b'"'
            || uc == b'\\'
            || uc == b'`'
            || uc == b'$'
            || uc == b'*'
            || uc == b'?'
            || uc == b'['
            || uc == b'\''
            || uc == b'('
            || uc == b')'
            || uc == b'<'
            || uc == b'>'
            || uc == b'|'
            || uc == b'&'
            || uc == b';'
            || uc == b'!';
        if needs_quote {
            break;
        }
        pi += if l > 0 { l as usize } else { 1 };
    }

    if pi >= s_bytes.len() {
        return s.to_string();
    }

    let posix = flags.contains(ShellEscapeFlags::SHELL_ESCAPE_POSIX);
    let mut result = Vec::with_capacity(s.len() * 4 + 4);

    if posix {
        result.extend_from_slice(b"$'");
    } else {
        result.push(b'"');
    }

    // Copy the safe prefix
    result.extend_from_slice(&s_bytes[..pi]);

    // Escape the rest
    let bad: &[u8] = if posix { b"\\'" } else { b"\"\\`$" };
    result.extend_from_slice(&strcpy_backslash_escaped(&s_bytes[pi..], bad));

    if posix {
        result.push(b'\'');
    } else {
        result.push(b'"');
    }

    String::from_utf8_lossy(&result).into_owned()
}

// ── quote_command_line ────────────────────────────────────────────────────

/// Quotes each argv element and joins with spaces.
pub fn quote_command_line(argv: &[&str], flags: ShellEscapeFlags) -> String {
    let parts: Vec<String> = argv.iter().map(|a| shell_maybe_quote(a, flags)).collect();
    parts.join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cescape_char_newline() {
        assert_eq!(cescape_char(b'\n'), vec![b'\\', b'n']);
    }

    #[test]
    fn test_cescape_char_tab() {
        assert_eq!(cescape_char(b'\t'), vec![b'\\', b't']);
    }

    #[test]
    fn test_cescape_char_backslash() {
        assert_eq!(cescape_char(b'\\'), vec![b'\\', b'\\']);
    }

    #[test]
    fn test_cescape_char_double_quote() {
        assert_eq!(cescape_char(b'"'), vec![b'\\', b'"']);
    }

    #[test]
    fn test_cescape_char_printable() {
        assert_eq!(cescape_char(b'A'), vec![b'A']);
    }

    #[test]
    fn test_cescape_char_null() {
        assert_eq!(cescape_char(0), vec![b'\\', b'0', b'0', b'0']);
    }

    #[test]
    fn test_cescape_char_bell() {
        assert_eq!(cescape_char(0x07), vec![b'\\', b'a']);
    }

    #[test]
    fn test_cescape_char_high_byte() {
        let result = cescape_char(0xFF);
        assert_eq!(result.len(), 4);
        assert_eq!(result[0], b'\\');
    }

    #[test]
    fn test_cescape_simple_string() {
        assert_eq!(cescape(b"hello\nworld"), b"hello\\nworld".to_vec());
    }

    #[test]
    fn test_cescape_tab_string() {
        assert_eq!(cescape(b"a\tb"), b"a\\tb".to_vec());
    }

    #[test]
    fn test_cunescape_one_newline() {
        let r = cunescape_one(b"n", false).unwrap();
        assert_eq!(r.ch, 0x0A);
        assert_eq!(r.consumed, 1);
        assert!(!r.eight_bit);
    }

    #[test]
    fn test_cunescape_one_tab() {
        let r = cunescape_one(b"t", false).unwrap();
        assert_eq!(r.ch, 0x09);
        assert_eq!(r.consumed, 1);
    }

    #[test]
    fn test_cunescape_one_hex() {
        let r = cunescape_one(b"x41", false).unwrap();
        assert_eq!(r.ch, 0x41);
        assert_eq!(r.consumed, 3);
        assert!(r.eight_bit);
    }

    #[test]
    fn test_cunescape_one_hex_null_rejected() {
        assert!(cunescape_one(b"x00", false).is_err());
    }

    #[test]
    fn test_cunescape_one_hex_null_accepted() {
        let r = cunescape_one(b"x00", true).unwrap();
        assert_eq!(r.ch, 0);
    }

    #[test]
    fn test_cunescape_one_unicode_16bit() {
        let r = cunescape_one(b"u0041", false).unwrap();
        assert_eq!(r.ch, 0x41);
        assert_eq!(r.consumed, 5);
    }

    #[test]
    fn test_cunescape_one_octal() {
        let r = cunescape_one(b"101", false).unwrap();
        assert_eq!(r.ch, 65); // octal 101 = 'A'
        assert_eq!(r.consumed, 3);
        assert!(r.eight_bit);
    }

    #[test]
    fn test_cunescape_one_invalid() {
        assert!(cunescape_one(b"z", false).is_err());
        assert!(cunescape_one(b"", false).is_err());
    }

    #[test]
    fn test_cunescape_simple() {
        let result = cunescape(b"hello\\nworld", UnescapeFlags::empty()).unwrap();
        assert_eq!(result, b"hello\nworld");
    }

    #[test]
    fn test_cunescape_hex() {
        let result = cunescape(b"\\x41", UnescapeFlags::empty()).unwrap();
        assert_eq!(result, b"A");
    }

    #[test]
    fn test_cunescape_relax_trailing_backslash() {
        let result = cunescape(b"foo\\", UnescapeFlags::RELAX).unwrap();
        assert_eq!(result, b"foo\\");
    }

    #[test]
    fn test_cunescape_relax_invalid_escape() {
        let result = cunescape(b"foo\\zbar", UnescapeFlags::RELAX).unwrap();
        assert_eq!(result, b"foo\\zbar");
    }

    #[test]
    fn test_cunescape_with_prefix() {
        let result = cunescape_with_prefix(b"world", "hello ", UnescapeFlags::empty()).unwrap();
        assert_eq!(result, b"hello world");
    }

    #[test]
    fn test_try_cunescape_bytes_preserves_binary_prefix_and_nul() {
        let result = try_cunescape_bytes(b"\\x00A", &[0xff, 0], UnescapeFlags::ACCEPT_NUL).unwrap();
        assert_eq!(result, [0xff, 0, 0, b'A']);
    }

    #[test]
    fn test_try_cunescape_into_zeroes_tail_and_does_not_publish_on_error() {
        let mut output = [0xaa; 8];
        let length =
            try_cunescape_into(b"\\x00A", &[0xff], UnescapeFlags::ACCEPT_NUL, &mut output).unwrap();
        assert_eq!(length, 3);
        assert_eq!(&output[..length], [0xff, 0, b'A']);
        assert!(output[length..].iter().all(|byte| *byte == 0));

        let mut untouched = [0x5a; 4];
        assert_eq!(
            try_cunescape_into(b"\\q", &[], UnescapeFlags::empty(), &mut untouched),
            Err(EINVAL)
        );
        assert_eq!(untouched, [0x5a; 4]);

        assert_eq!(
            try_cunescape_into(b"abc", &[], UnescapeFlags::empty(), &mut untouched),
            Err(ENOBUFS)
        );
        assert_eq!(untouched, [0x5a; 4]);
    }

    #[test]
    fn test_octescape_basic() {
        let result = octescape(b"hello");
        assert_eq!(result, b"hello");
    }

    #[test]
    fn test_octescape_newline() {
        let result = octescape(b"\n");
        assert_eq!(result.len(), 4);
        assert_eq!(result[0], b'\\');
    }

    #[test]
    fn test_octescape_backslash() {
        let result = octescape(b"\\");
        assert_eq!(result.len(), 4);
        assert_eq!(result[0], b'\\');
    }

    #[test]
    fn test_decescape_basic() {
        let result = decescape(b"hello", b"");
        assert_eq!(result, b"hello");
    }

    #[test]
    fn test_decescape_newline() {
        let result = decescape(b"\n", b"");
        assert_eq!(result.len(), 4);
        assert_eq!(&result[..3], b"\\01");
    }

    #[test]
    fn test_decescape_bad_char() {
        let result = decescape(b"a:b", b":");
        assert_eq!(result[0], b'a');
        assert_eq!(result[1], b'\\');
    }

    #[test]
    fn test_shell_escape_basic() {
        assert_eq!(shell_escape("hello", ""), "hello");
    }

    #[test]
    fn test_shell_escape_bad_char() {
        let result = shell_escape("hello world", " ");
        assert_eq!(result, "hello\\ world");
    }

    #[test]
    fn test_xescape_full_basic() {
        let result = xescape_full("hello", "", 100, XEscapeFlags::empty());
        assert_eq!(result, "hello");
    }

    #[test]
    fn test_xescape_full_truncation() {
        let result = xescape_full("abcdefghij", "", 5, XEscapeFlags::empty());
        assert!(result.contains('.'));
        assert!(result.len() <= 5);
    }

    #[test]
    fn test_xescape_full_zero_width() {
        let result = xescape_full("hello", "", 0, XEscapeFlags::empty());
        assert_eq!(result, "");
    }

    #[test]
    fn test_shell_maybe_quote_no_quotes_needed() {
        assert_eq!(
            shell_maybe_quote("hello", ShellEscapeFlags::empty()),
            "hello"
        );
    }

    #[test]
    fn test_shell_maybe_quote_space() {
        let result = shell_maybe_quote("hello world", ShellEscapeFlags::empty());
        assert!(result.starts_with('"'));
        assert!(result.ends_with('"'));
    }

    #[test]
    fn test_shell_maybe_quote_posix() {
        let result = shell_maybe_quote("hello world", ShellEscapeFlags::SHELL_ESCAPE_POSIX);
        assert!(result.starts_with("$'"));
        assert!(result.ends_with('\''));
    }

    #[test]
    fn test_shell_maybe_quote_empty() {
        let result = shell_maybe_quote("", ShellEscapeFlags::SHELL_ESCAPE_EMPTY);
        assert_eq!(result, "\"\"");
    }

    #[test]
    fn test_quote_command_line() {
        let result = quote_command_line(&["echo", "hello world"], ShellEscapeFlags::empty());
        assert_eq!(result, "echo \"hello world\"");
    }

    #[test]
    fn test_unhexchar_all() {
        assert_eq!(unhexchar(b'0'), Some(0));
        assert_eq!(unhexchar(b'9'), Some(9));
        assert_eq!(unhexchar(b'a'), Some(10));
        assert_eq!(unhexchar(b'f'), Some(15));
        assert_eq!(unhexchar(b'A'), Some(10));
        assert_eq!(unhexchar(b'F'), Some(15));
        assert_eq!(unhexchar(b'g'), None);
    }

    #[test]
    fn test_utf8_encode_unichar_ascii() {
        assert_eq!(utf8_encode_unichar(0x41), vec![0x41]);
    }

    #[test]
    fn test_utf8_encode_unichar_2byte() {
        let result = utf8_encode_unichar(0xC9); // É
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn test_utf8_encode_unichar_3byte() {
        let result = utf8_encode_unichar(0x2603); // ☃
        assert_eq!(result.len(), 3);
    }

    #[test]
    fn test_utf8_encode_unichar_4byte() {
        let result = utf8_encode_unichar(0x1F600); // 😀
        assert_eq!(result.len(), 4);
    }

    #[test]
    fn test_unichar_is_valid() {
        assert!(unichar_is_valid(0x41));
        assert!(unichar_is_valid(0x10FFFF));
        assert!(!unichar_is_valid(0x110000));
        assert!(!unichar_is_valid(0xD800));
        assert!(!unichar_is_valid(0xDFFF));
    }

    #[test]
    fn test_cescape_length() {
        assert_eq!(cescape_length(b"ab\x01cd", 3), b"ab\\001");
    }
}
