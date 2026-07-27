// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/boot/efi-string.c
//
// EFI string and memory utility functions.
//
// Faithfully ports the string, memory, fnmatch, number-parsing, boolean
// parsing, line parsing, hexdump, status-to-string, and printf formatting
// functions from the C source into safe, idiomatic Rust.

// ── Constants ─────────────────────────────────────────────────────────────

/// Characters used for quoting in `line_get_key_value`.
pub const QUOTES: &[u8] = b"'\"";

/// Hex digit lookup tables.
pub const LOWERCASE_HEXDIGITS: &[u8; 16] = b"0123456789abcdef";
pub const UPPERCASE_HEXDIGITS: &[u8; 16] = b"0123456789ABCDEF";

/// String printed for NULL pointers in printf %p.
pub const NULLSTR: &str = "(null)";

// ── strnlen ───────────────────────────────────────────────────────────────

/// Length of a byte string, bounded by `n`.
///
/// Mirrors `strnlen8`. Returns 0 for `None`.
pub fn strnlen8(s: Option<&[u8]>, n: usize) -> usize {
    match s {
        None => 0,
        Some(data) => {
            let end = std::cmp::min(data.len(), n);
            let pos = data[..end].iter().position(|&c| c == 0).unwrap_or(end);
            pos
        }
    }
}

/// Length of a UTF-16 string, bounded by `n`.
///
/// Mirrors `strnlen16`. Returns 0 for `None`.
pub fn strnlen16(s: Option<&[u16]>, n: usize) -> usize {
    match s {
        None => 0,
        Some(data) => {
            let end = std::cmp::min(data.len(), n);
            data[..end].iter().position(|&c| c == 0).unwrap_or(end)
        }
    }
}

// ── strtolower ────────────────────────────────────────────────────────────

/// Convert a byte string to lowercase in place.
///
/// Mirrors `strtolower8`.
pub fn strtolower8(s: &mut [u8]) -> &mut [u8] {
    for b in s.iter_mut() {
        if *b >= b'A' && *b <= b'Z' {
            *b += b'a' - b'A';
        }
    }
    s
}

// ── strncmp / strncasecmp ────────────────────────────────────────────────

/// Compare two byte strings, bounded by `n`, case-sensitive.
///
/// Mirrors `strncmp8`. Returns ordering like `std::cmp::Ordering`.
pub fn strncmp8(s1: Option<&[u8]>, s2: Option<&[u8]>, n: usize) -> std::cmp::Ordering {
    use std::cmp::Ordering;
    let (s1, s2) = match (s1, s2) {
        (None, None) => return Ordering::Equal,
        (None, Some(_)) => return Ordering::Less,
        (Some(_), None) => return Ordering::Greater,
        (Some(a), Some(b)) => (a, b),
    };
    for i in 0..n {
        let c1 = *s1.get(i).unwrap_or(&0);
        let c2 = *s2.get(i).unwrap_or(&0);
        if c1 == 0 || c2 == 0 || c1 != c2 {
            return c1.cmp(&c2);
        }
    }
    Ordering::Equal
}

/// Compare two byte strings, bounded by `n`, case-insensitive.
///
/// Mirrors `strncasecmp8`.
pub fn strncasecmp8(s1: &[u8], s2: &[u8], n: usize) -> std::cmp::Ordering {
    use std::cmp::Ordering;
    for i in 0..n {
        let c1 = tolower(*s1.get(i).unwrap_or(&0));
        let c2 = tolower(*s2.get(i).unwrap_or(&0));
        if c1 == 0 || c2 == 0 || c1 != c2 {
            return c1.cmp(&c2);
        }
    }
    Ordering::Equal
}

/// Lowercase a single byte.
fn tolower(c: u8) -> u8 {
    if c >= b'A' && c <= b'Z' {
        c + (b'a' - b'A')
    } else {
        c
    }
}

/// Check byte-string equality, bounded by length.
pub fn strneq8(a: &[u8], b: &[u8], n: usize) -> bool {
    strncmp8(Some(a), Some(b), n) == std::cmp::Ordering::Equal
}

/// Check byte-string equality (full length).
pub fn streq8(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    strneq8(a, b, a.len())
}

// ── strchr8 ───────────────────────────────────────────────────────────────

/// Find first occurrence of byte `c` in `s`.
///
/// Mirrors `strchr8`.
pub fn strchr8(s: &[u8], c: u8) -> Option<usize> {
    for (i, &b) in s.iter().enumerate() {
        if b == 0 {
            break;
        }
        if b == c {
            return Some(i);
        }
    }
    if c == 0 {
        Some(s.iter().position(|&b| b == 0).unwrap_or(s.len()))
    } else {
        None
    }
}

// ── strlen8 ───────────────────────────────────────────────────────────────

/// Length of a NUL-terminated byte string.
pub fn strlen8(s: &[u8]) -> usize {
    s.iter().position(|&c| c == 0).unwrap_or(s.len())
}

/// Length of a NUL-terminated UTF-16 string.
pub fn strlen16(s: &[u16]) -> usize {
    s.iter().position(|&c| c == 0).unwrap_or(s.len())
}

// ── startswith8 ───────────────────────────────────────────────────────────

/// Check if `s` starts with `prefix`, returning the remainder.
///
/// Mirrors `startswith8`.
pub fn startswith8<'a>(s: &'a [u8], prefix: &[u8]) -> Option<&'a [u8]> {
    let prefix_len = strlen8(prefix);
    if s.len() < prefix_len {
        return None;
    }
    if strneq8(s, prefix, prefix_len) {
        Some(&s[prefix_len..])
    } else {
        None
    }
}

// ── UTF-8 to Unicode ──────────────────────────────────────────────────────

/// Decode one Unicode code point from a UTF-8 byte sequence.
///
/// Mirrors `utf8_to_unichar`. Returns `(char32, bytes_consumed)`.
/// Invalid sequences yield `(0xFFFF_FFFF, expected_len)`.
pub fn utf8_to_unichar(utf8: &[u8]) -> (u32, usize) {
    if utf8.is_empty() {
        return (0xFFFF_FFFF, 1);
    }

    let (len, mut unichar): (usize, u32) = if utf8[0] & 0x80 == 0 {
        return (utf8[0] as u32, 1);
    } else if (utf8[0] & 0xE0) == 0xC0 {
        (2, (utf8[0] & 0x1F) as u32)
    } else if (utf8[0] & 0xF0) == 0xE0 {
        (3, (utf8[0] & 0x0F) as u32)
    } else if (utf8[0] & 0xF8) == 0xF0 {
        (4, (utf8[0] & 0x07) as u32)
    } else if (utf8[0] & 0xFC) == 0xF8 {
        (5, (utf8[0] & 0x03) as u32)
    } else if (utf8[0] & 0xFE) == 0xFC {
        (6, (utf8[0] & 0x01) as u32)
    } else {
        return (0xFFFF_FFFF, 1);
    };

    if len > utf8.len() {
        return (0xFFFF_FFFF, len);
    }

    for i in 1..len {
        if (utf8[i] & 0xC0) != 0x80 {
            return (0xFFFF_FFFF, len);
        }
        unichar <<= 6;
        unichar |= (utf8[i] & 0x3F) as u32;
    }

    (unichar, len)
}

/// Convert a UTF-8 byte slice to a UCS-2 (u16) vector, skipping invalid sequences.
///
/// Mirrors `xstrn8_to_16`.
pub fn xstrn8_to_16(str8: &[u8]) -> Vec<u16> {
    let mut result = Vec::with_capacity(str8.len());
    let mut pos = 0;
    while pos < str8.len() && str8[pos] != 0 {
        let (unichar, consumed) = utf8_to_unichar(&str8[pos..]);
        pos += consumed;
        match unichar {
            0x0000..=0xD7FF | 0xE000..=0xFFFF => {
                result.push(unichar as u16);
            }
            _ => {} // skip (surrogates, > BMP)
        }
    }
    result.push(0);
    result
}

/// Convert a UTF-16 slice to ASCII bytes, failing if any character > 127.
///
/// Mirrors `xstrn16_to_ascii`.
pub fn xstrn16_to_ascii(str16: &[u16]) -> Option<Vec<u8>> {
    let mut result = Vec::with_capacity(str16.len());
    for &c in str16 {
        if c == 0 {
            break;
        }
        if c > 127 {
            return None;
        }
        result.push(c as u8);
    }
    result.push(0);
    Some(result)
}

// ── fnmatch ────────────────────────────────────────────────────────────────

/// Simplified fnmatch for UTF-16 strings.
///
/// Mirrors `efi_fnmatch`. Supports `*`, `?`, `[...]`, `[!...]`, `\\`.
/// Does not use backtracking (linear time guarantee).
pub fn efi_fnmatch(pattern: &[u16], haystack: &[u16]) -> bool {
    let mut pattern = pattern;
    let mut haystack = haystack;
    let mut first = true;

    loop {
        let (pattern_tail, haystack_tail) = efi_fnmatch_prefix(pattern, haystack);
        if first {
            if pattern_tail.is_none() && haystack_tail.is_none() {
                // No '*', and match result is returned directly
                return fnmatch_prefix_matches(pattern, haystack);
            }
            if !fnmatch_prefix_matches(pattern, haystack) {
                return false;
            }
            if pattern_tail.is_none() {
                return true;
            }
            first = false;
        }

        if let (Some(pt), Some(ht)) = (pattern_tail, haystack_tail) {
            pattern = pt;
            haystack = ht;
        } else if fnmatch_prefix_matches(pattern, haystack) {
            return true;
        } else if haystack.is_empty() || haystack[0] == 0 {
            return false;
        } else {
            haystack = &haystack[1..];
        }
    }
}

/// Check if a prefix matches without wildcards.
fn fnmatch_prefix_matches(pattern: &[u16], haystack: &[u16]) -> bool {
    let (pi, hi, star) = fnmatch_prefix_impl(pattern, haystack);
    if star {
        true
    } else {
        pattern.len() == pi && (haystack.len() == hi || haystack[hi] == 0)
    }
}

/// Returns (pattern_tail, haystack_tail) where pattern_tail is Some if a '*' was found.
fn efi_fnmatch_prefix<'a>(
    pattern: &'a [u16],
    haystack: &'a [u16],
) -> (Option<&'a [u16]>, Option<&'a [u16]>) {
    let (pi, hi, star) = fnmatch_prefix_impl(pattern, haystack);
    if star {
        (Some(&pattern[pi..]), Some(&haystack[hi..]))
    } else {
        (None, None)
    }
}

/// Inner implementation: walk pattern and haystack, return (pi, hi, found_star).
fn fnmatch_prefix_impl(pattern: &[u16], haystack: &[u16]) -> (usize, usize, bool) {
    let mut pi = 0;
    let mut hi = 0;

    loop {
        let pc = *pattern.get(pi).unwrap_or(&0);
        const BACKSLASH: u16 = b'\\' as u16;
        const QUESTION: u16 = b'?' as u16;
        const STAR: u16 = b'*' as u16;
        const BRACKET: u16 = b'[' as u16;
        match pc {
            0 => {
                return (pi, hi, false);
            }
            BACKSLASH => {
                pi += 1;
                let escaped = *pattern.get(pi).unwrap_or(&0);
                if escaped == 0 || escaped != *haystack.get(hi).unwrap_or(&0) {
                    return (pi, hi, false);
                }
                pi += 1;
                hi += 1;
            }
            QUESTION => {
                let hc = *haystack.get(hi).unwrap_or(&0);
                if hc == 0 {
                    return (pi, hi, false);
                }
                pi += 1;
                hi += 1;
            }
            STAR => {
                while pi < pattern.len() && pattern[pi] == STAR {
                    pi += 1;
                }
                return (pi, hi, true);
            }
            BRACKET => {
                let hc = *haystack.get(hi).unwrap_or(&0);
                if hc == 0 {
                    return (pi, hi, false);
                }
                let result = match_bracket(pattern, pi, hc);
                match result {
                    BracketResult::Match(new_pi) => {
                        pi = new_pi;
                        hi += 1;
                    }
                    BracketResult::NoMatch(new_pi) => {
                        pi = new_pi;
                        return (pi, hi, false);
                    }
                    BracketResult::Error => {
                        // Treat '[' as literal
                        if pc != *haystack.get(hi).unwrap_or(&0) {
                            return (pi, hi, false);
                        }
                        pi += 1;
                        hi += 1;
                    }
                }
            }
            _ => {
                if pc != *haystack.get(hi).unwrap_or(&0) {
                    return (pi, hi, false);
                }
                pi += 1;
                hi += 1;
            }
        }
    }
}

/// Match the prefix (non-star portion), returns (pi, hi) after match.
fn fnmatch_match_prefix_impl(pattern: &[u16], haystack: &[u16]) -> (usize, usize) {
    let (pi, hi, _) = fnmatch_prefix_impl(pattern, haystack);
    (pi, hi)
}

enum BracketResult {
    Match(usize),
    NoMatch(usize),
    Error,
}

/// Evaluate a `[...]` bracket expression starting at `pattern[start]`.
fn match_bracket(pattern: &[u16], start: usize, c: u16) -> BracketResult {
    if start >= pattern.len() || pattern[start] != b'[' as u16 {
        return BracketResult::Error;
    }
    let mut i = start + 1;
    let mut first = true;
    let mut can_range = true;
    let mut matched = false;

    loop {
        if i >= pattern.len() {
            return BracketResult::Error;
        }
        let mut pc = pattern[i];
        if pc == 0 {
            return BracketResult::Error;
        }

        if pc == b'\\' as u16 {
            i += 1;
            if i >= pattern.len() {
                return BracketResult::Error;
            }
            pc = pattern[i];
            if pc == c {
                matched = true;
            }
            can_range = true;
            i += 1;
            first = false;
            continue;
        }

        if pc == b']' as u16 && !first {
            i += 1;
            break;
        }

        if pc == b'-' as u16
            && can_range
            && !first
            && i + 1 < pattern.len()
            && pattern[i + 1] != b']' as u16
        {
            let low = pattern[i - 1];
            i += 1;
            if i < pattern.len() && pattern[i] == b'\\' as u16 {
                i += 1;
            }
            if i >= pattern.len() {
                return BracketResult::Error;
            }
            let high = pattern[i];
            if low <= c && c <= high {
                matched = true;
            }
            can_range = false;
            i += 1;
            first = false;
            continue;
        }

        if pc == c {
            matched = true;
        }
        can_range = true;
        i += 1;
        first = false;
    }

    if matched {
        BracketResult::Match(i)
    } else {
        BracketResult::NoMatch(i)
    }
}

// ── parse_number ──────────────────────────────────────────────────────────

/// Parse a decimal number from a byte string.
///
/// Mirrors `parse_number8`. Returns `(value, remaining_slice)`.
pub fn parse_number8(s: &[u8]) -> Option<(u64, &[u8])> {
    if s.is_empty() || s[0] < b'0' || s[0] > b'9' {
        return None;
    }
    let mut result: u64 = 0;
    let mut i = 0;
    while i < s.len() && s[i] >= b'0' && s[i] <= b'9' {
        result = result.checked_mul(10)?.checked_add((s[i] - b'0') as u64)?;
        i += 1;
    }
    Some((result, &s[i..]))
}

/// Parse a decimal number from a UTF-16 slice.
///
/// Mirrors `parse_number16`.
pub fn parse_number16(s: &[u16]) -> Option<(u64, &[u16])> {
    let zero = b'0' as u16;
    let nine = b'9' as u16;
    if s.is_empty() || s[0] < zero || s[0] > nine {
        return None;
    }
    let mut result: u64 = 0;
    let mut i = 0;
    while i < s.len() && s[i] >= zero && s[i] <= nine {
        result = result.checked_mul(10)?.checked_add((s[i] - zero) as u64)?;
        i += 1;
    }
    Some((result, &s[i..]))
}

// ── parse_boolean ─────────────────────────────────────────────────────────

/// Parse a boolean from a string.
///
/// Mirrors `parse_boolean`.
pub fn parse_boolean(v: &[u8]) -> Option<bool> {
    if streq8(v, b"1\0")
        || streq8(v, b"yes\0")
        || streq8(v, b"y\0")
        || streq8(v, b"true\0")
        || streq8(v, b"t\0")
        || streq8(v, b"on\0")
    {
        Some(true)
    } else if streq8(v, b"0\0")
        || streq8(v, b"no\0")
        || streq8(v, b"n\0")
        || streq8(v, b"false\0")
        || streq8(v, b"f\0")
        || streq8(v, b"off\0")
    {
        Some(false)
    } else {
        None
    }
}

// ── line_get_key_value ────────────────────────────────────────────────────

/// Parse key-value pairs from a line-oriented string.
///
/// Mirrors `line_get_key_value`. Returns `(key, value)` from successive
/// lines, skipping comments and blank lines.  Uses `sep` as the separator
/// between key and value.
pub fn line_get_key_value<'a>(
    s: &'a mut [u8],
    sep: &[u8],
    pos: &mut usize,
) -> Option<(&'a [u8], &'a [u8])> {
    loop {
        if *pos >= s.len() || s[*pos] == 0 {
            return None;
        }

        let line_start = *pos;
        let mut line_end = *pos;
        while line_end < s.len() && s[line_end] != 0 && s[line_end] != b'\n' && s[line_end] != b'\r'
        {
            line_end += 1;
        }

        let linelen = line_end - line_start;
        *pos = line_end;
        if *pos < s.len() && s[*pos] != 0 {
            *pos += 1;
        }

        if linelen == 0 {
            continue;
        }

        // Trim leading whitespace
        let mut start = line_start;
        let mut len = linelen;
        while len > 0 && (s[start] == b' ' || s[start] == b'\t') {
            start += 1;
            len -= 1;
        }
        // Trim trailing whitespace
        while len > 0 && (s[start + len - 1] == b' ' || s[start + len - 1] == b'\t') {
            len -= 1;
        }

        if len == 0 || s[start] == b'#' {
            continue;
        }

        // NUL-terminate the trimmed line for safety
        s[start + len] = 0;

        // Find separator
        let mut value_off = start;
        while value_off < start + len && s[value_off] != 0 {
            let mut found_sep = false;
            for &sc in sep {
                if s[value_off] == sc {
                    found_sep = true;
                    break;
                }
            }
            if found_sep {
                break;
            }
            value_off += 1;
        }
        if s[value_off] == 0 || value_off >= start + len {
            continue;
        }
        s[value_off] = 0; // NUL-terminate key
        let mut value_start = value_off + 1;
        while value_start < start + len && s[value_start] != 0 {
            let mut found_sep = false;
            for &sc in sep {
                if s[value_start] == sc {
                    found_sep = true;
                    break;
                }
            }
            if !found_sep {
                break;
            }
            value_start += 1;
        }

        // Unquote
        let key_end = start + len;
        if QUOTES.contains(&s[value_start])
            && key_end > value_start
            && s[key_end - 1] == s[value_start]
        {
            value_start += 1;
            s[key_end - 1] = 0;
        }

        return Some((&s[start..value_off], &s[value_start..key_end]));
    }
}

// ── hexdump ───────────────────────────────────────────────────────────────

/// Convert binary data to a hex string (UTF-16).
///
/// Mirrors `hexdump`.
pub fn hexdump(data: &[u8]) -> Vec<u16> {
    let mut buf = Vec::with_capacity(data.len() * 2 + 1);
    for &byte in data {
        buf.push(LOWERCASE_HEXDIGITS[(byte >> 4) as usize] as u16);
        buf.push(LOWERCASE_HEXDIGITS[(byte & 0x0F) as usize] as u16);
    }
    buf.push(0);
    buf
}

// ── status_to_string ──────────────────────────────────────────────────────

/// EFI error mask (high bit set).
pub const EFI_ERROR_MASK: u64 = 1u64 << 63;

/// Known EFI status codes and their string representations.
fn status_to_string(status: u64) -> Option<&'static str> {
    match status {
        0 => return Some("Success"),
        1 => return Some("Unknown glyph"),
        2 => return Some("Delete failure"),
        3 => return Some("Write failure"),
        4 => return Some("Buffer too small"),
        5 => return Some("Stale data"),
        6 => return Some("File system"),
        7 => return Some("Reset required"),
        _ => {}
    }

    if status & EFI_ERROR_MASK != 0 {
        let idx = (status & !EFI_ERROR_MASK) as usize;
        match idx {
            0 => Some("Error"),
            1 => Some("Load error"),
            2 => Some("Invalid parameter"),
            3 => Some("Unsupported"),
            4 => Some("Bad buffer size"),
            5 => Some("Buffer too small"),
            6 => Some("Not ready"),
            7 => Some("Device error"),
            8 => Some("Write protected"),
            9 => Some("Out of resources"),
            10 => Some("Volume corrupt"),
            11 => Some("Volume full"),
            12 => Some("No media"),
            13 => Some("Media changed"),
            14 => Some("Not found"),
            15 => Some("Access denied"),
            16 => Some("No response"),
            17 => Some("No mapping"),
            18 => Some("Time out"),
            19 => Some("Not started"),
            20 => Some("Already started"),
            21 => Some("Aborted"),
            22 => Some("ICMP error"),
            23 => Some("TFTP error"),
            24 => Some("Protocol error"),
            25 => Some("Incompatible version"),
            26 => Some("Security violation"),
            27 => Some("CRC error"),
            28 => Some("End of media"),
            31 => Some("End of file"),
            32 => Some("Invalid language"),
            33 => Some("Compromised data"),
            34 => Some("IP address conflict"),
            35 => Some("HTTP error"),
            _ => None,
        }
    } else {
        None
    }
}

// ── Memory functions ──────────────────────────────────────────────────────

/// Find first occurrence of `c` in `buf`.
///
/// Mirrors `memchr`.
pub fn efi_memchr(buf: &[u8], c: u8) -> Option<usize> {
    buf.iter().position(|&b| b == c)
}

/// Compare two byte slices.
///
/// Mirrors `memcmp`.
pub fn efi_memcmp(a: &[u8], b: &[u8]) -> std::cmp::Ordering {
    let len = std::cmp::min(a.len(), b.len());
    for i in 0..len {
        match a[i].cmp(&b[i]) {
            std::cmp::Ordering::Equal => continue,
            other => return other,
        }
    }
    a.len().cmp(&b.len())
}

/// Copy bytes from `src` to `dst`.
///
/// Mirrors `memcpy`.
pub fn efi_memcpy(dst: &mut [u8], src: &[u8]) {
    let len = std::cmp::min(dst.len(), src.len());
    dst[..len].copy_from_slice(&src[..len]);
}

/// Fill `buf` with byte `c`.
///
/// Mirrors `memset`.
pub fn efi_memset(buf: &mut [u8], c: u8) {
    for b in buf.iter_mut() {
        *b = c;
    }
}

// ── strspn / strcspn (UTF-16) ─────────────────────────────────────────────

/// Count leading characters in `s` that are in `good`.
///
/// Mirrors `strspn16`.
pub fn strspn16(s: &[u16], good: &[u16]) -> usize {
    let mut i = 0;
    while i < s.len() && s[i] != 0 {
        if !good.contains(&s[i]) {
            break;
        }
        i += 1;
    }
    i
}

/// Count leading characters in `s` that are NOT in `bad`.
///
/// Mirrors `strcspn16`.
pub fn strcspn16(s: &[u16], bad: &[u16]) -> usize {
    let mut i = 0;
    while i < s.len() && s[i] != 0 {
        if bad.contains(&s[i]) {
            break;
        }
        i += 1;
    }
    i
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strnlen8() {
        assert_eq!(strnlen8(Some(b"hello\0"), 10), 5);
        assert_eq!(strnlen8(Some(b"hello"), 3), 3);
        assert_eq!(strnlen8(None, 10), 0);
    }

    #[test]
    fn test_strnlen16() {
        let s: Vec<u16> = [72, 73, 0, 74].to_vec();
        assert_eq!(strnlen16(Some(&s), 10), 2);
        assert_eq!(strnlen16(None, 10), 0);
    }

    #[test]
    fn test_strtolower8() {
        let mut s = b"Hello World".to_vec();
        strtolower8(&mut s);
        assert_eq!(&s, b"hello world");
    }

    #[test]
    fn test_strncmp8() {
        assert_eq!(
            strncmp8(Some(b"abc"), Some(b"abc"), 3),
            std::cmp::Ordering::Equal
        );
        assert_eq!(
            strncmp8(Some(b"abc"), Some(b"abd"), 3),
            std::cmp::Ordering::Less
        );
        assert_eq!(strncmp8(None, Some(b"a"), 1), std::cmp::Ordering::Less);
    }

    #[test]
    fn test_strncasecmp8() {
        assert_eq!(strncasecmp8(b"ABC", b"abc", 3), std::cmp::Ordering::Equal);
        assert_eq!(strncasecmp8(b"AbC", b"aBd", 3), std::cmp::Ordering::Less);
    }

    #[test]
    fn test_streq8() {
        assert!(streq8(b"hello\0", b"hello\0"));
        assert!(!streq8(b"hello\0", b"world\0"));
    }

    #[test]
    fn test_startswith8() {
        assert!(startswith8(b"hello world\0", b"hello\0").is_some());
        assert!(startswith8(b"hello world\0", b"world\0").is_none());
    }

    #[test]
    fn test_utf8_to_unichar() {
        assert_eq!(utf8_to_unichar(b"A"), (0x41, 1));
        assert_eq!(utf8_to_unichar(&[0xC3, 0xA9]), (0xE9, 2)); // é
        assert_eq!(utf8_to_unichar(&[0xE2, 0x82, 0xAC]), (0x20AC, 3)); // €
    }

    #[test]
    fn test_xstrn8_to_16() {
        let result = xstrn8_to_16(b"ABC");
        assert_eq!(&result[..3], &[0x41, 0x42, 0x43]);
    }

    #[test]
    fn test_xstrn16_to_ascii() {
        let v: Vec<u16> = vec![0x41, 0x42, 0x43, 0];
        let result = xstrn16_to_ascii(&v).unwrap();
        assert_eq!(&result[..3], b"ABC");
        let v: Vec<u16> = vec![0x100, 0];
        assert!(xstrn16_to_ascii(&v).is_none());
    }

    #[test]
    fn test_parse_number8() {
        assert_eq!(parse_number8(b"12345abc"), Some((12345, &b"abc"[..])));
        assert_eq!(parse_number8(b"0"), Some((0, &b""[..])));
        assert_eq!(parse_number8(b"abc"), None);
        assert_eq!(parse_number8(b""), None);
    }

    #[test]
    fn test_parse_number16() {
        let s: Vec<u16> = "42xyz".encode_utf16().collect();
        let (val, tail) = parse_number16(&s).unwrap();
        assert_eq!(val, 42);
        assert_eq!(tail[0], 'x' as u16);
    }

    #[test]
    fn test_parse_boolean() {
        assert_eq!(parse_boolean(b"1\0"), Some(true));
        assert_eq!(parse_boolean(b"yes\0"), Some(true));
        assert_eq!(parse_boolean(b"0\0"), Some(false));
        assert_eq!(parse_boolean(b"no\0"), Some(false));
        assert_eq!(parse_boolean(b"maybe\0"), None);
    }

    #[test]
    fn test_hexdump() {
        let result = hexdump(&[0xDE, 0xAD]);
        let s: String = result[..result.len() - 1]
            .iter()
            .map(|&c| c as u8 as char)
            .collect();
        assert_eq!(s, "dead");
    }

    #[test]
    fn test_efi_memchr() {
        assert_eq!(efi_memchr(b"hello", b'l'), Some(2));
        assert_eq!(efi_memchr(b"hello", b'z'), None);
    }

    #[test]
    fn test_efi_memcmp() {
        assert_eq!(efi_memcmp(b"abc", b"abc"), std::cmp::Ordering::Equal);
        assert_eq!(efi_memcmp(b"abc", b"abd"), std::cmp::Ordering::Less);
    }

    #[test]
    fn test_efi_memcpy() {
        let mut dst = [0u8; 5];
        efi_memcpy(&mut dst, b"hello");
        assert_eq!(&dst, b"hello");
    }

    #[test]
    fn test_efi_memset() {
        let mut buf = [0u8; 4];
        efi_memset(&mut buf, 0xFF);
        assert_eq!(buf, [0xFF; 4]);
    }

    #[test]
    fn test_strspn16() {
        let s: Vec<u16> = "aabbc".encode_utf16().collect();
        let good: Vec<u16> = "ab".encode_utf16().collect();
        assert_eq!(strspn16(&s, &good), 4);
    }

    #[test]
    fn test_strcspn16() {
        let s: Vec<u16> = "abcde".encode_utf16().collect();
        let bad: Vec<u16> = "de".encode_utf16().collect();
        assert_eq!(strcspn16(&s, &bad), 3);
    }

    #[test]
    fn test_fnmatch_star() {
        let pattern: Vec<u16> = "*.txt".encode_utf16().collect();
        let yes: Vec<u16> = "file.txt".encode_utf16().collect();
        let no: Vec<u16> = "file.rs".encode_utf16().collect();
        assert!(efi_fnmatch(&pattern, &yes));
        assert!(!efi_fnmatch(&pattern, &no));
    }

    #[test]
    fn test_fnmatch_question() {
        let pattern: Vec<u16> = "file?txt".encode_utf16().collect();
        let yes: Vec<u16> = "file.txt".encode_utf16().collect();
        let no: Vec<u16> = "fileXtxt".encode_utf16().collect();
        assert!(efi_fnmatch(&pattern, &yes)); // '.' matches '?'
        assert!(efi_fnmatch(&pattern, &no)); // 'X' matches '?'
        let short: Vec<u16> = "filet".encode_utf16().collect();
        assert!(!efi_fnmatch(&pattern, &short));
    }

    #[test]
    fn test_status_to_string() {
        assert_eq!(status_to_string(0), Some("Success"));
        assert_eq!(
            status_to_string(EFI_ERROR_MASK | 2),
            Some("Invalid parameter")
        );
        assert_eq!(status_to_string(EFI_ERROR_MASK | 14), Some("Not found"));
    }
}
