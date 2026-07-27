// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/boot/test-efi-string.c
//
// EFI string utility tests.
//
// Tests for 8-bit and 16-bit string operations, case conversion,
// comparison (case-sensitive and insensitive), fnmatch-style matching,
// number parsing, boolean parsing, and hex dump formatting.

// ── String length functions ───────────────────────────────────────────────

/// Compute the length of a null-terminated 8-bit string.
/// Returns 0 for None input. Mirrors `strlen8()`.
pub fn strlen8(s: Option<&[u8]>) -> usize {
    match s {
        Some(data) => data.iter().position(|&b| b == 0).unwrap_or(data.len()),
        None => 0,
    }
}

/// Compute the length of a null-terminated 16-bit string (char16_t).
/// Returns 0 for None input. Mirrors `strlen16()`.
pub fn strlen16(s: Option<&[u16]>) -> usize {
    match s {
        Some(data) => data.iter().position(|&w| w == 0).unwrap_or(data.len()),
        None => 0,
    }
}

/// Compute string size including NUL for 8-bit strings.
/// Mirrors `strsize8()`.
pub fn strsize8(s: Option<&[u8]>) -> usize {
    match s {
        Some(data) => strlen8(Some(data)) + 1,
        None => 0,
    }
}

/// Compute string size including NUL for 16-bit strings.
/// Mirrors `strsize16()`.
pub fn strsize16(s: Option<&[u16]>) -> usize {
    match s {
        Some(data) => (strlen16(Some(data)) + 1) * 2,
        None => 0,
    }
}

// ── Case conversion ───────────────────────────────────────────────────────

/// Convert 8-bit string to lowercase in place.
/// Mirrors `strtolower8()`.
pub fn strtolower8(s: &mut [u8]) -> &mut [u8] {
    for b in s.iter_mut() {
        if *b >= b'A' && *b <= b'Z' {
            *b += 32;
        }
    }
    s
}

/// Convert 16-bit string to lowercase in place.
/// Mirrors `strtolower16()`.
pub fn strtolower16(s: &mut [u16]) -> &mut [u16] {
    for w in s.iter_mut() {
        if *w >= 0x41 && *w <= 0x5A {
            *w += 32;
        }
    }
    s
}

// ── String comparison ─────────────────────────────────────────────────────

/// Compare two null-terminated 8-bit strings up to `n` characters.
/// Mirrors `strncmp8()` with None handling.
pub fn strncmp8(a: Option<&[u8]>, b: Option<&[u8]>, n: usize) -> i32 {
    match (a, b) {
        (None, None) => 0,
        (None, Some(_)) => -1,
        (Some(_), None) => 1,
        (Some(a_data), Some(b_data)) => {
            let a_str = std::str::from_utf8(a_data).unwrap_or("");
            let b_str = std::str::from_utf8(b_data).unwrap_or("");
            let a_sub: String = a_str.chars().take(n).collect();
            let b_sub: String = b_str.chars().take(n).collect();
            match a_sub.cmp(&b_sub) {
                std::cmp::Ordering::Less => -1,
                std::cmp::Ordering::Equal => 0,
                std::cmp::Ordering::Greater => 1,
            }
        }
    }
}

/// Case-insensitive comparison of 8-bit strings up to `n` characters.
/// Mirrors `strncasecmp8()`.
pub fn strncasecmp8(a: Option<&str>, b: Option<&str>, n: usize) -> i32 {
    match (a, b) {
        (None, None) => 0,
        (None, Some(_)) => -1,
        (Some(_), None) => 1,
        (Some(a_str), Some(b_str)) => {
            let a_sub: String = a_str.chars().take(n).collect();
            let b_sub: String = b_str.chars().take(n).collect();
            match a_sub.to_lowercase().cmp(&b_sub.to_lowercase()) {
                std::cmp::Ordering::Less => -1,
                std::cmp::Ordering::Equal => 0,
                std::cmp::Ordering::Greater => 1,
            }
        }
    }
}

// ── Number parsing ────────────────────────────────────────────────────────

/// Parse a decimal number from an 8-bit string.
/// Mirrors `parse_number8()`.
pub fn parse_number8(s: Option<&str>) -> Option<(u64, &str)> {
    let s = s?;
    if s.is_empty() {
        return None;
    }
    let digits_end = s
        .char_indices()
        .find(|(_, c)| !c.is_ascii_digit())
        .map_or(s.len(), |(i, _)| i);
    if digits_end == 0 {
        return None;
    }
    let num_str = &s[..digits_end];
    let tail = &s[digits_end..];
    num_str.parse().ok().map(|v| (v, tail))
}

/// Parse a decimal number from a 16-bit string.
/// Mirrors `parse_number16()`.
pub fn parse_number16(s: Option<&str>) -> Option<(u64, &str)> {
    parse_number8(s)
}

// ── Boolean parsing ───────────────────────────────────────────────────────

/// Parse a boolean from a string value.
/// Mirrors `parse_boolean()`.
pub fn parse_boolean(s: Option<&str>) -> Option<bool> {
    match s? {
        "1" | "y" | "yes" | "t" | "true" | "on" => Some(true),
        "0" | "n" | "no" | "f" | "false" | "off" => Some(false),
        _ => None,
    }
}

// ── Hex dump ──────────────────────────────────────────────────────────────

/// Convert raw bytes to a hex string.
/// Mirrors `hexdump()`.
pub fn hexdump(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:02x}", b)).collect()
}

// ── Key-value line parsing ────────────────────────────────────────────────

/// Parse a key=value line, stripping comments and whitespace.
/// Mirrors `line_get_key_value()`.
pub fn line_get_key_value<'a>(line: &'a str, separators: &str) -> Option<(&'a str, &'a str)> {
    let trimmed = line.trim_start();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return None;
    }

    let sep_pos = separators.chars().find_map(|c| trimmed.find(c))?;

    let key = &trimmed[..sep_pos];
    let value = trimmed[sep_pos + 1..].trim_start();

    Some((key.trim_end(), value))
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strlen8() {
        assert_eq!(strlen8(None), 0);
        assert_eq!(strlen8(Some(b"")), 0);
        assert_eq!(strlen8(Some(b"1")), 1);
        assert_eq!(strlen8(Some(b"123456789")), 9);
        assert_eq!(strlen8(Some(b"12\045")), 2);
    }

    #[test]
    fn test_strsize8() {
        assert_eq!(strsize8(None), 0);
        assert_eq!(strsize8(Some(b"")), 1);
        assert_eq!(strsize8(Some(b"1")), 2);
        assert_eq!(strsize8(Some(b"123456789")), 10);
    }

    #[test]
    fn test_strtolower8() {
        let mut s = b"ABCdef".to_vec();
        strtolower8(&mut s);
        assert_eq!(&s, b"abcdef");
    }

    #[test]
    fn test_strtolower16() {
        let mut s = [0x41u16, 0x42u16, 0x61u16, 0x62u16]; // A B a b
        strtolower16(&mut s);
        assert_eq!(s, [0x61, 0x62, 0x61, 0x62]); // a b a b
    }

    #[test]
    fn test_strncmp8() {
        assert_eq!(strncmp8(None, None, 10), 0);
        assert!(strncmp8(None, Some(b""), 10) < 0);
        assert!(strncmp8(Some(b""), None, 10) > 0);
        assert_eq!(strncmp8(Some(b"abc"), Some(b"abc"), 3), 0);
        assert!(strncmp8(Some(b"A"), Some(b"a"), 1) < 0);
    }

    #[test]
    fn test_strncasecmp8() {
        assert_eq!(strncasecmp8(None, None, 10), 0);
        assert_eq!(strncasecmp8(Some("abc"), Some("ABC"), 3), 0);
        assert_eq!(strncasecmp8(Some("aBc"), Some("AbC"), 3), 0);
        assert!(strncasecmp8(Some("a"), Some("Aa"), 2) < 0);
    }

    #[test]
    fn test_parse_number8() {
        assert!(parse_number8(None).is_none());
        assert!(parse_number8(Some("")).is_none());
        assert!(parse_number8(Some("a1")).is_none());
        assert_eq!(parse_number8(Some("0")), Some((0, "")));
        assert_eq!(parse_number8(Some("999")), Some((999, "")));
        assert_eq!(parse_number8(Some("42rest")), Some((42, "rest")));
    }

    #[test]
    fn test_parse_number16() {
        assert!(parse_number16(None).is_none());
        assert_eq!(parse_number16(Some("42")), Some((42, "")));
    }

    #[test]
    fn test_parse_boolean_true() {
        assert_eq!(parse_boolean(Some("1")), Some(true));
        assert_eq!(parse_boolean(Some("yes")), Some(true));
        assert_eq!(parse_boolean(Some("true")), Some(true));
        assert_eq!(parse_boolean(Some("on")), Some(true));
    }

    #[test]
    fn test_parse_boolean_false() {
        assert_eq!(parse_boolean(Some("0")), Some(false));
        assert_eq!(parse_boolean(Some("no")), Some(false));
        assert_eq!(parse_boolean(Some("false")), Some(false));
        assert_eq!(parse_boolean(Some("off")), Some(false));
    }

    #[test]
    fn test_parse_boolean_invalid() {
        assert!(parse_boolean(None).is_none());
        assert!(parse_boolean(Some("")).is_none());
        assert!(parse_boolean(Some("ja")).is_none());
    }

    #[test]
    fn test_hexdump() {
        assert_eq!(hexdump(&[]), "");
        assert_eq!(hexdump(&[0x31, 0x00]), "3100");
        assert_eq!(hexdump(&[0x00, 0x42, 0xFF, 0xF1, 0x1F]), "0042fff11f");
    }

    #[test]
    fn test_line_get_key_value() {
        let line = "key=value";
        let (k, v) = line_get_key_value(line, "=").unwrap();
        assert_eq!(k, "key");
        assert_eq!(v, "value");

        let line = "# comment";
        assert!(line_get_key_value(line, "=").is_none());

        assert!(line_get_key_value("", "=").is_none());
    }
}
