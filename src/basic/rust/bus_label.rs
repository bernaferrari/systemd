// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/basic/bus-label.c, src/basic/bus-label.h
//
// D-Bus object path label escaping/unescaping.

// ── Internal helpers ──────────────────────────────────────────────────────

const HEX_LOWER: &[u8; 16] = b"0123456789abcdef";

fn hexchar(x: u8) -> u8 {
    HEX_LOWER[(x & 0xf) as usize]
}

fn unhexchar(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

fn ascii_isalpha(c: u8) -> bool {
    (c >= b'a' && c <= b'z') || (c >= b'A' && c <= b'Z')
}

fn ascii_isdigit(c: u8) -> bool {
    c >= b'0' && c <= b'9'
}

// ── bus_label_escape ─────────────────────────────────────────────────────

/// Escape a string for use as a D-Bus object path label.
/// Empty string → "_". All non-alphanumeric chars are escaped as _XX hex.
/// Leading digits are also escaped. Faithful to C bus_label_escape().
pub fn bus_label_escape(s: &str) -> String {
    if s.is_empty() {
        return "_".to_owned();
    }

    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len() * 3);

    for (i, &byte) in bytes.iter().enumerate() {
        if !ascii_isalpha(byte) && !(i > 0 && ascii_isdigit(byte)) {
            out.push('_');
            out.push(hexchar(byte >> 4) as char);
            out.push(hexchar(byte) as char);
        } else {
            out.push(byte as char);
        }
    }

    out
}

// ── bus_label_unescape ───────────────────────────────────────────────────

/// Unescape a D-Bus object path label.
/// "_" alone → empty string. "_XX" sequences are decoded from hex.
/// Invalid escape sequences keep the literal '_'.
/// Faithful to C bus_label_unescape_n().
pub fn bus_label_unescape(escaped: &str) -> String {
    let bytes = escaped.as_bytes();
    let len = bytes.len();

    if len == 1 && bytes[0] == b'_' {
        return String::new();
    }

    let mut out = String::with_capacity(len);
    let mut i = 0;

    while i < len {
        if bytes[i] == b'_' {
            if len - i < 3 {
                out.push('_');
                i += 1;
                continue;
            }
            let a = unhexchar(bytes[i + 1]);
            let b = unhexchar(bytes[i + 2]);
            match (a, b) {
                (Some(av), Some(bv)) => {
                    out.push(((av << 4) | bv) as char);
                    i += 3;
                }
                _ => {
                    out.push('_');
                    i += 1;
                }
            }
        } else {
            out.push(bytes[i] as char);
            i += 1;
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_escape_empty() {
        assert_eq!(bus_label_escape(""), "_");
    }

    #[test]
    fn test_escape_alphanumeric() {
        assert_eq!(bus_label_escape("hello"), "hello");
    }

    #[test]
    fn test_escape_leading_digit() {
        assert_eq!(bus_label_escape("1abc"), "_31abc");
    }

    #[test]
    fn test_escape_symbol() {
        assert_eq!(bus_label_escape("abc-1"), "abc_2d1");
    }

    #[test]
    fn test_escape_dot() {
        assert_eq!(bus_label_escape("foo.bar"), "foo_2ebar");
    }

    #[test]
    fn test_escape_all_special() {
        assert_eq!(bus_label_escape("!@#"), "_21_40_23");
    }

    #[test]
    fn test_escape_non_leading_digit() {
        assert_eq!(bus_label_escape("a1b"), "a1b");
    }

    #[test]
    fn test_escape_space() {
        assert_eq!(bus_label_escape("a b"), "a_20b");
    }

    #[test]
    fn test_unescape_empty_underscore() {
        assert_eq!(bus_label_unescape("_"), "");
    }

    #[test]
    fn test_unescape_valid_sequence() {
        assert_eq!(bus_label_unescape("abc_2d1"), "abc-1");
    }

    #[test]
    fn test_unescape_invalid_hex() {
        assert_eq!(bus_label_unescape("_zz"), "_zz");
    }

    #[test]
    fn test_unescape_plain() {
        assert_eq!(bus_label_unescape("hello"), "hello");
    }

    #[test]
    fn test_unescape_trailing_underscore() {
        assert_eq!(bus_label_unescape("abc_"), "abc_");
    }

    #[test]
    fn test_roundtrip_simple() {
        let original = "hello123";
        assert_eq!(bus_label_unescape(&bus_label_escape(original)), original);
    }

    #[test]
    fn test_roundtrip_special() {
        let original = "foo-bar.baz";
        assert_eq!(bus_label_unescape(&bus_label_escape(original)), original);
    }

    #[test]
    fn test_roundtrip_empty() {
        assert_eq!(bus_label_unescape(&bus_label_escape("")), "");
    }

    #[test]
    fn test_roundtrip_leading_digit() {
        let original = "9start";
        assert_eq!(bus_label_unescape(&bus_label_escape(original)), original);
    }

    #[test]
    fn test_roundtrip_all_special() {
        let original = "!@#$%^&*()";
        assert_eq!(bus_label_unescape(&bus_label_escape(original)), original);
    }
}
