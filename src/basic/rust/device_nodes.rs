// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/basic/device-nodes.c
//
// Device node name encoding: allow_listed_char_for_devnode, encode_devnode_name.

use crate::ffi::Errno;

// ── Internal helpers ──────────────────────────────────────────────────────

/// Determine the expected length of a UTF-8 sequence from its leading byte.
/// Returns 1 for ASCII, 0 for continuation bytes, 2–4 for multi-byte leads.
#[inline]
fn utf8_sequence_length(byte: u8) -> usize {
    if byte < 0x80 {
        1
    } else if byte < 0xC0 {
        0 // continuation byte — shouldn't appear as leading byte
    } else if byte < 0xE0 {
        2
    } else if byte < 0xF0 {
        3
    } else if byte < 0xF8 {
        4
    } else {
        1 // overlong/invalid, treat as single byte
    }
}

// ── Public API ────────────────────────────────────────────────────────────

/// Check if a character is allowed in a device node name.
///
/// Port of C `allow_listed_char_for_devnode()`.
/// Allowed: ASCII digits, ASCII letters, and the set `#+-.:=@_`.
/// If `additional` is `Some`, characters in that slice are also allowed.
pub fn allow_listed_char_for_devnode(c: u8, additional: Option<&[u8]>) -> bool {
    // ASCII digit
    if c >= b'0' && c <= b'9' {
        return true;
    }
    // ASCII letter
    if (c >= b'a' && c <= b'z') || (c >= b'A' && c <= b'Z') {
        return true;
    }
    // Fixed allow-list: #+-.:=@_
    if c == b'#'
        || c == b'+'
        || c == b'-'
        || c == b'.'
        || c == b':'
        || c == b'='
        || c == b'@'
        || c == b'_'
    {
        return true;
    }
    // Additional allowed characters
    if let Some(extra) = additional {
        if extra.contains(&c) {
            return true;
        }
    }
    false
}

/// Encode a byte string for use as a device node name.
///
/// Port of C `encode_devnode_name()`.
/// Allowed characters and multi-byte UTF-8 sequences pass through;
/// backslash and all other characters are escaped as `\xHH`.
///
/// Returns `Ok(written_len)` on success (excluding NUL terminator),
/// or `Err(Errno::EINVAL)` on error or insufficient buffer space.
pub fn encode_devnode_name(input: &[u8], buf: &mut [u8]) -> Result<usize, Errno> {
    let hex = b"0123456789abcdef";
    let mut j: usize = 0;

    let mut i: usize = 0;
    while i < input.len() {
        let byte = input[i];

        // Check for multi-byte UTF-8 sequence
        let seqlen = utf8_sequence_length(byte);
        if seqlen > 1 {
            // Validate: we need all bytes in the sequence to exist
            if i + seqlen > input.len() {
                return Err(Errno::EINVAL); // truncated UTF-8
            }
            if j + seqlen >= buf.len() {
                return Err(Errno::EINVAL);
            }
            buf[j..j + seqlen].copy_from_slice(&input[i..i + seqlen]);
            j += seqlen;
            i += seqlen;
            continue;
        }

        // Escape backslash and non-allowed characters
        if byte == b'\\' || !allow_listed_char_for_devnode(byte, None) {
            if j + 4 >= buf.len() {
                return Err(Errno::EINVAL);
            }
            buf[j] = b'\\';
            buf[j + 1] = b'x';
            buf[j + 2] = hex[(byte >> 4) as usize];
            buf[j + 3] = hex[(byte & 0x0f) as usize];
            j += 4;
        } else {
            if j >= buf.len() {
                return Err(Errno::EINVAL);
            }
            buf[j] = byte;
            j += 1;
        }

        i += 1;
    }

    // NUL terminator
    if j >= buf.len() {
        return Err(Errno::EINVAL);
    }
    buf[j] = 0;
    Ok(j)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── allow_listed_char_for_devnode tests ────────────────────────────

    #[test]
    fn allow_listed_all_digits() {
        for c in b'0'..=b'9' {
            assert!(
                allow_listed_char_for_devnode(c, None),
                "digit {}",
                c as char
            );
        }
    }

    #[test]
    fn allow_listed_lowercase_letters() {
        for c in b'a'..=b'z' {
            assert!(
                allow_listed_char_for_devnode(c, None),
                "lower {}",
                c as char
            );
        }
    }

    #[test]
    fn allow_listed_uppercase_letters() {
        for c in b'A'..=b'Z' {
            assert!(
                allow_listed_char_for_devnode(c, None),
                "upper {}",
                c as char
            );
        }
    }

    #[test]
    fn allow_listed_special_chars() {
        for &c in b"#+-.:=@_" {
            assert!(
                allow_listed_char_for_devnode(c, None),
                "special {}",
                c as char
            );
        }
    }

    #[test]
    fn allow_listed_disallowed_chars() {
        let disallowed = [
            b' ', b'!', b'/', b'*', b'?', b'[', b']', b'(', b')', b'<', b'>', b'&', b'|', b';',
            b',',
        ];
        for &c in &disallowed {
            assert!(
                !allow_listed_char_for_devnode(c, None),
                "disallowed {}",
                c as char
            );
        }
    }

    #[test]
    fn allow_listed_additional_chars() {
        let additional = b"!/";
        assert!(allow_listed_char_for_devnode(b'!', Some(additional)));
        assert!(allow_listed_char_for_devnode(b'/', Some(additional)));
        // Already allowed chars still work
        assert!(allow_listed_char_for_devnode(b'@', Some(additional)));
        // Space still not allowed
        assert!(!allow_listed_char_for_devnode(b' ', Some(additional)));
    }

    #[test]
    fn allow_listed_no_additional() {
        assert!(!allow_listed_char_for_devnode(b' ', None));
        assert!(allow_listed_char_for_devnode(b'a', None));
    }

    #[test]
    fn allow_listed_empty_additional() {
        assert!(!allow_listed_char_for_devnode(b' ', Some(b"")));
    }

    // ── encode_devnode_name tests ──────────────────────────────────────

    #[test]
    fn encode_empty_string() {
        let mut buf = [0u8; 4];
        assert_eq!(encode_devnode_name(b"", &mut buf), Ok(0));
        assert_eq!(buf[0], 0);
    }

    #[test]
    fn encode_simple_allowed() {
        let mut buf = [0u8; 10];
        let len = encode_devnode_name(b"hello", &mut buf).unwrap();
        assert_eq!(len, 5);
        assert_eq!(&buf[..5], b"hello");
    }

    #[test]
    fn encode_all_allowed_chars() {
        let input = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789#+-.:=@_";
        let mut buf = [0u8; 128];
        let len = encode_devnode_name(input, &mut buf).unwrap();
        assert_eq!(len, input.len());
        assert_eq!(&buf[..len], input);
    }

    #[test]
    fn encode_escapes_space() {
        let mut buf = [0u8; 16];
        let len = encode_devnode_name(b"foo bar", &mut buf).unwrap();
        assert_eq!(len, 10);
        assert_eq!(&buf[..len], b"foo\\x20bar");
    }

    #[test]
    fn encode_escapes_backslash() {
        let mut buf = [0u8; 16];
        let len = encode_devnode_name(b"foo\\bar", &mut buf).unwrap();
        assert_eq!(len, 10);
        assert_eq!(&buf[..len], b"foo\\x5cbar");
    }

    #[test]
    fn encode_escapes_newline() {
        let mut buf = [0u8; 16];
        let len = encode_devnode_name(b"foo\nbar", &mut buf).unwrap();
        assert_eq!(len, 10);
        assert_eq!(&buf[..len], b"foo\\x0abar");
    }

    #[test]
    fn encode_escapes_tab() {
        let mut buf = [0u8; 16];
        let len = encode_devnode_name(b"foo\tbar", &mut buf).unwrap();
        assert_eq!(len, 10);
        assert_eq!(&buf[..len], b"foo\\x09bar");
    }

    #[test]
    fn encode_multiple_escapes() {
        let mut buf = [0u8; 32];
        let len = encode_devnode_name(b"a b c", &mut buf).unwrap();
        assert_eq!(len, 11);
        assert_eq!(&buf[..len], b"a\\x20b\\x20c");
    }

    #[test]
    fn encode_insufficient_buffer() {
        let mut buf = [0u8; 5];
        assert_eq!(
            encode_devnode_name(b"hello world", &mut buf),
            Err(Errno::EINVAL)
        );
    }

    #[test]
    fn encode_exact_buffer_fit() {
        let mut buf = [0u8; 4]; // 3 chars + NUL
        let len = encode_devnode_name(b"abc", &mut buf).unwrap();
        assert_eq!(len, 3);
        assert_eq!(&buf[..3], b"abc");
    }

    #[test]
    fn encode_buffer_too_small_by_one() {
        let mut buf = [0u8; 3]; // need 3 + 1 = 4
        assert_eq!(encode_devnode_name(b"abc", &mut buf), Err(Errno::EINVAL));
    }

    #[test]
    fn encode_high_bytes_escaped() {
        let mut buf = [0u8; 16];
        let len = encode_devnode_name(&[0x80, 0xFF], &mut buf).unwrap();
        assert_eq!(len, 8);
        assert_eq!(&buf[..8], b"\\x80\\xff");
    }

    #[test]
    fn encode_mixed_allowed_and_escaped() {
        let mut buf = [0u8; 32];
        let len = encode_devnode_name(b"abc123 foo", &mut buf).unwrap();
        assert_eq!(&buf[..len], b"abc123\\x20foo");
    }
}
