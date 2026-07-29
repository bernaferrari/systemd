// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/udev-util.c (udev_replace_whitespace, udev_replace_chars)
//
// Udev string transformations. The byte-slice core deliberately owns all
// parsing and mutation; the two C exports are only checked pointer adapters.

use std::ffi::{CStr, c_char};

use crate::device_nodes::allow_listed_char_for_devnode;

const LEADING_WHITESPACE: &[u8] = b" \t\n\r";

/// C `isspace()` for the ASCII byte domain used by the udev string APIs.
///
/// `udev_replace_whitespace()` uses the narrower `WHITESPACE` list for the
/// leading run, but uses C `isspace()` for interior runs. Keep those two
/// decisions distinct: vertical tab and form feed are not stripped at the
/// front, but are normalized when they occur after a non-whitespace byte.
#[inline]
const fn c_isspace(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c)
}

/// Copy at most `input.len()` C bytes, stripping leading/trailing whitespace
/// and replacing each interior whitespace run with one underscore.
///
/// This is the fully safe, bounded equivalent of C
/// `udev_replace_whitespace(str, to, len)`: the returned vector excludes the
/// trailing NUL, and never contains more than `input.len()` bytes. `input`
/// may be a non-NUL-terminated fixed-width field.
pub fn udev_replace_whitespace_bytes(input: &[u8]) -> Vec<u8> {
    let len = input.len();
    let mut source = 0;
    let mut output = Vec::with_capacity(len);
    let mut pending_space = false;

    while source < len && input[source] != 0 && LEADING_WHITESPACE.contains(&input[source]) {
        source += 1;
    }

    while output.len() < len && source < len && input[source] != 0 {
        let byte = input[source];
        source += 1;

        if c_isspace(byte) {
            pending_space = true;
            continue;
        }

        if pending_space {
            // The C implementation must reserve a byte for the non-space
            // character that follows the underscore. `saturating_sub` also
            // preserves its `len == 0` behavior without arithmetic overflow.
            if output.len() >= len.saturating_sub(1) {
                break;
            }
            output.push(b'_');
            pending_space = false;
        }

        output.push(byte);
    }

    output
}

/// String convenience wrapper for [`udev_replace_whitespace_bytes`].
/// A valid UTF-8 input remains valid because this transformation only deletes
/// ASCII bytes or inserts ASCII underscores.
pub fn udev_replace_whitespace(input: &str) -> String {
    String::from_utf8(udev_replace_whitespace_bytes(input.as_bytes()))
        .expect("ASCII-only udev whitespace normalization preserves UTF-8")
}

/// Replace invalid device-node bytes in a mutable C-string byte buffer.
///
/// The safe API treats the first NUL as the end of the string. It therefore
/// also supports ordinary Rust byte slices that omit a terminator, while the
/// C ABI wrapper below requires one exactly as the C authority does.
pub fn udev_replace_chars(bytes: &mut [u8], allow: Option<&[u8]>) -> usize {
    let string_len = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    let allow = allow.map(c_string_prefix);
    let mut index = 0;
    let mut replaced = 0;

    while index < string_len {
        let byte = bytes[index];

        if allow_listed_char_for_devnode(byte, allow) {
            index += 1;
            continue;
        }

        // C accepts every "\\x" prefix, not merely a complete hexadecimal
        // escape. It advances two bytes and lets a later iteration validate
        // the remaining bytes independently.
        if byte == b'\\' && index + 1 < string_len && bytes[index + 1] == b'x' {
            index += 2;
            continue;
        }

        if let Some(width) = valid_utf8_unichar_len(&bytes[index..string_len]) {
            if width > 1 {
                index += width;
                continue;
            }
        }

        // Unlike `allow_listed_char_for_devnode`, C `isspace()` includes VT
        // and FF. A literal space is already accepted by the allow-list above;
        // this branch converts every other allowed whitespace byte to space.
        if c_isspace(byte) && allow.is_some_and(|list| list.contains(&b' ')) {
            bytes[index] = b' ';
        } else {
            bytes[index] = b'_';
        }
        index += 1;
        replaced += 1;
    }

    replaced
}

#[inline]
fn c_string_prefix(bytes: &[u8]) -> &[u8] {
    &bytes[..bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len())]
}

/// Safe byte-slice form of `utf8_encoded_valid_unichar(..., SIZE_MAX)`.
///
/// It mirrors the C validator rather than using `str::from_utf8()`: C accepts
/// one valid scalar followed by an invalid byte sequence, so validating the
/// whole suffix would change the replacement boundary.
fn valid_utf8_unichar_len(bytes: &[u8]) -> Option<usize> {
    let first = *bytes.first()?;
    let width = match first {
        0x00..=0x7f => 1,
        0xc0..=0xdf => 2,
        0xe0..=0xef => 3,
        0xf0..=0xf7 => 4,
        0xf8..=0xfb => 5,
        0xfc..=0xfd => 6,
        _ => return None,
    };

    if width == 1 {
        return Some(1);
    }
    let sequence = bytes.get(..width)?;
    if sequence[1..].iter().any(|byte| byte & 0xc0 != 0x80) {
        return None;
    }

    let initial_mask = match width {
        2 => 0x1f,
        3 => 0x0f,
        4 => 0x07,
        5 => 0x03,
        6 => 0x01,
        _ => unreachable!(),
    };
    let mut unichar = u32::from(first & initial_mask);
    for byte in &sequence[1..] {
        unichar = (unichar << 6) | u32::from(byte & 0x3f);
    }

    if encoded_len(unichar) != width || !valid_unichar(unichar) {
        return None;
    }
    Some(width)
}

#[inline]
const fn encoded_len(unichar: u32) -> usize {
    if unichar < 0x80 {
        1
    } else if unichar < 0x800 {
        2
    } else if unichar < 0x10000 {
        3
    } else if unichar < 0x200000 {
        4
    } else if unichar < 0x4000000 {
        5
    } else {
        6
    }
}

#[inline]
const fn valid_unichar(unichar: u32) -> bool {
    unichar < 0x110000
        && !(unichar >= 0xd800 && unichar <= 0xdfff)
        && !(unichar >= 0xfdd0 && unichar <= 0xfdef)
        && unichar & 0xfffe != 0xfffe
}

/// C ABI mirror of `udev_replace_whitespace()`.
///
/// # Safety
/// `str_` must be non-NULL and readable for exactly `len` bytes. `to` must be
/// non-NULL and writable for at least `len + 1` bytes. The ranges may be the
/// same (in-place replacement); other overlapping layouts are not supported
/// by the C authority either.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_udev_replace_whitespace(
    str_: *const c_char,
    to: *mut c_char,
    len: usize,
) -> usize {
    if str_.is_null() || to.is_null() {
        return 0;
    }

    // Work directly in the caller's bounded buffer, as the C helper does.
    // This avoids an allocator failure in an ABI whose size_t return has no
    // error channel. Output never advances beyond the byte already read, so
    // the documented `str_ == to` in-place form remains valid.
    let mut source = 0;
    let mut output = 0;
    let mut pending_space = false;
    while source < len {
        // SAFETY: `source < len` and the entry-point contract grants a
        // readable `len`-byte input range.
        let byte = unsafe { *str_.cast::<u8>().add(source) };
        if byte == 0 || !LEADING_WHITESPACE.contains(&byte) {
            break;
        }
        source += 1;
    }
    while output < len && source < len {
        // SAFETY: `source < len` and the input range is readable by contract.
        let byte = unsafe { *str_.cast::<u8>().add(source) };
        source += 1;
        if byte == 0 {
            break;
        }
        if c_isspace(byte) {
            pending_space = true;
            continue;
        }
        if pending_space {
            if output >= len.saturating_sub(1) {
                break;
            }
            // SAFETY: `output < len`, and the output range has `len + 1`
            // writable bytes. This write is never ahead of the byte read.
            unsafe { *to.cast::<u8>().add(output) = b'_' };
            output += 1;
            pending_space = false;
        }
        // SAFETY: `output < len`; the output range is writable by contract.
        unsafe { *to.cast::<u8>().add(output) = byte };
        output += 1;
    }
    // SAFETY: the contract grants `len + 1` writable bytes, so the terminator
    // at `output <= len` is always in bounds.
    unsafe { *to.cast::<u8>().add(output) = 0 };
    output
}

/// C ABI mirror of `udev_replace_chars()`.
///
/// # Safety
/// `str_` must be a non-NULL, writable NUL-terminated C string. If non-NULL,
/// `allow` must be a readable NUL-terminated C string for the duration of the
/// call. `allow` must not overlap `str_`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_udev_replace_chars(str_: *mut c_char, allow: *const c_char) -> usize {
    if str_.is_null() {
        return 0;
    }

    let allow = if allow.is_null() {
        None
    } else {
        // SAFETY: the caller contract supplies a readable NUL-terminated C
        // string and explicitly forbids overlap with the mutable input.
        Some(unsafe { CStr::from_ptr(allow) }.to_bytes())
    };
    // SAFETY: the caller contract supplies a readable NUL-terminated string.
    // The CStr borrow ends before the mutable slice is created.
    let len = unsafe { CStr::from_ptr(str_) }.to_bytes().len();
    // SAFETY: the caller contract supplies `len` writable bytes before the
    // NUL terminator. The safe byte core never accesses the terminator.
    let bytes = unsafe { std::slice::from_raw_parts_mut(str_.cast::<u8>(), len) };

    udev_replace_chars(bytes, allow)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn whitespace_preserves_fixed_width_and_in_place_boundaries() {
        assert_eq!(
            udev_replace_whitespace_bytes(b"  hello  world  "),
            b"hello_world"
        );
        assert_eq!(udev_replace_whitespace_bytes(&b"abcdef"[..4]), b"abcd");
        assert_eq!(udev_replace_whitespace_bytes(b"\x0bhello"), b"_hello");
    }

    #[test]
    fn chars_match_c_allow_hex_and_utf8_rules() {
        let mut bytes = b"test!@#$\\xGG\0".to_vec();
        assert_eq!(udev_replace_chars(&mut bytes, Some(b"#$@\0")), 1);
        assert_eq!(&bytes[..], b"test_@#$\\xGG\0");

        let mut bytes = b"a\xc3\xa9\xffb\0".to_vec();
        assert_eq!(udev_replace_chars(&mut bytes, None), 1);
        assert_eq!(&bytes[..], b"a\xc3\xa9_b\0");
    }
}
