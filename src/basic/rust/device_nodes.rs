// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: scope=basic.device-nodes; authority=src/basic/device-nodes.c,src/basic/device-nodes.h,src/basic/utf8.c,src/basic/utf8.h
//
// Device node name encoding: allow_listed_char_for_devnode, encode_devnode_name.

use crate::ffi::Errno;
use std::ffi::CStr;
use std::os::raw::{c_char, c_int};
use std::slice;

const HEX_LOWER: &[u8; 16] = b"0123456789abcdef";
const FIXED_ALLOWED: &[u8] = b"#+-.:=@_";

/// Check whether a raw byte is accepted in a device-node name.
///
/// This deliberately models C `strchr()` semantics: NUL is found at the
/// terminator of the fixed allow-list.
pub fn allow_listed_char_for_devnode(c: u8, additional: Option<&[u8]>) -> bool {
    c.is_ascii_digit()
        || c.is_ascii_alphabetic()
        || c == 0
        || FIXED_ALLOWED.contains(&c)
        || additional.is_some_and(|extra| extra.contains(&c))
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

/// Safe byte-slice form of C
/// `utf8_encoded_valid_unichar(input, SIZE_MAX)`.
///
/// Only the first encoded character is considered. Invalid sequences return
/// `None` so the encoder escapes their first raw byte and then tries again at
/// the following byte, exactly like the C loop.
fn valid_utf8_unichar_len(input: &[u8]) -> Option<usize> {
    let first = *input.first()?;
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

    let sequence = input.get(..width)?;
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

    (encoded_len(unichar) == width && valid_unichar(unichar)).then_some(width)
}

/// Encode raw bytes for use as a device-node name.
///
/// Valid multi-byte UTF-8 is copied unchanged. Backslash and bytes outside the
/// allow-list are encoded as `\xHH`. The output is NUL-terminated on success.
///
/// On insufficient capacity this returns `EINVAL`, as the C authority does,
/// and preserves all writes made before the failing capacity check. In
/// particular, a completed escape writes its temporary trailing NUL before
/// processing the next input byte.
pub fn encode_devnode_name(input: &[u8], output: &mut [u8]) -> Result<usize, Errno> {
    let mut i = 0;
    let mut j = 0;

    while i < input.len() {
        let seqlen = valid_utf8_unichar_len(&input[i..]);
        if seqlen.is_some_and(|n| n > 1) {
            let n = seqlen.unwrap();
            if output.len() - j < n {
                return Err(Errno::EINVAL);
            }

            output[j..j + n].copy_from_slice(&input[i..i + n]);
            i += n;
            j += n;
        } else if input[i] == b'\\' || !allow_listed_char_for_devnode(input[i], None) {
            /* C uses snprintf(..., 5, ...), including its temporary trailing NUL. */
            if output.len() - j < 5 {
                return Err(Errno::EINVAL);
            }

            let byte = input[i];
            output[j] = b'\\';
            output[j + 1] = b'x';
            output[j + 2] = HEX_LOWER[usize::from(byte >> 4)];
            output[j + 3] = HEX_LOWER[usize::from(byte & 0x0f)];
            output[j + 4] = 0;
            i += 1;
            j += 4;
        } else {
            if output.len() - j < 1 {
                return Err(Errno::EINVAL);
            }

            output[j] = input[i];
            i += 1;
            j += 1;
        }
    }

    if output.len() - j < 1 {
        return Err(Errno::EINVAL);
    }

    output[j] = 0;
    Ok(j)
}

/// C ABI mirror of `allow_listed_char_for_devnode()`.
///
/// # Safety
/// If `additional` is non-NULL, it must point to a readable NUL-terminated C
/// string that remains live for the duration of this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_allow_listed_char_for_devnode(
    c: c_char,
    additional: *const c_char,
) -> c_int {
    let additional = if additional.is_null() {
        None
    } else {
        // SAFETY: upheld by this function's caller contract.
        Some(unsafe { CStr::from_ptr(additional) }.to_bytes())
    };

    if allow_listed_char_for_devnode(c as u8, additional) {
        1
    } else {
        0
    }
}

/// C ABI mirror of `encode_devnode_name()`.
///
/// # Safety
/// `input` must point to a readable NUL-terminated C string. `output` must be
/// writable for `len` bytes. Both pointers must be non-NULL, and their live
/// ranges must not overlap.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_encode_devnode_name(
    input: *const c_char,
    output: *mut c_char,
    len: usize,
) -> c_int {
    if input.is_null() || output.is_null() {
        return Errno::EINVAL.to_neg_errno();
    }

    // SAFETY: the caller supplies a readable NUL-terminated input string.
    let input = unsafe { CStr::from_ptr(input) }.to_bytes();
    // SAFETY: the caller supplies a non-NULL output range of exactly `len`
    // bytes, disjoint from the live input range.
    let output = unsafe { slice::from_raw_parts_mut(output.cast::<u8>(), len) };

    match encode_devnode_name(input, output) {
        Ok(_) => 0,
        Err(error) => error.to_neg_errno(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ptr;

    #[test]
    fn allow_list_matches_c_strchr_semantics() {
        for c in b'0'..=b'9' {
            assert!(allow_listed_char_for_devnode(c, None));
        }
        for c in b'a'..=b'z' {
            assert!(allow_listed_char_for_devnode(c, None));
        }
        for c in b'A'..=b'Z' {
            assert!(allow_listed_char_for_devnode(c, None));
        }
        for &c in FIXED_ALLOWED {
            assert!(allow_listed_char_for_devnode(c, None));
        }

        assert!(allow_listed_char_for_devnode(0, None));
        assert!(allow_listed_char_for_devnode(b'!', Some(b"!/")));
        assert!(!allow_listed_char_for_devnode(b'!', None));
        assert!(!allow_listed_char_for_devnode(0xff, None));
    }

    #[test]
    fn encode_allowed_escaped_and_valid_utf8() {
        let input = "valíd\\ųtf8".as_bytes();
        let mut output = [0xa5; 64];

        assert_eq!(encode_devnode_name(input, &mut output), Ok(15));
        assert_eq!(&output[..=15], b"val\xc3\xadd\\x5c\xc5\xb3tf8\0");
    }

    #[test]
    fn invalid_utf8_is_escaped_one_raw_byte_at_a_time() {
        let cases: &[(&[u8], &[u8])] = &[
            (&[0xc2, b'A'], b"\\xc2A"),
            (&[0xc0, 0x80], b"\\xc0\\x80"),
            (&[0xed, 0xa0, 0x80], b"\\xed\\xa0\\x80"),
            (&[0xef, 0xb7, 0x90], b"\\xef\\xb7\\x90"),
            (&[0xf4, 0x90, 0x80, 0x80], b"\\xf4\\x90\\x80\\x80"),
            (&[0xff], b"\\xff"),
        ];

        for &(input, expected) in cases {
            let mut output = [0xa5; 32];
            let written = encode_devnode_name(input, &mut output).unwrap();
            assert_eq!(&output[..written], expected);
            assert_eq!(output[written], 0);
        }
    }

    #[test]
    fn capacity_failure_preserves_c_partial_writes() {
        let mut allowed = [0xa5; 1];
        assert_eq!(encode_devnode_name(b"ab", &mut allowed), Err(Errno::EINVAL));
        assert_eq!(allowed, [b'a']);

        let mut escaped = [0xa5; 5];
        assert_eq!(encode_devnode_name(b" a", &mut escaped), Err(Errno::EINVAL));
        assert_eq!(&escaped, b"\\x20a");

        let mut utf8 = [0xa5; 2];
        assert_eq!(
            encode_devnode_name("í".as_bytes(), &mut utf8),
            Err(Errno::EINVAL)
        );
        assert_eq!(utf8, [0xc3, 0xad]);

        let mut too_short_for_snprintf = [0xa5; 4];
        assert_eq!(
            encode_devnode_name(b" ", &mut too_short_for_snprintf),
            Err(Errno::EINVAL)
        );
        assert_eq!(too_short_for_snprintf, [0xa5; 4]);
    }

    #[test]
    fn exact_capacity_includes_final_nul() {
        let mut output = [0xa5; 4];
        assert_eq!(encode_devnode_name(b"abc", &mut output), Ok(3));
        assert_eq!(&output, b"abc\0");
    }

    #[test]
    fn ffi_rejects_null_pointers() {
        let mut output = [0 as c_char; 1];

        // SAFETY: null inputs are explicitly accepted and rejected before dereference.
        assert_eq!(
            unsafe { rs_encode_devnode_name(ptr::null(), output.as_mut_ptr(), output.len()) },
            Errno::EINVAL.to_neg_errno()
        );
        // SAFETY: null output is explicitly accepted and rejected before dereference.
        assert_eq!(
            unsafe { rs_encode_devnode_name(c"".as_ptr(), ptr::null_mut(), 0) },
            Errno::EINVAL.to_neg_errno()
        );
    }
}
