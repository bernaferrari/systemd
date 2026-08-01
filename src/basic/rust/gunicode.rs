// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: scope=basic.gunicode; authority=src/basic/gunicode.c,src/basic/gunicode.h
//
// Unicode manipulation: prev_char, skip_data, iswide.

use std::ffi::c_char;

// ── UTF-8 skip data table ─────────────────────────────────────────────────

/// Number of bytes to skip for each leading UTF-8 byte.
/// Copied from C gunicode.c (Unicode 6.0).
pub const UTF8_SKIP_DATA: [u8; 256] = [
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 4, 4, 4, 4, 4, 4, 4, 4, 5, 5, 5, 5, 6, 6, 1, 1,
];

const fn utf8_skip_data_as_c_char() -> [c_char; 256] {
    let mut result = [0; 256];
    let mut index = 0;
    while index < UTF8_SKIP_DATA.len() {
        result[index] = UTF8_SKIP_DATA[index] as c_char;
        index += 1;
    }
    result
}

/// C ABI export corresponding to `utf8_skip_data`.
///
/// The table is byte-for-byte identical to C and uses C's `char` element
/// type, rather than merely an equivalently sized Rust integer type.
#[allow(non_upper_case_globals)]
#[unsafe(no_mangle)]
pub static rs_utf8_skip_data: [c_char; 256] = utf8_skip_data_as_c_char();

// ── Public API ────────────────────────────────────────────────────────────

/// Return the number of bytes for the UTF-8 sequence starting with byte c.
pub fn utf8_skip_data_get(c: u8) -> u8 {
    UTF8_SKIP_DATA[c as usize]
}

/// Faithful port of C utf8_prev_char().
/// Finds the byte index of the previous UTF-8 character before position `pos`
/// in `data`. Scans backwards until finding a byte that is not a continuation
/// byte (i.e., not in range 0x80..=0xBF).
/// Panics if pos is 0 or out of bounds.
pub fn utf8_prev_char(data: &[u8], pos: usize) -> usize {
    assert!(pos > 0 && pos <= data.len());
    let mut p = pos;
    loop {
        p -= 1;
        if (data[p] & 0xc0) != 0x80 {
            return p;
        }
    }
}

/// C ABI twin of `utf8_prev_char()`.
///
/// # Safety
/// `p` must be non-null and point into (or one byte past) a live byte
/// allocation. There must be a non-continuation byte before `p` in the same
/// allocation, and every byte inspected while walking backwards must be
/// readable. As in C, this routine does not validate UTF-8 and callers must
/// not use it when `p` might be the first byte of the allocation.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_utf8_prev_char(p: *const c_char) -> *mut c_char {
    if p.is_null() {
        // Match the C function's assert(p) precondition without unwinding
        // across the C ABI boundary.
        std::process::abort();
    }

    let mut current = p;
    loop {
        // SAFETY: the caller contract guarantees that each predecessor stays
        // within the same allocation and is readable, until this returns.
        current = unsafe_ffi!(current.sub(1));
        // SAFETY: `current` is readable by the caller contract above.
        let byte = unsafe_ffi!(current.read()) as u8;
        if (byte & 0xc0) != 0x80 {
            return current.cast_mut();
        }
    }
}

/// Faithful port of C unichar_iswide() from gunicode.c (Unicode 6.0 table).
/// Checks if a Unicode codepoint is wide (takes 2 columns in terminal).
pub fn unichar_iswide(uc: u32) -> bool {
    const WIDE: &[(u32, u32)] = &[
        (0x1100, 0x115F),
        (0x2329, 0x232A),
        (0x2E80, 0x2E99),
        (0x2E9B, 0x2EF3),
        (0x2F00, 0x2FD5),
        (0x2FF0, 0x2FFB),
        (0x3000, 0x303E),
        (0x3041, 0x3096),
        (0x3099, 0x30FF),
        (0x3105, 0x312D),
        (0x3131, 0x318E),
        (0x3190, 0x31BA),
        (0x31C0, 0x31E3),
        (0x31F0, 0x321E),
        (0x3220, 0x3247),
        (0x3250, 0x32FE),
        (0x3300, 0x4DBF),
        (0x4E00, 0xA48C),
        (0xA490, 0xA4C6),
        (0xA960, 0xA97C),
        (0xAC00, 0xD7A3),
        (0xF900, 0xFAFF),
        (0xFE10, 0xFE19),
        (0xFE30, 0xFE52),
        (0xFE54, 0xFE66),
        (0xFE68, 0xFE6B),
        (0xFF01, 0xFF60),
        (0xFFE0, 0xFFE6),
        (0x1B000, 0x1B001),
        (0x1F200, 0x1F202),
        (0x1F210, 0x1F23A),
        (0x1F240, 0x1F248),
        (0x1F250, 0x1F251),
        (0x1F300, 0x1F567),
        (0x20000, 0x2FFFD),
        (0x30000, 0x3FFFD),
    ];
    WIDE.iter().any(|&(lo, hi)| uc >= lo && uc <= hi)
}

/// C ABI twin of `unichar_iswide()`.
#[unsafe(no_mangle)]
pub extern "C" fn rs_unichar_iswide(c: u32) -> bool {
    unichar_iswide(c)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_utf8_prev_char_ascii() {
        let s = b"hello";
        assert_eq!(utf8_prev_char(s, 4), 3);
        assert_eq!(s[utf8_prev_char(s, 4)], b'l');
    }

    #[test]
    fn test_utf8_prev_char_two_byte() {
        let s = "a\u{00E9}b".as_bytes();
        let pos = s.len() - 1;
        let prev = utf8_prev_char(s, pos);
        assert_eq!(&s[prev..pos], "é".as_bytes());
    }

    #[test]
    fn test_utf8_prev_char_three_byte() {
        let s = "a\u{4E00}b".as_bytes();
        let pos = s.len() - 1;
        let prev = utf8_prev_char(s, pos);
        assert_eq!(&s[prev..pos], "一".as_bytes());
    }

    #[test]
    fn test_utf8_skip_data_get_ascii() {
        assert_eq!(utf8_skip_data_get(0x00), 1);
        assert_eq!(utf8_skip_data_get(0x7F), 1);
    }

    #[test]
    fn test_utf8_skip_data_get_multibyte() {
        assert_eq!(utf8_skip_data_get(0xC0), 2);
        assert_eq!(utf8_skip_data_get(0xE0), 3);
        assert_eq!(utf8_skip_data_get(0xF0), 4);
        assert_eq!(utf8_skip_data_get(0xF8), 5);
        assert_eq!(utf8_skip_data_get(0xFC), 6);
    }

    #[test]
    fn test_utf8_skip_data_continuation_bytes() {
        for b in 0x80u8..=0xBF {
            assert_eq!(utf8_skip_data_get(b), 1);
        }
    }

    #[test]
    fn test_unichar_iswide_cjk() {
        assert!(unichar_iswide(0x4E00));
    }

    #[test]
    fn test_unichar_iswide_hangul() {
        assert!(unichar_iswide(0xAC00));
    }

    #[test]
    fn test_unichar_iswide_hiragana() {
        assert!(unichar_iswide(0x3041));
    }

    #[test]
    fn test_unichar_iswide_katakana() {
        assert!(unichar_iswide(0x30A0));
    }

    #[test]
    fn test_unichar_iswide_cjk_punctuation() {
        assert!(unichar_iswide(0x3000));
    }

    #[test]
    fn test_unichar_iswide_fullwidth_latin() {
        assert!(unichar_iswide(0xFF01));
    }

    #[test]
    fn test_unichar_iswide_not_wide_latin() {
        assert!(!unichar_iswide(0x0041));
    }

    #[test]
    fn test_unichar_iswide_not_wide_euro_sign() {
        assert!(!unichar_iswide(0x20AC));
    }

    #[test]
    fn test_unichar_iswide_boundary_start() {
        assert!(unichar_iswide(0x1100));
    }

    #[test]
    fn test_unichar_iswide_boundary_end() {
        assert!(unichar_iswide(0x115F));
    }

    #[test]
    fn test_unichar_iswide_just_before_range() {
        assert!(!unichar_iswide(0x10FF));
    }

    #[test]
    fn test_unichar_iswide_just_after_range() {
        assert!(!unichar_iswide(0x1160));
    }

    #[test]
    fn test_unichar_iswide_emoji() {
        assert!(unichar_iswide(0x1F300));
    }

    #[test]
    fn test_unichar_iswide_zero() {
        assert!(!unichar_iswide(0));
    }

    #[test]
    fn test_unichar_iswide_max_unicode() {
        assert!(!unichar_iswide(0x10FFFF));
    }

    #[test]
    fn test_unichar_iswide_ascii_range() {
        for c in 0..=127u32 {
            assert!(!unichar_iswide(c), "ASCII char {} should not be wide", c);
        }
    }
}
