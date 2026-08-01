// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/basic/string-util.c
//
// Read-only string scanning, distance, and version validation. No sibling
// string-util domain is imported, keeping this layer acyclic.

// Centralized unsafe expression boundary for this module.
macro_rules! unsafe_ffi {
    ($expression:expr) => {{
        // SAFETY: the enclosing helper documents and validates this operation.
        unsafe { $expression }
    }};
}
use std::ffi::CStr;

use libc::c_char;

use crate::path_util::rs_filename_part_is_valid;

/// Calls `operation` with the byte contents of two valid C strings.
///
/// The raw pointers never escape this adapter, so callers can keep scanning
/// logic byte-oriented after validating the FFI boundary once. When requested,
/// null pointers are represented as empty byte strings.
fn with_c_string_pair<T>(
    left: *const c_char,
    right: *const c_char,
    nulls_are_empty: bool,
    operation: impl FnOnce(&[u8], &[u8]) -> T,
) -> Option<T> {
    if !nulls_are_empty && (left.is_null() || right.is_null()) {
        return None;
    }

    // SAFETY: callers use this adapter only under their C-string contracts.
    let left = if left.is_null() {
        &[]
    } else {
        // SAFETY: the non-null pointer is covered by this adapter's C-string contract.
        unsafe_ffi!(CStr::from_ptr(left)).to_bytes()
    };
    // SAFETY: callers use this adapter only under their C-string contracts.
    let right = if right.is_null() {
        &[]
    } else {
        // SAFETY: the non-null pointer is covered by this adapter's C-string contract.
        unsafe_ffi!(CStr::from_ptr(right)).to_bytes()
    };
    Some(operation(left, right))
}

fn strrstr_offset(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(haystack.len());
    }

    let mut last = None;
    for offset in 0..=haystack.len().saturating_sub(needle.len()) {
        if haystack[offset..].starts_with(needle) {
            last = Some(offset);
        }
    }
    last
}

/// # Safety
/// `s` and `charset` must designate readable NUL-terminated byte strings.
pub unsafe fn rs_in_charset(s: *const c_char, charset: *const c_char) -> bool {
    with_c_string_pair(s, charset, false, |bytes, charset| {
        bytes.iter().all(|byte| charset.contains(byte))
    })
    .unwrap_or(false)
}

/// Rust representation of `char_is_cc()`'s explicitly unsigned comparison.
///
/// C deliberately casts its `char` parameter to `uint8_t` before testing the
/// C0 range, because the signedness of `char` is target-dependent. Keeping
/// that conversion at the ABI edge makes this byte-only core independent of
/// the target's `char` ABI.
pub fn rs_char_is_cc(p: u8) -> bool {
    p < b' ' || p == 127
}

/// # Safety
/// `s` must be non-null and readable through its first NUL byte or for
/// `l + 1` bytes, whichever comes first. If no NUL occurs in the first `l`
/// bytes, byte `l` must be writable. This is the exact bounded `strnlen()`
/// contract used by C and does not require a terminator beyond byte `l`.
pub unsafe fn rs_strshorten(s: *mut c_char, l: usize) -> *mut c_char {
    if s.is_null() || l >= usize::MAX - 1 {
        return s;
    }

    // SAFETY: the caller guarantees that the bounded byte range is readable,
    // and that its last byte is writable if no earlier NUL is found.
    unsafe_ffi!({
        if std::slice::from_raw_parts(s.cast_const(), l + 1).contains(&0) {
            return s;
        }

        // No earlier NUL was found, so the contract guarantees byte `l` is
        // writable. This is exactly the byte C's `strshorten()` overwrites.
        *s.add(l) = 0;
    });
    s
}

/// # Safety
/// `haystack` and `needle` must be readable NUL-terminated byte strings when
/// non-null. The returned pointer aliases `haystack`.
pub unsafe fn rs_strrstr_internal(haystack: *const c_char, needle: *const c_char) -> *mut c_char {
    let Some(offset) = with_c_string_pair(haystack, needle, false, strrstr_offset).flatten() else {
        return std::ptr::null_mut();
    };

    // `offset` indexes a byte in (or the terminator after) the validated
    // `haystack` C string. `wrapping_add()` preserves that pointer value
    // without creating a second raw-pointer operation at the ABI boundary.
    (haystack as *mut c_char).wrapping_add(offset)
}

/// # Safety
/// `x` and `y` must be null or readable NUL-terminated byte strings.
pub unsafe fn rs_strlevenshtein(x: *const c_char, y: *const c_char) -> isize {
    // Null inputs deliberately scan as empty strings, matching the C API.
    with_c_string_pair(x, y, true, levenshtein_bytes)
        .expect("nulls_are_empty makes the C-string adapter infallible")
}

fn levenshtein_bytes(xb: &[u8], yb: &[u8]) -> isize {
    const E2BIG: isize = 7;
    const ENOMEM: isize = 12;
    if xb == yb {
        return 0;
    }
    if xb.len() > isize::MAX as usize || yb.len() > isize::MAX as usize {
        return -E2BIG;
    }
    if xb.is_empty() {
        return yb.len() as isize;
    }
    if yb.is_empty() {
        return xb.len() as isize;
    }

    let row_len = match yb.len().checked_add(1) {
        Some(len) => len,
        None => return -ENOMEM,
    };

    // `new0()` in the C implementation reports allocation failure as
    // `-ENOMEM`. `Vec::try_reserve_exact` gives this safe implementation the
    // same failure mode instead of relying on an infallible `vec!` allocation.
    fn zeroed_row(len: usize) -> Result<Vec<usize>, ()> {
        let mut row = Vec::new();
        row.try_reserve_exact(len).map_err(|_| ())?;
        row.resize(len, 0);
        Ok(row)
    }

    let mut before_previous = match zeroed_row(row_len) {
        Ok(row) => row,
        Err(()) => return -ENOMEM,
    };
    let mut previous = match zeroed_row(row_len) {
        Ok(row) => row,
        Err(()) => return -ENOMEM,
    };
    let mut current = match zeroed_row(row_len) {
        Ok(row) => row,
        Err(()) => return -ENOMEM,
    };
    for (index, value) in previous.iter_mut().enumerate() {
        *value = index;
    }
    for (i, &x_byte) in xb.iter().enumerate() {
        current[0] = i + 1;
        for (j, &y_byte) in yb.iter().enumerate() {
            let mut distance = previous[j] + usize::from(x_byte != y_byte);
            if i > 0 && j > 0 && xb[i - 1] == y_byte && x_byte == yb[j - 1] {
                distance = distance.min(before_previous[j - 1] + 1);
            }
            distance = distance.min(previous[j + 1] + 1).min(current[j] + 1);
            current[j + 1] = distance;
        }
        std::mem::swap(&mut before_previous, &mut previous);
        std::mem::swap(&mut previous, &mut current);
    }
    previous[yb.len()] as isize
}

/// # Safety
/// `s` must be a readable NUL-terminated string when non-null. `flags` uses
/// the C `VersionFlags` bit values (`1`, `2`, and `4`); unknown bits are
/// ignored, matching `FLAGS_SET()`.
pub unsafe fn rs_version_is_valid(s: *const c_char, flags: i32) -> bool {
    const VERSION_ALLOW_EMPTY: i32 = 1 << 0;
    const VERSION_ALLOW_UNDERSCORE: i32 = 1 << 1;
    const VERSION_ALLOW_PLUS: i32 = 1 << 2;

    if s.is_null() {
        return false;
    }
    // SAFETY: non-null `s` is a readable NUL-terminated string by contract
    // and satisfies `rs_filename_part_is_valid()`'s C-string requirement.
    let Some(bytes) = (unsafe_ffi!({
        let bytes = CStr::from_ptr(s).to_bytes();
        if bytes.is_empty() && flags & VERSION_ALLOW_EMPTY == 0 {
            None
        } else if !rs_filename_part_is_valid(s) {
            None
        } else {
            Some(bytes)
        }
    })) else {
        return false;
    };

    bytes.iter().all(|byte| {
        byte.is_ascii_alphanumeric()
            || matches!(*byte, b'.' | b'-' | b'~' | b'^')
            || (*byte == b'_' && flags & VERSION_ALLOW_UNDERSCORE != 0)
            || (*byte == b'+' && flags & VERSION_ALLOW_PLUS != 0)
    })
}
