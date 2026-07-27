// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/basic/string-util.c
//
// Read-only string scanning, distance, and version validation. No sibling
// string-util domain is imported, keeping this layer acyclic.

use std::ffi::CStr;

use libc::c_char;

use crate::path_util::rs_filename_part_is_valid;

/// # Safety
/// `s` and `charset` must designate readable NUL-terminated byte strings.
pub unsafe fn rs_in_charset(s: *const c_char, charset: *const c_char) -> bool {
    if s.is_null() || charset.is_null() {
        return false;
    }
    // SAFETY: both pointers are valid C strings by the function contract.
    let bytes = unsafe { CStr::from_ptr(s) }.to_bytes();
    // SAFETY: both pointers are valid C strings by the function contract.
    let charset = unsafe { CStr::from_ptr(charset) }.to_bytes();
    bytes.iter().all(|byte| charset.contains(byte))
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

    for index in 0..=l {
        // SAFETY: the caller guarantees that each byte through the first NUL,
        // or all `l + 1` bytes when no NUL occurs, is readable.
        if unsafe { *s.add(index) } == 0 {
            return s;
        }
    }

    // SAFETY: no earlier NUL was found, so the contract guarantees byte `l`
    // is writable. This is exactly the byte C's `strshorten()` overwrites.
    unsafe { *s.add(l) = 0 };
    s
}

/// # Safety
/// `haystack` and `needle` must be readable NUL-terminated byte strings when
/// non-null. The returned pointer aliases `haystack`.
pub unsafe fn rs_strrstr_internal(haystack: *const c_char, needle: *const c_char) -> *mut c_char {
    if haystack.is_null() || needle.is_null() {
        return std::ptr::null_mut();
    }
    // SAFETY: both pointers are valid C strings by the function contract.
    let haystack_bytes = unsafe { CStr::from_ptr(haystack) }.to_bytes();
    // SAFETY: both pointers are valid C strings by the function contract.
    let needle_bytes = unsafe { CStr::from_ptr(needle) }.to_bytes();
    if needle_bytes.is_empty() {
        // SAFETY: the NUL terminator lies immediately after `haystack_bytes`.
        return unsafe { (haystack as *mut c_char).add(haystack_bytes.len()) };
    }

    let mut last = std::ptr::null_mut();
    for offset in 0..=haystack_bytes.len().saturating_sub(needle_bytes.len()) {
        if haystack_bytes[offset..].starts_with(needle_bytes) {
            // SAFETY: `offset` indexes a byte in (or the terminator after)
            // the validated `haystack` C string.
            last = unsafe { (haystack as *mut c_char).add(offset) };
        }
    }
    last
}

/// # Safety
/// `x` and `y` must be null or readable NUL-terminated byte strings.
pub unsafe fn rs_strlevenshtein(x: *const c_char, y: *const c_char) -> isize {
    const E2BIG: isize = 7;
    const ENOMEM: isize = 12;
    if x.is_null() && y.is_null() {
        return 0;
    }
    let xb = if x.is_null() {
        &[]
    } else {
        // SAFETY: non-null `x` is a readable C string by the function contract.
        unsafe { CStr::from_ptr(x) }.to_bytes()
    };
    let yb = if y.is_null() {
        &[]
    } else {
        // SAFETY: non-null `y` is a readable C string by the function contract.
        unsafe { CStr::from_ptr(y) }.to_bytes()
    };
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
    // SAFETY: non-null `s` is a readable NUL-terminated string by contract.
    let bytes = unsafe { CStr::from_ptr(s) }.to_bytes();
    if bytes.is_empty() && flags & VERSION_ALLOW_EMPTY == 0 {
        return false;
    }
    // SAFETY: non-null `s` satisfies the callee's C-string contract.
    if !unsafe { rs_filename_part_is_valid(s) } {
        return false;
    }

    bytes.iter().all(|byte| {
        byte.is_ascii_alphanumeric()
            || matches!(*byte, b'.' | b'-' | b'~' | b'^')
            || (*byte == b'_' && flags & VERSION_ALLOW_UNDERSCORE != 0)
            || (*byte == b'+' && flags & VERSION_ALLOW_PLUS != 0)
    })
}
