// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/basic/string-util.c, src/basic/json-util.h
//
// Small in-place mutation helpers. This domain has no dependency on the
// string-util facade or other string utility domains.

use std::ffi::c_void;

use libc::c_char;

use crate::ffi::Errno;

/// C `strgrowpad0()`: grow an owned C string and clear new storage.
///
/// # Safety
/// `s` must point to null or a uniquely-owned malloc-compatible NUL-terminated
/// allocation. On success ownership is replaced with the realloc result.
pub unsafe fn rs_strgrowpad0(s: *mut *mut c_char, l: usize) -> i32 {
    if s.is_null() {
        return Errno::EINVAL.to_neg_errno();
    }

    // SAFETY: `s` is writable for one pointer by the function contract.
    let size = if unsafe { (*s).is_null() } {
        0
    } else {
        // SAFETY: the non-null allocation is NUL terminated by contract.
        unsafe { crate::ffi::strlen(*s) + 1 }
    };
    if size >= l {
        return 0;
    }

    // SAFETY: `*s` is null or a unique malloc-compatible allocation; realloc
    // leaves it valid and owned by the caller if allocation fails.
    let replacement = unsafe { crate::ffi::realloc((*s).cast::<c_void>(), l) };
    if replacement.is_null() {
        return Errno::ENOMEM.to_neg_errno();
    }
    // SAFETY: `replacement` owns `l` bytes and `[size, l)` is newly exposed.
    unsafe {
        *s = replacement.cast::<c_char>();
        crate::ffi::memset(replacement.add(size), 0, l - size);
    }
    0
}

/// C `json_underscorify()`: normalize JSON-style separators in place.
///
/// # Safety
/// `p` must be null or a writable NUL-terminated byte string.
pub unsafe fn rs_json_underscorify(p: *mut c_char) -> *mut c_char {
    if p.is_null() {
        return std::ptr::null_mut();
    }
    let mut q = p;
    // SAFETY: `q` initially points into the writable NUL-terminated string.
    while unsafe { *q } != 0 {
        // SAFETY: `q` remains within the writable NUL-terminated string.
        unsafe {
            if matches!(*q as u8, b'-' | b'+' | b'_') {
                *q = b'_' as c_char;
            }
            q = q.add(1);
        }
    }
    p
}

/// C `json_dashify()`: normalize JSON-style separators in place.
///
/// # Safety
/// `p` must be null or a writable NUL-terminated byte string.
pub unsafe fn rs_json_dashify(p: *mut c_char) -> *mut c_char {
    if p.is_null() {
        return std::ptr::null_mut();
    }
    let mut q = p;
    // SAFETY: `q` initially points into the writable NUL-terminated string.
    while unsafe { *q } != 0 {
        // SAFETY: `q` remains within the writable NUL-terminated string.
        unsafe {
            if matches!(*q as u8, b'_' | b'-' | b'+') {
                *q = b'-' as c_char;
            }
            q = q.add(1);
        }
    }
    p
}
