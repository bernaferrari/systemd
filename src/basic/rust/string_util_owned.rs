// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/basic/string-util.c
//
// C-allocation and ownership-transfer adapters. This is a leaf domain: other
// string-util modules may allocate through it, but it imports no sibling.
//
// SAFETY: every raw operation below is covered by the containing function's
// explicit pointer/ownership contract; allocation sites additionally document
// allocator provenance and the exact point where ownership is published.

use std::ffi::{CStr, c_void};

use libc::c_char;

use crate::ffi::{Errno, calloc, free, malloc};

pub(crate) fn alloc_empty_c_string() -> *mut c_char {
    // SAFETY: malloc(1) returns null or one writable byte owned by the caller.
    let ptr = unsafe { malloc(1) }.cast::<c_char>();
    if !ptr.is_null() {
        // SAFETY: successful malloc above provided exactly one writable byte.
        unsafe { *ptr = 0 };
    }
    ptr
}

pub(crate) fn alloc_c_string_from_bytes(bytes: &[u8]) -> *mut c_char {
    let Some(allocation_size) = bytes.len().checked_add(1) else {
        return std::ptr::null_mut();
    };
    let ptr = malloc(allocation_size).cast::<c_char>();
    if ptr.is_null() {
        return std::ptr::null_mut();
    }
    // SAFETY: `ptr` owns `allocation_size` bytes and `bytes` is live/readable.
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), ptr.cast::<u8>(), bytes.len());
        *ptr.add(bytes.len()) = 0;
    }
    ptr
}

/// # Safety
/// `src` must be null or a readable NUL-terminated string. When non-null,
/// `ret` must be null or writable for one pointer.
pub unsafe fn rs_strdup_to_full(ret: *mut *mut c_char, src: *const c_char) -> i32 {
    if src.is_null() {
        if !ret.is_null() {
            // SAFETY: non-null `ret` is writable by contract.
            unsafe { *ret = std::ptr::null_mut() };
        }
        return 0;
    }
    if ret.is_null() {
        return 1;
    }
    // SAFETY: non-null `src` is a readable C string by the function contract.
    let copy = alloc_c_string_from_bytes(unsafe { CStr::from_ptr(src) }.to_bytes());
    if copy.is_null() {
        return Errno::ENOMEM.to_neg_errno();
    }
    // SAFETY: non-null `ret` is writable by contract and takes ownership.
    unsafe { *ret = copy };
    1
}

/// # Safety
/// `p` must point to null or a unique malloc-compatible string; `s` must be
/// null or a readable NUL-terminated string.
pub unsafe fn rs_free_and_strdup(p: *mut *mut c_char, s: *const c_char) -> i32 {
    if p.is_null() {
        return Errno::EINVAL.to_neg_errno();
    }

    // SAFETY: `p` is writable for one pointer by the function contract.
    let old = unsafe { *p };
    // SAFETY: `old` and non-null `s` meet this public function's C-string
    // contract.
    if unsafe { c_strings_equal_null_safe(old, s) } {
        return 0;
    }
    let replacement = if s.is_null() {
        std::ptr::null_mut()
    } else {
        // SAFETY: non-null `s` is a readable C string by the function contract.
        let copy = alloc_c_string_from_bytes(unsafe { CStr::from_ptr(s) }.to_bytes());
        if copy.is_null() {
            return Errno::ENOMEM.to_neg_errno();
        }
        copy
    };
    // SAFETY: `p` is writable for one pointer by the function contract.
    if !old.is_null() {
        // SAFETY: `*p` is the unique C allocation relinquished by this API.
        unsafe { free(old.cast::<c_void>()) };
    }
    // SAFETY: `p` is writable and receives unique ownership of replacement.
    unsafe { *p = replacement };
    1
}

/// # Safety
/// `p` must point to null or a unique malloc-compatible string; `s` must be
/// readable through its first NUL byte or for `l` bytes, whichever comes
/// first, when non-null.
pub unsafe fn rs_free_and_strndup(p: *mut *mut c_char, s: *const c_char, l: usize) -> i32 {
    if p.is_null() || (s.is_null() && l != 0) {
        return Errno::EINVAL.to_neg_errno();
    }
    // SAFETY: non-null `p` is writable for one pointer by the contract.
    let old = unsafe { *p };
    if old.is_null() && s.is_null() {
        return 0;
    }
    // SAFETY: `old` is a C string and non-null `s` is readable for `l` bytes
    // by this public function's contract.
    if !old.is_null() && !s.is_null() && unsafe { strndup_result_matches(old.cast_const(), s, l) } {
        return 0;
    }

    let replacement = if s.is_null() {
        std::ptr::null_mut()
    } else {
        let mut copy_len = 0usize;
        // SAFETY: `s` is readable for `l` bytes by the function contract.
        while copy_len < l && unsafe { *s.add(copy_len) } != 0 {
            copy_len += 1;
        }
        // SAFETY: `s` is readable for copy_len bytes by contract.
        let bytes = unsafe { std::slice::from_raw_parts(s.cast::<u8>(), copy_len) };
        let copy = alloc_c_string_from_bytes(bytes);
        if copy.is_null() {
            return Errno::ENOMEM.to_neg_errno();
        }
        copy
    };
    // SAFETY: `p` is writable for one pointer by the function contract.
    if !old.is_null() {
        // SAFETY: replacement is complete before the unique old allocation is released.
        unsafe { free(old.cast::<c_void>()) };
    }
    // SAFETY: `p` is writable and receives unique ownership of replacement.
    unsafe { *p = replacement };
    1
}

/// Null-safe content equality matching C's `streq_ptr()`. The raw pointers are
/// not compared for identity because distinct owned allocations may hold the
/// same string and must retain the C API's no-op result.
///
/// # Safety
/// Each non-null pointer must reference a readable NUL-terminated C string.
unsafe fn c_strings_equal_null_safe(left: *const c_char, right: *const c_char) -> bool {
    match (left.is_null(), right.is_null()) {
        (true, true) => true,
        (true, false) | (false, true) => false,
        (false, false) => {
            // SAFETY: required by this helper's contract.
            unsafe { CStr::from_ptr(left).to_bytes() == CStr::from_ptr(right).to_bytes() }
        }
    }
}

/// Return whether `strndup(source, len)` would retain the current `old`
/// allocation unchanged. This is the exact `strneq()` plus terminator check
/// used by C's `free_and_strndup()`: a source terminator before `len` is part
/// of the comparison, while a terminator at `len` permits a full-length match.
///
/// # Safety
/// `old` must be readable through its NUL terminator, and `source` must be
/// readable through its first NUL byte or for `len` bytes, whichever comes
/// first.
unsafe fn strndup_result_matches(old: *const c_char, source: *const c_char, len: usize) -> bool {
    for index in 0..len {
        // SAFETY: `old` is NUL terminated, so the loop stops at its first NUL
        // before advancing past it; `source` is readable for `len` bytes.
        let (old_byte, source_byte) = unsafe { (*old.add(index), *source.add(index)) };
        if old_byte != source_byte {
            return false;
        }
        if old_byte == 0 {
            return true;
        }
    }

    // SAFETY: reaching here means `old[..len]` contained no NUL, so index
    // `len` still denotes a byte in its NUL-terminated allocation.
    unsafe { *old.add(len) == 0 }
}

const MAKE_CSTRING_REFUSE_TRAILING_NUL: i32 = 0;
const MAKE_CSTRING_REQUIRE_TRAILING_NUL: i32 = 2;

/// # Safety
/// `s` must be readable for `n` bytes when non-null; non-null `ret` must be
/// writable for one owned pointer.
pub unsafe fn rs_make_cstring(s: *const c_char, n: usize, mode: i32, ret: *mut *mut c_char) -> i32 {
    if (s.is_null() && n != 0) || !(0..=2).contains(&mode) {
        return Errno::EINVAL.to_neg_errno();
    }
    if n == 0 {
        if mode == MAKE_CSTRING_REQUIRE_TRAILING_NUL {
            return Errno::EINVAL.to_neg_errno();
        }
        if ret.is_null() {
            return 0;
        }
        // SAFETY: calloc returns null or a unique zeroed byte.
        let value = unsafe { calloc(1, 1) }.cast::<c_char>();
        if value.is_null() {
            return Errno::ENOMEM.to_neg_errno();
        }
        // SAFETY: `ret` is writable by contract and takes ownership.
        unsafe { *ret = value };
        return 0;
    }

    // SAFETY: the function contract grants a readable `n`-byte source range.
    let bytes = unsafe { std::slice::from_raw_parts(s.cast::<u8>(), n) };
    let nul = bytes.iter().position(|&byte| byte == 0);
    let actual_n = match nul {
        Some(position) if position < n - 1 || mode == MAKE_CSTRING_REFUSE_TRAILING_NUL => {
            return Errno::EINVAL.to_neg_errno();
        }
        Some(position) => position,
        None if mode == MAKE_CSTRING_REQUIRE_TRAILING_NUL => return Errno::EINVAL.to_neg_errno(),
        None => n,
    };
    if ret.is_null() {
        return 0;
    }
    let value = alloc_c_string_from_bytes(&bytes[..actual_n]);
    if value.is_null() {
        return Errno::ENOMEM.to_neg_errno();
    }
    // SAFETY: `ret` is writable by contract and takes ownership.
    unsafe { *ret = value };
    0
}

/// # Safety
/// `s` and `sep` must be readable NUL-terminated strings; each non-null output
/// must be writable for one owned pointer.
pub unsafe fn rs_split_pair(
    s: *const c_char,
    sep: *const c_char,
    ret_first: *mut *mut c_char,
    ret_second: *mut *mut c_char,
) -> i32 {
    // SAFETY: non-null `sep` is a readable C string by the function contract.
    if s.is_null() || sep.is_null() || unsafe { *sep } == 0 {
        return Errno::EINVAL.to_neg_errno();
    }
    // SAFETY: `s` and `sep` are readable C strings by the function contract.
    let bytes = unsafe { CStr::from_ptr(s) }.to_bytes();
    // SAFETY: `s` and `sep` are readable C strings by the function contract.
    let separator = unsafe { CStr::from_ptr(sep) }.to_bytes();
    let Some(position) = bytes
        .windows(separator.len())
        .position(|part| part == separator)
    else {
        return Errno::EINVAL.to_neg_errno();
    };

    let first = if ret_first.is_null() {
        std::ptr::null_mut()
    } else {
        let value = alloc_c_string_from_bytes(&bytes[..position]);
        if value.is_null() {
            return Errno::ENOMEM.to_neg_errno();
        }
        value
    };
    let second = if ret_second.is_null() {
        std::ptr::null_mut()
    } else {
        let value = alloc_c_string_from_bytes(&bytes[position + separator.len()..]);
        if value.is_null() {
            if !first.is_null() {
                // SAFETY: first has not been published and remains uniquely owned.
                unsafe { free(first.cast::<c_void>()) };
            }
            return Errno::ENOMEM.to_neg_errno();
        }
        value
    };
    // SAFETY: each non-null output pointer is writable by the function contract.
    if !ret_first.is_null() {
        unsafe { *ret_first = first };
    }
    // SAFETY: each non-null output pointer is writable by the function contract.
    if !ret_second.is_null() {
        unsafe { *ret_second = second };
    }
    0
}
