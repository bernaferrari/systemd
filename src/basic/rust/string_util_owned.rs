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

/// Optional C ABI output pointer. Its public caller establishes writability;
/// this adapter is the sole ownership-publication boundary for copied strings.
#[derive(Clone, Copy)]
struct COutString(*mut *mut c_char);

impl COutString {
    fn from_contract(ptr: *mut *mut c_char) -> Self {
        Self(ptr)
    }

    fn is_requested(self) -> bool {
        !self.0.is_null()
    }

    fn store(self, value: *mut c_char) {
        if !self.0.is_null() {
            // SAFETY: a non-null pointer is writable under the enclosing C ABI contract.
            unsafe { *self.0 = value };
        }
    }
}

/// A C ABI slot with the unique malloc-compatible ownership required by
/// `free()`. Replacement is intentionally atomic at the ownership level:
/// callers allocate a complete replacement before releasing the old value.
struct OwnedCStringSlot(*mut *mut c_char);

impl OwnedCStringSlot {
    fn from_contract(ptr: *mut *mut c_char) -> Self {
        debug_assert!(!ptr.is_null());
        Self(ptr)
    }

    fn current(&self) -> *mut c_char {
        // SAFETY: construction requires a writable pointer-sized C ABI slot.
        unsafe { *self.0 }
    }

    fn replace(&self, replacement: *mut c_char) {
        // SAFETY: the slot uniquely owns its old malloc-compatible value; this
        // releases it before publishing `replacement` exactly once.
        unsafe {
            let old = *self.0;
            if !old.is_null() {
                free(old.cast::<c_void>());
            }
            *self.0 = replacement;
        }
    }
}

fn free_unpublished_c_string(value: *mut c_char) {
    if !value.is_null() {
        // SAFETY: this helper only receives allocations made by this module
        // before they have been published to a caller-owned output slot.
        unsafe { free(value.cast::<c_void>()) };
    }
}

pub(crate) fn alloc_empty_c_string() -> *mut c_char {
    alloc_c_string_from_bytes(&[])
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
    let output = COutString::from_contract(ret);
    if src.is_null() {
        output.store(std::ptr::null_mut());
        return 0;
    }
    if !output.is_requested() {
        return 1;
    }
    // SAFETY: non-null `src` is a readable C string by the function contract.
    let copy = alloc_c_string_from_bytes(unsafe { CStr::from_ptr(src) }.to_bytes());
    if copy.is_null() {
        return Errno::ENOMEM.to_neg_errno();
    }
    output.store(copy);
    1
}

/// # Safety
/// `p` must point to null or a unique malloc-compatible string; `s` must be
/// null or a readable NUL-terminated string.
pub unsafe fn rs_free_and_strdup(p: *mut *mut c_char, s: *const c_char) -> i32 {
    if p.is_null() {
        return Errno::EINVAL.to_neg_errno();
    }

    let slot = OwnedCStringSlot::from_contract(p);
    let old = slot.current();
    let unchanged = match (old.is_null(), s.is_null()) {
        (true, true) => true,
        (true, false) | (false, true) => false,
        // SAFETY: both non-null pointers are live C strings by this API's contract.
        (false, false) => unsafe { CStr::from_ptr(old) == CStr::from_ptr(s) },
    };
    if unchanged {
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
    slot.replace(replacement);
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
    let slot = OwnedCStringSlot::from_contract(p);
    let old = slot.current();
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
    slot.replace(replacement);
    1
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
    let output = COutString::from_contract(ret);
    if (s.is_null() && n != 0) || !(0..=2).contains(&mode) {
        return Errno::EINVAL.to_neg_errno();
    }
    if n == 0 {
        if mode == MAKE_CSTRING_REQUIRE_TRAILING_NUL {
            return Errno::EINVAL.to_neg_errno();
        }
        if !output.is_requested() {
            return 0;
        }
        // SAFETY: calloc returns null or a unique zeroed byte.
        let value = calloc(1, 1).cast::<c_char>();
        if value.is_null() {
            return Errno::ENOMEM.to_neg_errno();
        }
        output.store(value);
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
    if !output.is_requested() {
        return 0;
    }
    let value = alloc_c_string_from_bytes(&bytes[..actual_n]);
    if value.is_null() {
        return Errno::ENOMEM.to_neg_errno();
    }
    output.store(value);
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
    let first_output = COutString::from_contract(ret_first);
    let second_output = COutString::from_contract(ret_second);
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

    let first = if !first_output.is_requested() {
        std::ptr::null_mut()
    } else {
        let value = alloc_c_string_from_bytes(&bytes[..position]);
        if value.is_null() {
            return Errno::ENOMEM.to_neg_errno();
        }
        value
    };
    let second = if !second_output.is_requested() {
        std::ptr::null_mut()
    } else {
        let value = alloc_c_string_from_bytes(&bytes[position + separator.len()..]);
        if value.is_null() {
            free_unpublished_c_string(first);
            return Errno::ENOMEM.to_neg_errno();
        }
        value
    };
    first_output.store(first);
    second_output.store(second);
    0
}
