// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/basic/strv.c
//
// Allocating strv transforms with C-owned results and explicit rollback rules.

use std::ffi::{CStr, c_void};

use libc::c_char;

use crate::ffi::{Errno, SIZE_MAX, calloc, free, reallocarray, strdup};

use super::{rs_strv_copy_n, rs_strv_length, strv_iter};

/// Safe byte-prefix policy shared by the `strv_filter_prefix()` ABI shell.
#[inline]
fn cstr_has_prefix(entry: &CStr, prefix: &[u8]) -> bool {
    entry.to_bytes().starts_with(prefix)
}

/// C ABI mirror of `strv_filter_prefix()` from `strv.c`.
///
/// # Safety
///
/// `l` is either null or a readable NULL-terminated array of readable
/// NUL-terminated strings. `prefix` is either null or a readable
/// NUL-terminated string. All inputs are borrowed for this call. A non-null
/// result and all of its entries are fresh C-allocator allocations owned by
/// the caller and released with `strv_free()`/`free()`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_strv_filter_prefix(
    l: *const *mut c_char,
    prefix: *const c_char,
) -> *mut *mut c_char {
    let prefix = if prefix.is_null() {
        None
    } else {
        // SAFETY: the entry-point contract guarantees the borrowed C string.
        Some(unsafe { CStr::from_ptr(prefix) })
    };

    // `isempty(prefix)` in C treats NULL and "" alike and delegates to
    // strv_copy(), including its non-null empty-vector allocation behavior.
    let Some(prefix) = prefix.filter(|prefix| !prefix.to_bytes().is_empty()) else {
        // SAFETY: the entry-point contract is the one required by copy_n.
        return unsafe { rs_strv_copy_n(l.cast::<*const c_char>(), SIZE_MAX) };
    };
    if l.is_null() {
        return std::ptr::null_mut();
    }

    let prefix = prefix.to_bytes();
    let mut count = 0usize;
    // SAFETY: the entry-point contract guarantees the NULL-terminated vector.
    for entry in unsafe { strv_iter(l.cast::<*const c_char>()) } {
        if cstr_has_prefix(entry, prefix) {
            let Some(next) = count.checked_add(1) else {
                return std::ptr::null_mut();
            };
            count = next;
        }
    }
    if count == 0 {
        return std::ptr::null_mut();
    }
    let Some(slots) = count.checked_add(1) else {
        return std::ptr::null_mut();
    };
    let copied = calloc(slots, std::mem::size_of::<*mut c_char>()).cast::<*mut c_char>();
    if copied.is_null() {
        return std::ptr::null_mut();
    }

    let mut copied_count = 0usize;
    // SAFETY: the same input-vector contract applies to this second borrowed
    // pass. `copied` has `slots` zeroed writable entries.
    for entry in unsafe { strv_iter(l.cast::<*const c_char>()) } {
        if !cstr_has_prefix(entry, prefix) {
            continue;
        }
        // SAFETY: entry is a valid C string borrowed from the input vector.
        let duplicate = unsafe { strdup(entry.as_ptr()) };
        if duplicate.is_null() {
            // SAFETY: every earlier slot is a C allocation owned by this new
            // result; freeing them leaves the input and caller state untouched.
            unsafe {
                for index in 0..copied_count {
                    free((*copied.add(index)).cast::<c_void>());
                }
                free(copied.cast::<c_void>());
            }
            return std::ptr::null_mut();
        }
        // SAFETY: copied_count remains below count, hence below `slots - 1`.
        unsafe { *copied.add(copied_count) = duplicate };
        copied_count += 1;
    }
    // SAFETY: `copied_count <= count`, so this is the reserved sentinel slot
    // in the `count + 1` element zeroed allocation.
    unsafe { *copied.add(copied_count) = std::ptr::null_mut() };
    copied
}

/// Return whether a C strv currently contains `needle`, using only safe CStr
/// equality once the bounded raw-pointer adapter has borrowed each entry.
fn strv_contains_cstr(l: *const *mut c_char, needle: &CStr) -> bool {
    if l.is_null() {
        return false;
    }
    // SAFETY: callers provide a live NULL-terminated C string vector for this
    // short-lived borrow. The iterator never owns or mutates either vector.
    unsafe { strv_iter(l.cast::<*const c_char>()) }.any(|entry| entry == needle)
}

/// C ABI mirror of `strv_extend_strv()` from `strv.c`.
///
/// # Safety
///
/// `a` points to writable storage for a C-owned NULL-terminated vector pointer
/// (which may itself be null). `b` is either null or a readable
/// NULL-terminated vector of readable strings. Existing `*a` entries must be
/// C-allocator allocations. The source vector storage `b` must not alias the
/// destination allocation `*a`: `reallocarray()` may move and free that
/// allocation before iteration over `b` begins. On failure, `*a` retains its
/// original entries and the temporary appended suffix is freed, matching C's
/// content-atomic rollback rule (the backing pointer may have been realloc'ed).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_strv_extend_strv(
    a: *mut *mut *mut c_char,
    b: *const *mut c_char,
    filter_duplicates: bool,
) -> i32 {
    if a.is_null() {
        return Errno::EINVAL.to_neg_errno();
    }
    // SAFETY: the entry-point contract guarantees `a` is writable after the
    // explicit null check. A null b is an empty vector in C.
    let q = unsafe { rs_strv_length(b.cast::<*const c_char>()) };
    if q == 0 {
        return 0;
    }
    // SAFETY: `*a` is either null or a valid vector per the entry contract.
    let p = unsafe { rs_strv_length((*a).cast::<*const c_char>()) };
    if p >= SIZE_MAX - q {
        return Errno::ENOMEM.to_neg_errno();
    }
    let slots = p + q + 1;
    // SAFETY: `*a` is C-allocator storage or null and `slots` cannot overflow
    // due to the preceding C-equivalent guard. The source vector is disjoint
    // from this allocation by the entry-point contract.
    let extended = unsafe {
        reallocarray(
            (*a).cast::<c_void>(),
            crate::basic_validators::rs_GREEDY_ALLOC_ROUND_UP(slots),
            std::mem::size_of::<*mut c_char>(),
        )
    }
    .cast::<*mut c_char>();
    if extended.is_null() {
        return Errno::ENOMEM.to_neg_errno();
    }
    // Publish the possibly moved allocation before copying, exactly like C.
    // SAFETY: extended has room for the prefix plus the terminating sentinel.
    unsafe {
        *extended.add(p) = std::ptr::null_mut();
        *a = extended;
    }

    let mut added = 0usize;
    // SAFETY: b remains a readable borrowed vector for this call because the
    // contract excludes aliasing with the realloc'ed destination storage.
    for entry in unsafe { strv_iter(b.cast::<*const c_char>()) } {
        if filter_duplicates && strv_contains_cstr(extended.cast::<*mut c_char>(), entry) {
            continue;
        }
        // SAFETY: entry is a live borrowed C string.
        let duplicate = unsafe { strdup(entry.as_ptr()) };
        if duplicate.is_null() {
            // C rolls back only the newly-created suffix, retaining the
            // existing prefix and the realloc'ed array pointer.
            // SAFETY: exactly `added` suffix entries were initialized by this
            // loop; each is a distinct C allocation, and slot `p` is writable.
            unsafe {
                for index in 0..added {
                    free((*extended.add(p + index)).cast::<c_void>());
                }
                *extended.add(p) = std::ptr::null_mut();
            }
            return Errno::ENOMEM.to_neg_errno();
        }
        // SAFETY: at most q entries are appended into q reserved slots.
        unsafe {
            *extended.add(p + added) = duplicate;
            added += 1;
            *extended.add(p + added) = std::ptr::null_mut();
        }
    }
    added as i32
}
