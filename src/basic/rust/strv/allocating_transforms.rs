// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: scope=basic.strv; authority=src/basic/strv.c,src/basic/strv.h,src/fundamental/strv.h
//
// Allocating strv transforms with C-owned results and explicit rollback rules.

// Centralized unsafe expression boundary for this module.
macro_rules! unsafe_ffi {
    ($expression:expr) => {{
        // SAFETY: the enclosing helper documents and validates this operation.
        unsafe { $expression }
    }};
}
use std::ffi::{CStr, c_void};

use libc::c_char;

use crate::ffi::{Errno, SIZE_MAX, free, strdup};

use super::{CStrvAllocation, StrvSlot, rs_strv_copy_n, rs_strv_length, strv_iter};

/// Borrow a NULL-terminated C string vector for one local iteration.
///
/// Each invoking ABI adapter documents that the vector and entries are live
/// and readable through the final NULL pointer for the iterator's lifetime.
macro_rules! borrowed_strv {
    ($vector:expr) => {{
        // SAFETY: upheld by the invoking C ABI adapter's strv contract.
        unsafe { strv_iter(($vector).cast::<*const c_char>()) }
    }};
}

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
        Some(unsafe_ffi!(CStr::from_ptr(prefix)))
    };

    // `isempty(prefix)` in C treats NULL and "" alike and delegates to
    // strv_copy(), including its non-null empty-vector allocation behavior.
    let Some(prefix) = prefix.filter(|prefix| !prefix.to_bytes().is_empty()) else {
        // SAFETY: the entry-point contract is the one required by copy_n.
        return unsafe_ffi!(rs_strv_copy_n(l, SIZE_MAX));
    };
    if l.is_null() {
        return std::ptr::null_mut();
    }

    let prefix = prefix.to_bytes();
    let mut count = 0usize;
    // SAFETY: the entry-point contract guarantees the NULL-terminated vector.
    for entry in borrowed_strv!(l) {
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
    let Some(mut copied) = CStrvAllocation::malloc(slots) else {
        return std::ptr::null_mut();
    };

    // SAFETY: the same input-vector contract applies to this second borrowed
    // pass. `copied` has a reserved NULL terminator slot.
    for entry in borrowed_strv!(l) {
        if !cstr_has_prefix(entry, prefix) {
            continue;
        }
        // SAFETY: entry is a valid C string borrowed from the input vector.
        let duplicate = unsafe_ffi!(strdup(entry.as_ptr()));
        if duplicate.is_null() {
            // The allocation owns every prior duplicate and rolls them back
            // before freeing its C-allocator backing storage.
            copied.free_entries_and_storage();
            return std::ptr::null_mut();
        }
        copied.push(duplicate);
    }
    copied.into_raw()
}

/// Return whether a C strv currently contains `needle`, using only safe CStr
/// equality once the bounded raw-pointer adapter has borrowed each entry.
fn strv_contains_cstr(l: *const *mut c_char, needle: &CStr) -> bool {
    if l.is_null() {
        return false;
    }
    // SAFETY: callers provide a live NULL-terminated C string vector for this
    // short-lived borrow. The iterator never owns or mutates either vector.
    borrowed_strv!(l).any(|entry| entry == needle)
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
    let q = unsafe_ffi!(rs_strv_length(b));
    if q == 0 {
        return 0;
    }
    // SAFETY: `a` was checked above, and its entry-point contract guarantees
    // that `*a` is null or a caller-owned NULL-terminated C vector.
    let mut destination = unsafe_ffi!(StrvSlot::from_raw(a));
    let p = destination.len();
    if p >= SIZE_MAX - q {
        return Errno::ENOMEM.to_neg_errno();
    }
    let slots = p + q + 1;
    let Some(extended) = destination.grow_for(slots) else {
        return Errno::ENOMEM.to_neg_errno();
    };
    // Publish the possibly moved allocation before copying, exactly like C.
    // SAFETY: extended has room for the prefix plus the terminating sentinel.
    unsafe_ffi!(*extended.add(p) = std::ptr::null_mut());

    let mut added = 0usize;
    // SAFETY: b remains a readable borrowed vector for this call because the
    // contract excludes aliasing with the realloc'ed destination storage.
    for entry in borrowed_strv!(b) {
        if filter_duplicates && strv_contains_cstr(extended.cast::<*mut c_char>(), entry) {
            continue;
        }
        // SAFETY: entry is a live borrowed C string.
        let duplicate = unsafe_ffi!(strdup(entry.as_ptr()));
        if duplicate.is_null() {
            // C rolls back only the newly-created suffix, retaining the
            // existing prefix and the realloc'ed array pointer.
            // SAFETY: exactly `added` suffix entries were initialized by this
            // loop; each is a distinct C allocation, and slot `p` is writable.
            unsafe_ffi!({
                for index in 0..added {
                    free((*extended.add(p + index)).cast::<c_void>());
                }
                *extended.add(p) = std::ptr::null_mut();
            });
            return Errno::ENOMEM.to_neg_errno();
        }
        // SAFETY: at most q entries are appended into q reserved slots.
        unsafe_ffi!({
            *extended.add(p + added) = duplicate;
            added += 1;
            *extended.add(p + added) = std::ptr::null_mut();
        })
    }
    added as i32
}
