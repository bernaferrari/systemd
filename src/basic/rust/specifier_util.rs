// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: scope=basic.specifier-util; authority=src/shared/specifier.c,src/shared/specifier.h,src/shared/efi-loader.c,src/shared/efi-loader.h
//
// Specifier escaping and EFI loader entry validation utilities.

use std::ffi::{CStr, c_char, c_void};
use std::mem::size_of;
use std::ptr;

use crate::ffi::{Errno, free, malloc};

const NAME_MAX: usize = 255;

// ── Specifier escaping ───────────────────────────────────────────────────

/// Allocate a C-owned copy of `input` with every percent byte doubled.
///
/// NULL is reserved for allocation/overflow failure so callers can preserve
/// C's `strreplace()` error convention.
fn allocate_specifier_escape(input: &[u8]) -> *mut c_char {
    let percent_count = input.iter().filter(|byte| **byte == b'%').count();
    let Some(allocation_size) = input
        .len()
        .checked_add(percent_count)
        .and_then(|length| length.checked_add(1))
    else {
        return ptr::null_mut();
    };

    let output = malloc(allocation_size).cast::<u8>();
    if output.is_null() {
        return ptr::null_mut();
    }

    let mut output_index = 0;
    // SAFETY: `allocation_size` reserves one byte for each input byte, one
    // additional byte for each percent, and the final NUL terminator.
    unsafe {
        for &byte in input {
            *output.add(output_index) = byte;
            output_index += 1;
            if byte == b'%' {
                *output.add(output_index) = byte;
                output_index += 1;
            }
        }
        *output.add(output_index) = 0;
    }

    output.cast::<c_char>()
}

/// Release a partially initialized C-allocator string vector.
///
/// # Safety
///
/// `vector` must be a live C allocation with exactly `initialized` owned
/// C-allocator strings stored at its leading entries.
unsafe fn free_escaped_strv(vector: *mut *mut c_char, initialized: usize) {
    for index in 0..initialized {
        // SAFETY: guaranteed by this helper's contract.
        unsafe { free((*vector.add(index)).cast::<c_void>()) };
    }
    // SAFETY: guaranteed by this helper's contract.
    unsafe { free(vector.cast::<c_void>()) };
}

// ── EFI loader entry validation ──────────────────────────────────────────

/// Faithful raw-byte port of filename_is_valid() followed by in_charset().
fn efi_loader_entry_name_valid_bytes(bytes: &[u8]) -> bool {
    if bytes.is_empty()
        || bytes == b"."
        || bytes == b".."
        || bytes.len() > NAME_MAX
        || bytes.contains(&b'/')
    {
        return false;
    }

    bytes.iter().all(|byte| {
        byte.is_ascii_alphanumeric() || matches!(*byte, b'+' | b'-' | b'_' | b'.' | b'@')
    })
}

// ── C ABI ─────────────────────────────────────────────────────────────────

/// C ABI facade for specifier_escape().
///
/// The returned non-NULL pointer is a C-allocator allocation owned by the
/// caller and releasable with free(3). NULL input and allocation failure both
/// return NULL, matching C's strreplace()-based authority.
///
/// # Safety
///
/// A non-NULL `string` must point to a live NUL-terminated C string for the
/// duration of the call. Its raw non-NUL bytes are copied without UTF-8
/// interpretation.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_specifier_escape(string: *const c_char) -> *mut c_char {
    if string.is_null() {
        return ptr::null_mut();
    }

    // SAFETY: required by this entry point's C-string contract.
    allocate_specifier_escape(unsafe { CStr::from_ptr(string) }.to_bytes())
}

/// C ABI facade for specifier_escape_strv().
///
/// The input strv is borrowed and never modified or consumed. On success, a
/// non-empty result is a newly allocated NULL-terminated strv whose strings
/// and vector base are all C-allocator allocations; the caller owns it and
/// must release it with strv_free(). An empty input (including NULL) publishes
/// NULL. On allocation failure, `*ret` is not modified.
///
/// # Safety
///
/// A non-NULL `l` must be a live NULL-terminated vector of live
/// NUL-terminated C strings. `ret` must be writable for one `char **`.
/// C asserts `ret` is non-NULL; this facade returns `-EINVAL` instead for that
/// precondition violation.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_specifier_escape_strv(
    l: *mut *mut c_char,
    ret: *mut *mut *mut c_char,
) -> i32 {
    if ret.is_null() {
        return Errno::EINVAL.to_neg_errno();
    }

    if l.is_null()
        // SAFETY: `l` is non-NULL on this branch and points to the strv's first slot.
        || unsafe { (*l).is_null() }
    {
        // SAFETY: `ret` is non-NULL and writable by this entry point's contract.
        unsafe { *ret = ptr::null_mut() };
        return 0;
    }

    let mut count = 0usize;
    loop {
        // SAFETY: the entry point contract requires a NULL-terminated input strv.
        if unsafe { (*l.add(count)).is_null() } {
            break;
        }
        let Some(next_count) = count.checked_add(1) else {
            return Errno::ENOMEM.to_neg_errno();
        };
        count = next_count;
    }

    let Some(vector_size) = count
        .checked_add(1)
        .and_then(|slots| slots.checked_mul(size_of::<*mut c_char>()))
    else {
        return Errno::ENOMEM.to_neg_errno();
    };
    let vector = malloc(vector_size).cast::<*mut c_char>();
    if vector.is_null() {
        return Errno::ENOMEM.to_neg_errno();
    }

    let mut initialized = 0usize;
    for index in 0..count {
        // SAFETY: `index` is within the input vector's non-NULL prefix.
        let source = unsafe { *l.add(index) };
        // SAFETY: every non-NULL input entry is a live C string by contract.
        let escaped = allocate_specifier_escape(unsafe { CStr::from_ptr(source) }.to_bytes());
        if escaped.is_null() {
            // SAFETY: vector and its initialized prefix are exclusively owned here.
            unsafe { free_escaped_strv(vector, initialized) };
            return Errno::ENOMEM.to_neg_errno();
        }

        // SAFETY: vector_size reserves count entries plus this final NULL slot.
        unsafe { *vector.add(index) = escaped };
        initialized += 1;
    }

    // SAFETY: both writes are valid and output publication happens only after
    // the vector has been fully initialized, matching specifier_escape_strv().
    unsafe {
        *vector.add(count) = ptr::null_mut();
        *ret = vector;
    }
    0
}

/// C ABI facade for efi_loader_entry_name_valid().
///
/// # Safety
///
/// A non-NULL `s` must point to a live NUL-terminated C string for the
/// duration of the call. NULL returns false, matching filename_is_valid().
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_efi_loader_entry_name_valid(s: *const c_char) -> bool {
    if s.is_null() {
        return false;
    }

    // SAFETY: required by this entry point's C-string contract.
    efi_loader_entry_name_valid_bytes(unsafe { CStr::from_ptr(s) }.to_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn specifier_escape_preserves_non_utf8_bytes() {
        let escaped = allocate_specifier_escape(b"a%\xff%");
        assert!(!escaped.is_null());
        // SAFETY: the successful helper result is a live C string until freed below.
        unsafe {
            assert_eq!(CStr::from_ptr(escaped).to_bytes(), b"a%%\xff%%");
            free(escaped.cast::<c_void>());
        }
    }

    #[test]
    fn efi_loader_entry_name_validation_matches_filename_rules() {
        assert!(efi_loader_entry_name_valid_bytes(b".hidden"));
        assert!(efi_loader_entry_name_valid_bytes(&[b'a'; NAME_MAX]));
        assert!(!efi_loader_entry_name_valid_bytes(b""));
        assert!(!efi_loader_entry_name_valid_bytes(b"."));
        assert!(!efi_loader_entry_name_valid_bytes(b".."));
        assert!(!efi_loader_entry_name_valid_bytes(b"entry/name"));
        assert!(!efi_loader_entry_name_valid_bytes(b"entry\xff"));
        assert!(!efi_loader_entry_name_valid_bytes(&[b'a'; NAME_MAX + 1]));
    }
}
