// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/basic/strv.c
//
// C ABI boundary for the strv helpers that delegate matching to libc or
// replace C-owned strings with byte-escaped copies.

use std::ffi::{CStr, c_void};

use libc::c_char;

use crate::escape::{malloc_c_string, try_strcpy_backslash_escaped};
use crate::ffi::{SIZE_MAX, fnmatch, free};

/// Run libc's platform fnmatch implementation for two already-validated C
/// strings. systemd delegates syntax and flags to libc, so a hand-rolled
/// globber would be less faithful across libc versions and locales.
fn cstr_fnmatch(pattern: &CStr, subject: &CStr, flags: i32) -> bool {
    // SAFETY: `CStr` guarantees NUL-terminated input for the duration of this
    // call. `flags` is passed unchanged. fnmatch errors map to false exactly
    // as `strv_fnmatch_full()` does in C.
    unsafe { fnmatch(pattern.as_ptr(), subject.as_ptr(), flags) == 0 }
}

/// Safe matching core: preserve array order and return the first match.
fn first_fnmatch<'a>(
    mut patterns: impl Iterator<Item = &'a CStr>,
    subject: &CStr,
    flags: i32,
) -> Option<usize> {
    patterns.position(|pattern| cstr_fnmatch(pattern, subject, flags))
}

/// Produce one replacement entry using the reviewed byte-oriented shell
/// escape core. The result is a fresh C-allocator allocation so it can replace
/// a string owned by the caller's C strv.
fn escape_strv_entry(entry: &CStr, bad: &CStr) -> Option<*mut c_char> {
    try_strcpy_backslash_escaped(entry.to_bytes(), bad.to_bytes())
        .ok()
        .and_then(|escaped| {
            let replacement = malloc_c_string(&escaped);
            (!replacement.is_null()).then_some(replacement)
        })
}

/// C ABI mirror of `strv_fnmatch_full()` from `strv.c`.
///
/// # Safety
///
/// `patterns` is either null or a readable NULL-terminated array of readable
/// NUL-terminated strings. `s` is a readable NUL-terminated string. When
/// non-null, `ret_matched_pos` is writable for one `size_t`. All inputs are
/// borrowed only for this call. The first matching pattern wins and every
/// `fnmatch(3)` error is equivalent to `FNM_NOMATCH`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_strv_fnmatch_full(
    patterns: *const *mut c_char,
    s: *const c_char,
    flags: i32,
    ret_matched_pos: *mut usize,
) -> bool {
    let Some(subject) = (!s.is_null()).then(|| {
        // SAFETY: the entry-point contract guarantees a readable C string
        // after this explicit null check.
        unsafe { CStr::from_ptr(s) }
    }) else {
        // C asserts this precondition. A Rust C ABI must not unwind or
        // dereference null, so reject it and return the normal non-match
        // sentinel when an output was supplied.
        if !ret_matched_pos.is_null() {
            // SAFETY: covered by the entry-point contract.
            unsafe { *ret_matched_pos = SIZE_MAX };
        }
        return false;
    };

    let matched = if patterns.is_null() {
        None
    } else {
        // The pointer-array boundary is intentionally kept here. The safe
        // matching core below borrows only CStr values for this call.
        let mut cursor = patterns;
        first_fnmatch(
            std::iter::from_fn(|| {
                // SAFETY: the entry-point contract guarantees the next slot
                // and each non-null entry are readable. Advancing only after
                // a non-null slot avoids reading beyond the sentinel.
                let entry = unsafe { *cursor };
                if entry.is_null() {
                    None
                } else {
                    // SAFETY: the current slot was readable and non-null; the
                    // vector contract provides the next slot and a valid C
                    // string at `entry`.
                    cursor = unsafe { cursor.add(1) };
                    // SAFETY: `entry` was read from the live vector and was
                    // checked non-null immediately above.
                    Some(unsafe { CStr::from_ptr(entry) })
                }
            }),
            subject,
            flags,
        )
    };

    if let Some(position) = matched {
        if !ret_matched_pos.is_null() {
            // SAFETY: covered by the entry-point contract.
            unsafe { *ret_matched_pos = position };
        }
        true
    } else {
        if !ret_matched_pos.is_null() {
            // SAFETY: covered by the entry-point contract.
            unsafe { *ret_matched_pos = SIZE_MAX };
        }
        false
    }
}

/// C ABI mirror of `strv_shell_escape()` from `strv.c`.
///
/// # Safety
///
/// `l` is either null or a writable NULL-terminated array whose non-null
/// entries are individually-owned C-allocator strings. `bad` is a readable
/// NUL-terminated string whenever `l` has an entry. `bad` must not point into
/// any entry allocation: entries are freed one by one, so such an alias could
/// dangle before a later replacement reads it. Entries are replaced in place.
/// On allocation failure an already-replaced prefix is retained, matching C's
/// documented no-rollback behavior.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_strv_shell_escape(
    l: *mut *mut c_char,
    bad: *const c_char,
) -> *mut *mut c_char {
    if l.is_null() {
        return std::ptr::null_mut();
    }

    let mut cursor = l;
    loop {
        // SAFETY: the entry-point contract guarantees each slot through the
        // terminating null is readable and writable.
        let entry = unsafe { *cursor };
        if entry.is_null() {
            // Preserve C's empty-array behavior: bad is not inspected when
            // there is no entry to escape.
            return l;
        }
        if bad.is_null() {
            // C asserts this only when an entry is present. Refuse the invalid
            // ABI input without freeing or replacing that entry.
            return std::ptr::null_mut();
        }
        // SAFETY: the entry-point contract guarantees entry and bad are C
        // strings and do not have the forbidden ownership alias. The borrows
        // end before the old entry allocation is released.
        let replacement = unsafe {
            let entry = CStr::from_ptr(entry);
            let bad = CStr::from_ptr(bad);
            escape_strv_entry(entry, bad)
        };
        let Some(replacement) = replacement else {
            return std::ptr::null_mut();
        };

        // SAFETY: each entry is an owned C allocation and the replacement uses
        // the same allocator. One-at-a-time replacement preserves no-rollback.
        unsafe {
            free(entry.cast::<c_void>());
            *cursor = replacement;
            cursor = cursor.add(1);
        }
    }
}
