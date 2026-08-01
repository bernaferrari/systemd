// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/basic/string-util.c
//
// Prefix/suffix comparisons and allocated or in-place replacement. Allocation
// flows downward through `owned`; this module has no facade dependency.
//
// SAFETY: raw reads and writes only materialize the pointer extents stated in
// each public function's Safety contract. Owned results are created solely by
// the lower `owned` domain or the explicitly documented malloc site.

// Centralized unsafe expression boundary for this module.
macro_rules! unsafe_ffi {
    ($expression:expr) => {{
        // SAFETY: the enclosing helper documents and validates this operation.
        unsafe { $expression }
    }};
}
use std::ffi::CStr;
use std::ptr;

use libc::c_char;

use crate::ffi::SIZE_MAX;
use crate::string_util::owned::{alloc_c_string_from_bytes, alloc_empty_c_string};

/// Borrow a NUL-terminated C string only for the duration of a safe core
/// operation. This keeps all pointer traversal in one audited adapter while
/// callers retain their existing null semantics.
fn with_c_string<T>(value: *const c_char, operation: impl FnOnce(&[u8]) -> T) -> Option<T> {
    if value.is_null() {
        return None;
    }
    // SAFETY: each caller upholds the documented readable NUL-terminated C
    // string contract for this synchronous closure.
    Some(operation(unsafe_ffi!(CStr::from_ptr(value)).to_bytes()))
}

fn with_two_c_strings<T>(
    first: *const c_char,
    second: *const c_char,
    operation: impl FnOnce(&[u8], &[u8]) -> T,
) -> Option<T> {
    with_c_string(first, |first| {
        with_c_string(second, |second| operation(first, second))
    })
    .flatten()
}

fn with_three_c_strings<T>(
    first: *const c_char,
    second: *const c_char,
    third: *const c_char,
    operation: impl FnOnce(&[u8], &[u8], &[u8]) -> T,
) -> Option<T> {
    with_c_string(first, |first| {
        with_c_string(second, |second| {
            with_c_string(third, |third| operation(first, second, third))
        })
    })
    .flatten()
    .flatten()
}

/// # Safety
/// `a` and `b` must be readable NUL-terminated strings when non-null.
pub unsafe fn rs_str_common_prefix(a: *const c_char, b: *const c_char) -> usize {
    with_two_c_strings(a, b, |a, b| {
        for (index, (&left, &right)) in a.iter().zip(b).enumerate() {
            if left != right {
                return index;
            }
        }
        if a.len() == b.len() {
            SIZE_MAX
        } else {
            a.len().min(b.len())
        }
    })
    .unwrap_or(0)
}

/// # Safety
/// `string` and `accept` must be readable NUL-terminated strings when non-null.
pub unsafe fn rs_strspn_from_end(string: *const c_char, accept: *const c_char) -> usize {
    with_two_c_strings(string, accept, |string, accept| {
        string
            .iter()
            .rev()
            .take_while(|byte| accept.contains(byte))
            .count()
    })
    .unwrap_or(0)
}

/// # Safety
/// `s1` and `s2` must be null or readable NUL-terminated strings. `ok` must
/// be null or a readable NUL-terminated string; null selects C's `WHITESPACE`
/// default (space, tab, newline, and carriage return).
pub unsafe fn rs_streq_skip_trailing_chars(
    s1: *const c_char,
    s2: *const c_char,
    ok: *const c_char,
) -> bool {
    match (s1.is_null(), s2.is_null()) {
        (true, true) => return true,
        (true, false) | (false, true) => return false,
        (false, false) => {}
    }
    with_two_c_strings(s1, s2, |first, second| {
        let compare_with = |accepted: &[u8]| {
            let mut index = 0;
            while index < first.len() && index < second.len() && first[index] == second[index] {
                index += 1;
            }
            first[index..].iter().all(|byte| accepted.contains(byte))
                && second[index..].iter().all(|byte| accepted.contains(byte))
        };
        if ok.is_null() {
            compare_with(b" \t\n\r")
        } else {
            with_c_string(ok, compare_with).unwrap_or(false)
        }
    })
    .unwrap_or(false)
}

/// # Safety
/// `a` and `accept` must be readable NUL-terminated strings when non-null.
pub unsafe fn rs_strdupspn(a: *const c_char, accept: *const c_char) -> *mut c_char {
    if a.is_null() || accept.is_null() {
        return alloc_empty_c_string();
    }
    with_two_c_strings(a, accept, |bytes, accept| {
        if bytes.is_empty() || accept.is_empty() {
            return alloc_empty_c_string();
        }
        let length = bytes
            .iter()
            .take_while(|byte| accept.contains(byte))
            .count();
        alloc_c_string_from_bytes(&bytes[..length])
    })
    .unwrap_or_else(alloc_empty_c_string)
}

/// # Safety
/// `a` and `reject` must be readable NUL-terminated strings when non-null.
pub unsafe fn rs_strdupcspn(a: *const c_char, reject: *const c_char) -> *mut c_char {
    if a.is_null() {
        return alloc_empty_c_string();
    }
    with_c_string(a, |bytes| {
        if bytes.is_empty() {
            return alloc_empty_c_string();
        }
        let length = if reject.is_null() {
            bytes.len()
        } else {
            with_c_string(reject, |reject| {
                if reject.is_empty() {
                    bytes.len()
                } else {
                    bytes
                        .iter()
                        .take_while(|byte| !reject.contains(byte))
                        .count()
                }
            })
            .unwrap_or(0)
        };
        alloc_c_string_from_bytes(&bytes[..length])
    })
    .unwrap_or_else(alloc_empty_c_string)
}

/// # Safety
/// `string` must be null or a writable NUL-terminated string.
pub unsafe fn rs_string_replace_char(
    string: *mut c_char,
    old_char: c_char,
    new_char: c_char,
) -> *mut c_char {
    if string.is_null() || old_char == 0 || new_char == 0 || old_char == new_char {
        return std::ptr::null_mut();
    }
    let Some(length) = with_c_string(string.cast_const(), <[u8]>::len) else {
        return ptr::null_mut();
    };
    // SAFETY: `string` is writable for all visible bytes by the contract.
    let bytes = unsafe_ffi!(std::slice::from_raw_parts_mut(string.cast::<u8>(), length));
    for byte in bytes {
        if *byte == old_char as u8 {
            *byte = new_char as u8;
        }
    }
    string
}

fn repeated_bytes(bytes: &[u8], n: usize) -> Option<Vec<u8>> {
    let Some(allocation_size) = bytes
        .len()
        .checked_mul(n)
        .and_then(|total| total.checked_add(1))
    else {
        return None;
    };
    let output_len = allocation_size - 1;
    let mut output = Vec::new();
    if output.try_reserve_exact(output_len).is_err() {
        return None;
    }
    for _ in 0..n {
        output.extend_from_slice(bytes);
    }
    Some(output)
}

/// # Safety
/// `s` must be a readable NUL-terminated string when non-null.
pub unsafe fn rs_strrep(s: *const c_char, n: usize) -> *mut c_char {
    if s.is_null() {
        return std::ptr::null_mut();
    }
    with_c_string(s, |bytes| {
        let Some(output) = repeated_bytes(bytes, n) else {
            return ptr::null_mut();
        };
        alloc_c_string_from_bytes(&output)
    })
    .unwrap_or(ptr::null_mut())
}

fn count_occurrences(haystack: &[u8], needle: &[u8]) -> usize {
    let mut count = 0;
    let mut index = 0;
    while index < haystack.len() {
        let Some(remaining) = haystack.get(index..) else {
            return count;
        };
        if remaining.starts_with(needle) {
            count += 1;
            index += needle.len();
        } else {
            index += 1;
        }
    }
    count
}

fn replaced_bytes(text: &[u8], old: &[u8], new: &[u8]) -> Option<Vec<u8>> {
    if old.is_empty() {
        let mut copy = Vec::new();
        if copy.try_reserve_exact(text.len()).is_err() {
            return None;
        }
        copy.extend_from_slice(text);
        return Some(copy);
    }

    let count = count_occurrences(text, old);
    let output_len = count
        .checked_mul(old.len())
        .and_then(|removed| text.len().checked_sub(removed))
        .and_then(|base| {
            count
                .checked_mul(new.len())
                .and_then(|added| base.checked_add(added))
        })?;
    let mut output = Vec::new();
    if output.try_reserve_exact(output_len).is_err() {
        return None;
    }

    let mut remaining = text;
    while let Some(index) = remaining
        .windows(old.len())
        .position(|window| window == old)
    {
        output.extend_from_slice(&remaining[..index]);
        output.extend_from_slice(new);
        remaining = &remaining[index + old.len()..];
    }
    output.extend_from_slice(remaining);
    debug_assert_eq!(output.len(), output_len);
    Some(output)
}

/// # Safety
/// All non-null arguments must be readable NUL-terminated strings.
pub unsafe fn rs_strreplace(
    text: *const c_char,
    old_string: *const c_char,
    new_string: *const c_char,
) -> *mut c_char {
    if text.is_null() || old_string.is_null() || new_string.is_null() {
        return std::ptr::null_mut();
    }
    with_three_c_strings(text, old_string, new_string, |text, old, new| {
        let Some(output) = replaced_bytes(text, old, new) else {
            return ptr::null_mut();
        };
        alloc_c_string_from_bytes(&output)
    })
    .unwrap_or(ptr::null_mut())
}
