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

use std::ffi::CStr;

use libc::c_char;

use crate::ffi::SIZE_MAX;
use crate::string_util::owned::{alloc_c_string_from_bytes, alloc_empty_c_string};

/// # Safety
/// `a` and `b` must be readable NUL-terminated strings when non-null.
pub unsafe fn rs_str_common_prefix(a: *const c_char, b: *const c_char) -> usize {
    if a.is_null() || b.is_null() {
        return 0;
    }
    // SAFETY: both inputs are readable C strings by the function contract.
    let a = unsafe { CStr::from_ptr(a) }.to_bytes();
    // SAFETY: both inputs are readable C strings by the function contract.
    let b = unsafe { CStr::from_ptr(b) }.to_bytes();
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
}

/// # Safety
/// `string` and `accept` must be readable NUL-terminated strings when non-null.
pub unsafe fn rs_strspn_from_end(string: *const c_char, accept: *const c_char) -> usize {
    if string.is_null() || accept.is_null() {
        return 0;
    }
    // SAFETY: both inputs are readable C strings by the function contract.
    let string = unsafe { CStr::from_ptr(string) }.to_bytes();
    // SAFETY: both inputs are readable C strings by the function contract.
    let accept = unsafe { CStr::from_ptr(accept) }.to_bytes();
    string
        .iter()
        .rev()
        .take_while(|byte| accept.contains(byte))
        .count()
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
    // SAFETY: non-null inputs are readable C strings by the function contract.
    let first = unsafe { CStr::from_ptr(s1) }.to_bytes();
    // SAFETY: non-null inputs are readable C strings by the function contract.
    let second = unsafe { CStr::from_ptr(s2) }.to_bytes();
    let accepted: &[u8] = if ok.is_null() {
        b" \t\n\r"
    } else {
        // SAFETY: non-null `ok` is a readable C string by the function contract.
        unsafe { CStr::from_ptr(ok) }.to_bytes()
    };
    let mut index = 0;
    while index < first.len() && index < second.len() && first[index] == second[index] {
        index += 1;
    }

    first[index..].iter().all(|byte| accepted.contains(byte))
        && second[index..].iter().all(|byte| accepted.contains(byte))
}

/// # Safety
/// `a` and `accept` must be readable NUL-terminated strings when non-null.
pub unsafe fn rs_strdupspn(a: *const c_char, accept: *const c_char) -> *mut c_char {
    if a.is_null() || accept.is_null() {
        return alloc_empty_c_string();
    }
    // SAFETY: both inputs are readable C strings by the function contract.
    let bytes = unsafe { CStr::from_ptr(a) }.to_bytes();
    // SAFETY: both inputs are readable C strings by the function contract.
    let accept = unsafe { CStr::from_ptr(accept) }.to_bytes();
    if bytes.is_empty() || accept.is_empty() {
        return alloc_empty_c_string();
    }
    let length = bytes
        .iter()
        .take_while(|byte| accept.contains(byte))
        .count();
    alloc_c_string_from_bytes(&bytes[..length])
}

/// # Safety
/// `a` and `reject` must be readable NUL-terminated strings when non-null.
pub unsafe fn rs_strdupcspn(a: *const c_char, reject: *const c_char) -> *mut c_char {
    if a.is_null() {
        return alloc_empty_c_string();
    }
    // SAFETY: non-null `a` is a readable C string by the function contract.
    let bytes = unsafe { CStr::from_ptr(a) }.to_bytes();
    if bytes.is_empty() {
        return alloc_empty_c_string();
    }
    let length = if reject.is_null() {
        bytes.len()
    } else {
        // SAFETY: non-null `reject` is a readable C string by the contract.
        let reject = unsafe { CStr::from_ptr(reject) }.to_bytes();
        if reject.is_empty() {
            bytes.len()
        } else {
            bytes
                .iter()
                .take_while(|byte| !reject.contains(byte))
                .count()
        }
    };
    alloc_c_string_from_bytes(&bytes[..length])
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
    // SAFETY: `string` is a readable C string by the function contract.
    let length = unsafe { CStr::from_ptr(string) }.to_bytes().len();
    // SAFETY: `string` is writable for all visible bytes by the contract.
    let bytes = unsafe { std::slice::from_raw_parts_mut(string.cast::<u8>(), length) };
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
    // SAFETY: non-null `s` is a readable C string by the function contract.
    let bytes = unsafe { CStr::from_ptr(s) }.to_bytes();
    let Some(output) = repeated_bytes(bytes, n) else {
        return std::ptr::null_mut();
    };
    alloc_c_string_from_bytes(&output)
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
    // SAFETY: all three inputs are readable C strings by the function contract.
    let text = unsafe { CStr::from_ptr(text) }.to_bytes();
    // SAFETY: all three inputs are readable C strings by the function contract.
    let old = unsafe { CStr::from_ptr(old_string) }.to_bytes();
    // SAFETY: all three inputs are readable C strings by the function contract.
    let new = unsafe { CStr::from_ptr(new_string) }.to_bytes();
    let Some(output) = replaced_bytes(text, old, new) else {
        return std::ptr::null_mut();
    };
    alloc_c_string_from_bytes(&output)
}
