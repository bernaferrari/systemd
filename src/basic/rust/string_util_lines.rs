// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/basic/string-util.c
//
// Line extraction/search and word-vector matching. Allocation points downward
// to `owned`; no sibling imports this domain, so dependencies remain acyclic.
//
// SAFETY: pointer traversal is bounded by NUL terminators required by each
// function's Safety contract. Every allocation is sized before copying, and
// word ownership is released exactly once at the extract-word boundary.

// Centralized unsafe expression boundary for this C-ABI adapter.
macro_rules! unsafe_ffi {
    ($expression:expr) => {{
        // SAFETY: the enclosing adapter documents and validates the raw-pointer,
        // ownership, and lifetime contract before evaluating this expression.
        unsafe { $expression }
    }};
}
use std::ffi::{CStr, c_void};

use libc::c_char;

use crate::extract_word::rs_extract_first_word;
use crate::ffi::{Errno, free, malloc};

const NEWLINE: &[u8] = b"\n\r";

/// Copy byte content into a NUL-terminated C-allocator string.
///
/// The safe line-parsing cores use this as their sole allocation bridge, so
/// callers retain the exact `free(3)` ownership expected by the C ABI.
fn c_string_copy(bytes: &[u8]) -> Option<*mut c_char> {
    let allocation_len = bytes.len().checked_add(1)?;
    let value = malloc(allocation_len).cast::<c_char>();
    if value.is_null() {
        return None;
    }
    // SAFETY: `value` owns allocation_len bytes, including the final NUL slot.
    unsafe_ffi!({
        let output = std::slice::from_raw_parts_mut(value.cast::<u8>(), allocation_len);
        output[..bytes.len()].copy_from_slice(bytes);
        output[bytes.len()] = 0;
    });
    Some(value)
}

/// Return the selected line and whether more bytes follow its newline.
/// `None` represents C's special null source result for an unterminated first
/// line; an empty slice is the allocated empty-string result for a missing
/// later line.
fn extract_line_bytes(bytes: &[u8], wanted: usize) -> Option<(&[u8], bool)> {
    let (mut cursor, mut line) = (0usize, 0usize);
    loop {
        let remainder = &bytes[cursor..];
        let line_end = remainder
            .iter()
            .position(|byte| *byte == b'\n')
            .unwrap_or(remainder.len());
        let has_newline = line_end < remainder.len();
        if line == wanted {
            if has_newline {
                return Some((&remainder[..line_end], line_end + 1 < remainder.len()));
            }
            return if cursor == 0 {
                None
            } else {
                Some((remainder, false))
            };
        }
        if !has_newline {
            return Some((&[], false));
        }
        cursor += line_end + 1;
        line += 1;
    }
}

/// Scope two borrowed C strings to a single line-search operation so only this
/// adapter performs raw C-string conversion.
fn with_line_search_bytes<T>(
    haystack: *const c_char,
    needle: *const c_char,
    search: impl FnOnce(&[u8], &[u8]) -> T,
) -> Option<T> {
    if haystack.is_null() || needle.is_null() {
        return None;
    }
    // SAFETY: each public caller guarantees both inputs are readable C strings
    // for this synchronous, non-retaining search.
    let haystack = unsafe_ffi!(CStr::from_ptr(haystack).to_bytes());
    // SAFETY: see the preceding conversion for the same ABI contract.
    let needle = unsafe_ffi!(CStr::from_ptr(needle).to_bytes());
    Some(search(haystack, needle))
}

fn find_line_startswith_offset(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    let mut offset = 0usize;
    loop {
        if haystack[offset..].starts_with(needle) {
            return Some(offset + needle.len());
        }
        if offset == haystack.len() {
            return None;
        }
        offset += haystack[offset..]
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(haystack.len() - offset, |line_len| line_len + 1);
    }
}

/// # Safety
/// `s` must be a readable NUL-terminated string and non-null `ret` must be
/// writable for one owned pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_string_truncate_lines(
    s: *const c_char,
    n_lines: usize,
    ret: *mut *mut c_char,
) -> i32 {
    if s.is_null() || ret.is_null() {
        return Errno::EINVAL.to_neg_errno();
    }
    // SAFETY: the entry-point contract guarantees s is a live C string.
    let bytes = unsafe_ffi!(CStr::from_ptr(s)).to_bytes();
    let mut cursor = 0usize;
    let mut end = 0usize;
    let mut count = 0usize;
    let mut truncated = false;
    loop {
        let mut width = 0usize;
        while cursor + width < bytes.len() && bytes[cursor + width] != b'\n' {
            width += 1;
        }
        if cursor + width == bytes.len() {
            if width == 0 || count >= n_lines {
                break;
            }
            end = cursor + width;
            break;
        }
        if count >= n_lines {
            break;
        }
        if width > 0 {
            end = cursor + width;
        }
        cursor += width + 1;
        count += 1;
    }

    let copy = if end == bytes.len() {
        c_string_copy(bytes)
    } else {
        truncated = !bytes[end..].iter().all(|byte| *byte == b'\n');
        c_string_copy(&bytes[..end])
    };
    let Some(copy) = copy else {
        return Errno::ENOMEM.to_neg_errno();
    };
    // SAFETY: ret was checked non-null and is writable by the function contract.
    unsafe_ffi!(*ret = copy);
    i32::from(truncated)
}

/// # Safety
/// `s` must be a readable NUL-terminated string and `ret` must be null or
/// writable for one owned pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_string_extract_line(
    s: *const c_char,
    wanted: usize,
    ret: *mut *mut c_char,
) -> i32 {
    if s.is_null() || ret.is_null() {
        return Errno::EINVAL.to_neg_errno();
    }
    // SAFETY: the C ABI contract makes `s` a readable NUL-terminated string.
    let bytes = unsafe_ffi!(CStr::from_ptr(s)).to_bytes();
    let Some((line, has_more)) = extract_line_bytes(bytes, wanted) else {
        // SAFETY: `ret` is writable and receives C's null source result.
        unsafe_ffi!(*ret = std::ptr::null_mut());
        return 0;
    };
    let Some(value) = c_string_copy(line) else {
        return Errno::ENOMEM.to_neg_errno();
    };
    // SAFETY: `ret` was checked non-null and is writable by this function contract.
    unsafe_ffi!(*ret = value);
    i32::from(has_more)
}

/// # Safety
/// `haystack` and `needle` must be readable NUL-terminated strings.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_find_line_startswith_internal(
    haystack: *const c_char,
    needle: *const c_char,
) -> *mut c_char {
    let Some(Some(offset)) = with_line_search_bytes(haystack, needle, find_line_startswith_offset)
    else {
        return std::ptr::null_mut();
    };
    // SAFETY: the safe search offset is at or before the input C terminator.
    unsafe_ffi!((haystack as *mut c_char).add(offset))
}

/// # Safety
/// `haystack` and `needle` must be readable NUL-terminated strings.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_find_line_internal(
    haystack: *const c_char,
    needle: *const c_char,
) -> *mut c_char {
    let start = with_line_search_bytes(haystack, needle, |bytes, needle| {
        let after = find_line_startswith_offset(bytes, needle)?;
        match bytes.get(after) {
            None => Some(after - needle.len()),
            Some(byte) if NEWLINE.contains(byte) => Some(after - needle.len()),
            Some(_) => None,
        }
    })
    .flatten();
    let Some(start) = start else {
        return std::ptr::null_mut();
    };
    // SAFETY: `start` is the matching line start established by the safe core.
    unsafe_ffi!((haystack as *mut c_char).add(start))
}

/// # Safety
/// `haystack` and `needle` must be readable NUL-terminated strings.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_find_line_after_internal(
    haystack: *const c_char,
    needle: *const c_char,
) -> *mut c_char {
    let offset = with_line_search_bytes(haystack, needle, |bytes, needle| {
        let after = find_line_startswith_offset(bytes, needle)?;
        match bytes.get(after) {
            None => Some(after),
            Some(byte) if NEWLINE.contains(byte) => Some(after + 1),
            Some(_) => None,
        }
    })
    .flatten();
    let Some(offset) = offset else {
        return std::ptr::null_mut();
    };
    // SAFETY: `offset` is the terminator or byte after a newline in haystack.
    unsafe_ffi!((haystack as *mut c_char).add(offset))
}

/// # Safety
/// `list` must be a NUL-terminated vector of readable C strings and `needle`
/// must be a readable C string.
unsafe fn strv_find(list: *const *const c_char, needle: *const c_char) -> *const c_char {
    if list.is_null() || needle.is_null() {
        return std::ptr::null();
    }
    // SAFETY: `needle` is a readable C string by the helper contract.
    let needle = unsafe_ffi!(CStr::from_ptr(needle));
    let mut entry = list;
    loop {
        // SAFETY: `entry` traverses the NUL-terminated vector required by the contract.
        let value = unsafe_ffi!(*entry);
        if value.is_null() {
            break;
        }
        // SAFETY: every non-null vector element is a readable C string by contract.
        if unsafe_ffi!(CStr::from_ptr(value)) == needle {
            return value;
        }
        // SAFETY: advancing within the NUL-terminated vector stays in its allocation.
        entry = unsafe_ffi!(entry.add(1));
    }
    std::ptr::null()
}

/// # Safety
/// `string`, `separators`, and the null-terminated `words` vector must remain
/// readable for the call. Non-null `ret_word` must be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_string_contains_word_strv(
    string: *const c_char,
    separators: *const c_char,
    words: *const *mut c_char,
    ret_word: *mut *const c_char,
) -> i32 {
    let mut cursor = string;
    loop {
        let mut word = std::ptr::null_mut();
        // SAFETY: the input and output pointers meet extract_first_word's contract.
        let flags = if separators.is_null() { 0 } else { 1 << 6 };
        let result = unsafe_ffi!(rs_extract_first_word(
            &mut cursor,
            &mut word,
            separators,
            flags
        ));
        if result == 0 {
            // SAFETY: non-null `ret_word` is writable by the function contract.
            if !ret_word.is_null() {
                unsafe_ffi!(*ret_word = std::ptr::null());
            }
            return 0;
        }
        if result < 0 {
            return result;
        }
        let found = if word.is_null() {
            std::ptr::null()
        } else {
            // SAFETY: `words` is a NUL-terminated string vector and `word` is a C string.
            unsafe_ffi!(strv_find(words.cast(), word))
        };
        if !word.is_null() {
            // SAFETY: extract_first_word returned unique C ownership.
            unsafe_ffi!(free(word.cast::<c_void>()));
        }
        if !found.is_null() {
            // SAFETY: non-null `ret_word` is writable by the function contract.
            if !ret_word.is_null() {
                unsafe_ffi!(*ret_word = found);
            }
            return 1;
        }
    }
}
