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

use std::ffi::{CStr, c_void};

use libc::c_char;

use crate::extract_word::rs_extract_first_word;
use crate::ffi::{Errno, free, malloc, strlen};
use crate::string_util::owned::rs_strdup_to_full;

const NEWLINE: &[u8] = b"\n\r";

/// # Safety
/// `ret` and `source` must meet `rs_strdup_to_full`'s output and C-string
/// contracts, respectively.
unsafe fn strdup_to(ret: *mut *mut c_char, source: *const c_char) -> i32 {
    // SAFETY: this helper forwards its exact pointer contract unchanged.
    let result = unsafe { rs_strdup_to_full(ret, source) };
    if result < 0 { result } else { 0 }
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
    let mut cursor = 0usize;
    let mut end = 0usize;
    let mut count = 0usize;
    let mut truncated = false;
    loop {
        let mut width = 0usize;
        // SAFETY: `cursor + width` stays within the input C string while scanning.
        while unsafe { *s.add(cursor + width) } != 0
            && unsafe { *s.add(cursor + width) } != b'\n' as c_char
        {
            width += 1;
        }
        // SAFETY: the scan offset is within the readable NUL-terminated input.
        if unsafe { *s.add(cursor + width) } == 0 {
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

    // SAFETY: `end` was computed while traversing the input C string.
    let copy = if unsafe { *s.add(end) } == 0 {
        // SAFETY: `s` is a readable NUL-terminated input string by contract.
        let length = unsafe { strlen(s) };
        // SAFETY: allocation includes the terminator copied below.
        let value = malloc(length + 1).cast::<c_char>();
        if value.is_null() {
            return Errno::ENOMEM.to_neg_errno();
        }
        // SAFETY: `value` has `length + 1` bytes and the source string has
        // exactly `length` visible bytes.
        unsafe {
            std::ptr::copy_nonoverlapping(s.cast::<u8>(), value.cast::<u8>(), length);
            *value.add(length) = 0;
        }
        value
    } else {
        let mut remainder = end;
        let mut only_newlines = true;
        loop {
            // SAFETY: `remainder` advances only while traversing the input C string.
            let byte = unsafe { *s.add(remainder) };
            if byte == 0 {
                break;
            }
            if byte != b'\n' as c_char {
                only_newlines = false;
                break;
            }
            remainder += 1;
        }
        truncated = !only_newlines;
        // SAFETY: allocation includes the copied prefix and its trailing NUL.
        let value = malloc(end + 1).cast::<c_char>();
        if value.is_null() {
            return Errno::ENOMEM.to_neg_errno();
        }
        // SAFETY: `value` owns `end + 1` bytes and the source prefix is readable.
        unsafe {
            std::ptr::copy_nonoverlapping(s.cast::<u8>(), value.cast::<u8>(), end);
            *value.add(end) = 0;
        }
        value
    };
    // SAFETY: ret was checked non-null and is writable by the function contract.
    unsafe { *ret = copy };
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
    let mut cursor = 0usize;
    let mut line = 0usize;
    loop {
        let mut end = cursor;
        loop {
            // SAFETY: `end` advances only while traversing the input C string.
            let byte = unsafe { *s.add(end) };
            if byte == 0 || byte == b'\n' as c_char {
                break;
            }
            end += 1;
        }
        // SAFETY: `end` was found by traversing the input C string.
        let has_newline = unsafe { *s.add(end) } == b'\n' as c_char;
        if line == wanted {
            if has_newline {
                let length = end - cursor;
                // SAFETY: allocation includes the selected line and trailing NUL.
                let value = malloc(length + 1).cast::<c_char>();
                if value.is_null() {
                    return Errno::ENOMEM.to_neg_errno();
                }
                // SAFETY: source and destination ranges contain `length` bytes;
                // `value` owns one extra byte for the terminator and `ret` is optional.
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        s.add(cursor).cast::<u8>(),
                        value.cast::<u8>(),
                        length,
                    );
                    *value.add(length) = 0;
                    *ret = value;
                }
                // SAFETY: a newline was found at `end`, so `end + 1` remains in range.
                return i32::from(unsafe { *s.add(end + 1) } != 0);
            }
            let source = if cursor == 0 {
                std::ptr::null()
            } else {
                // SAFETY: `cursor` is an offset established while scanning `s`.
                unsafe { s.add(cursor) }
            };
            // SAFETY: `source` and `ret` satisfy `strdup_to`'s forwarded contract.
            return unsafe { strdup_to(ret, source) };
        }
        if !has_newline {
            // SAFETY: the static empty C string and optional `ret` satisfy the helper contract.
            return unsafe { strdup_to(ret, c"".as_ptr()) };
        }
        cursor = end + 1;
        line += 1;
    }
}

/// # Safety
/// `haystack` and `needle` must be readable NUL-terminated strings.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_find_line_startswith_internal(
    haystack: *const c_char,
    needle: *const c_char,
) -> *mut c_char {
    if haystack.is_null() || needle.is_null() {
        return std::ptr::null_mut();
    }
    // SAFETY: both inputs are readable C strings by the function contract.
    let haystack_bytes = unsafe { CStr::from_ptr(haystack) }.to_bytes();
    // SAFETY: both inputs are readable C strings by the function contract.
    let needle_bytes = unsafe { CStr::from_ptr(needle) }.to_bytes();
    let mut offset = 0usize;
    loop {
        if haystack_bytes[offset..].starts_with(needle_bytes) {
            // SAFETY: the returned offset lies at or before the input terminator.
            return unsafe { (haystack as *mut c_char).add(offset + needle_bytes.len()) };
        }
        if offset >= haystack_bytes.len() {
            break;
        }
        while offset < haystack_bytes.len() && haystack_bytes[offset] != b'\n' {
            offset += 1;
        }
        if offset < haystack_bytes.len() {
            offset += 1;
        }
    }
    std::ptr::null_mut()
}

/// # Safety
/// `haystack` and `needle` must be readable NUL-terminated strings.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_find_line_internal(
    haystack: *const c_char,
    needle: *const c_char,
) -> *mut c_char {
    // SAFETY: this function forwards the same C-string contract to the helper.
    let after = unsafe { rs_find_line_startswith_internal(haystack, needle) };
    if after.is_null() {
        return std::ptr::null_mut();
    }
    // SAFETY: non-null `after` aliases a byte within the validated haystack string.
    let after_byte = unsafe { *after } as u8;
    if !(after_byte == 0 || NEWLINE.contains(&after_byte)) {
        return std::ptr::null_mut();
    }
    // SAFETY: `after` was formed by adding exactly `needle.len()` to haystack.
    unsafe { after.sub(strlen(needle)) }
}

/// # Safety
/// `haystack` and `needle` must be readable NUL-terminated strings.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_find_line_after_internal(
    haystack: *const c_char,
    needle: *const c_char,
) -> *mut c_char {
    // SAFETY: this function forwards the same C-string contract to the helper.
    let after = unsafe { rs_find_line_startswith_internal(haystack, needle) };
    if after.is_null() {
        return after;
    }
    // SAFETY: non-null `after` aliases a byte within the validated haystack string.
    let after_byte = unsafe { *after } as u8;
    if after_byte == 0 {
        return after;
    }
    if NEWLINE.contains(&after_byte) {
        // SAFETY: a newline byte is followed by another byte in the C string.
        unsafe { after.add(1) }
    } else {
        std::ptr::null_mut()
    }
}

/// # Safety
/// `list` must be a NUL-terminated vector of readable C strings and `needle`
/// must be a readable C string.
unsafe fn strv_find(list: *const *const c_char, needle: *const c_char) -> *const c_char {
    if list.is_null() || needle.is_null() {
        return std::ptr::null();
    }
    // SAFETY: `needle` is a readable C string by the helper contract.
    let needle = unsafe { CStr::from_ptr(needle) };
    let mut entry = list;
    loop {
        // SAFETY: `entry` traverses the NUL-terminated vector required by the contract.
        let value = unsafe { *entry };
        if value.is_null() {
            break;
        }
        // SAFETY: every non-null vector element is a readable C string by contract.
        if unsafe { CStr::from_ptr(value) } == needle {
            return value;
        }
        // SAFETY: advancing within the NUL-terminated vector stays in its allocation.
        entry = unsafe { entry.add(1) };
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
        let result = unsafe { rs_extract_first_word(&mut cursor, &mut word, separators, flags) };
        if result == 0 {
            // SAFETY: non-null `ret_word` is writable by the function contract.
            if !ret_word.is_null() {
                unsafe { *ret_word = std::ptr::null() };
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
            unsafe { strv_find(words.cast(), word) }
        };
        if !word.is_null() {
            // SAFETY: extract_first_word returned unique C ownership.
            unsafe { free(word.cast::<c_void>()) };
        }
        if !found.is_null() {
            // SAFETY: non-null `ret_word` is writable by the function contract.
            if !ret_word.is_null() {
                unsafe { *ret_word = found };
            }
            return 1;
        }
    }
}
