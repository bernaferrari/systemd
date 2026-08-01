// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: scope=basic.bus-label; authority=src/basic/bus-label.c,src/basic/bus-label.h
//
// D-Bus object-path label escaping/unescaping. The C ABI accepts and returns
// byte strings; only the input to rs_bus_label_escape is NUL-terminated.

// Centralized unsafe expression boundary for this module.
macro_rules! unsafe_ffi {
    ($expression:expr) => {{
        // SAFETY: the enclosing helper documents and validates this operation.
        unsafe { $expression }
    }};
}
use std::ffi::CStr;
use std::os::raw::c_char;
use std::ptr;
use std::slice;

const HEX_LOWER: &[u8; 16] = b"0123456789abcdef";

#[inline]
fn hexchar(x: u8) -> u8 {
    HEX_LOWER[(x & 0xf) as usize]
}

#[inline]
fn unhexchar(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

#[inline]
fn ascii_isalpha(c: u8) -> bool {
    c.is_ascii_lowercase() || c.is_ascii_uppercase()
}

#[inline]
fn ascii_isdigit(c: u8) -> bool {
    c.is_ascii_digit()
}

fn escape_into(input: &[u8], mut push: impl FnMut(u8)) {
    if input.is_empty() {
        push(b'_');
        return;
    }

    for (i, &byte) in input.iter().enumerate() {
        if !ascii_isalpha(byte) && !(i > 0 && ascii_isdigit(byte)) {
            push(b'_');
            push(hexchar(byte >> 4));
            push(hexchar(byte));
        } else {
            push(byte);
        }
    }
}

fn unescape_into(input: &[u8], mut push: impl FnMut(u8)) {
    if input == b"_" {
        return;
    }

    let mut i = 0;
    while i < input.len() {
        if input[i] != b'_' {
            push(input[i]);
            i += 1;
            continue;
        }

        if input.len() - i >= 3 {
            if let (Some(a), Some(b)) = (unhexchar(input[i + 1]), unhexchar(input[i + 2])) {
                push((a << 4) | b);
                i += 3;
                continue;
            }
        }

        // Invalid and truncated escapes keep their underscore literal. The
        // following bytes are intentionally processed by later iterations.
        push(b'_');
        i += 1;
    }
}

/// Escape arbitrary bytes using `bus_label_escape()` semantics.
///
/// `None` means that reserving the output buffer failed. Unlike the former
/// `String` helper, this preserves non-UTF-8 input byte-for-byte.
pub fn bus_label_escape_bytes(input: &[u8]) -> Option<Vec<u8>> {
    let capacity = input.len().checked_mul(3)?.max(1);
    let mut output = Vec::new();
    output.try_reserve_exact(capacity).ok()?;
    escape_into(input, |byte| output.push(byte));
    Some(output)
}

/// Unescape arbitrary bytes using `bus_label_unescape_n()` semantics.
///
/// The returned bytes may contain NUL or invalid UTF-8, exactly as the C
/// function's allocated buffer may. `None` means that reserving the output
/// buffer failed.
pub fn bus_label_unescape_bytes(input: &[u8]) -> Option<Vec<u8>> {
    let mut output = Vec::new();
    output.try_reserve_exact(input.len()).ok()?;
    unescape_into(input, |byte| output.push(byte));
    Some(output)
}

#[inline]
fn malloc_c_buffer(capacity: usize) -> *mut c_char {
    let Some(allocation_size) = capacity.checked_add(1) else {
        return ptr::null_mut();
    };

    crate::ffi::malloc(allocation_size).cast::<c_char>()
}

/// C ABI mirror of `bus_label_escape()`.
///
/// # Safety
///
/// `s` must be null or point to a live NUL-terminated byte string. On success,
/// the returned pointer owns a C-allocator allocation and must be released
/// with `free()` by the caller.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_bus_label_escape(s: *const c_char) -> *mut c_char {
    if s.is_null() {
        return ptr::null_mut();
    }

    // SAFETY: the entry-point contract guarantees a live NUL-terminated input.
    let input = unsafe_ffi!(CStr::from_ptr(s)).to_bytes();
    let Some(capacity) = input.len().checked_mul(3).map(|n| n.max(1)) else {
        return ptr::null_mut();
    };
    let output = malloc_c_buffer(capacity);
    if output.is_null() {
        return ptr::null_mut();
    }

    let mut cursor = output.cast::<u8>();
    escape_into(input, |byte| {
        // SAFETY: `capacity` reserves three bytes per input byte (or one for
        // the empty special case), so each write stays in the allocation.
        unsafe_ffi!({
            *cursor = byte;
            cursor = cursor.add(1);
        })
    });
    // SAFETY: the escaping pass used at most `capacity` bytes, leaving the
    // final byte of the `capacity + 1` allocation for the terminator.
    unsafe_ffi!(*cursor = 0);

    output
}

/// C ABI mirror of `bus_label_unescape_n()`.
///
/// # Safety
///
/// `f` must be non-null. If `l != SIZE_MAX`, it must be readable for `l`
/// bytes; if `l == SIZE_MAX`, it must be a live NUL-terminated byte string.
/// On success, the returned pointer owns a C-allocator allocation and must be
/// released with `free()` by the caller. Decoded `_00` bytes are retained in
/// the allocation before its final terminator, just as in C.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_bus_label_unescape_n(f: *const c_char, l: usize) -> *mut c_char {
    if f.is_null() {
        return ptr::null_mut();
    }

    let input = if l == usize::MAX {
        // SAFETY: the entry-point contract guarantees a live C string here.
        unsafe_ffi!(CStr::from_ptr(f)).to_bytes()
    } else if l == 0 {
        // C only checks that f is non-null in this case; it does not dereference
        // it, so avoid imposing a stronger Rust slice-provenance requirement.
        &[]
    } else {
        // SAFETY: the entry-point contract guarantees this exact readable range.
        unsafe_ffi!(slice::from_raw_parts(f.cast::<u8>(), l))
    };

    let output = malloc_c_buffer(input.len());
    if output.is_null() {
        return ptr::null_mut();
    }

    let mut cursor = output.cast::<u8>();
    unescape_into(input, |byte| {
        // SAFETY: unescaping produces no more bytes than its input length.
        unsafe_ffi!({
            *cursor = byte;
            cursor = cursor.add(1);
        })
    });
    // SAFETY: at most `input.len()` bytes were written into the allocation.
    unsafe_ffi!(*cursor = 0);

    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escape_preserves_raw_input_bytes() {
        assert_eq!(
            bus_label_escape_bytes(b"a\xc3\xa9"),
            Some(b"a_c3_a9".to_vec())
        );
    }

    #[test]
    fn escape_matches_c_special_cases() {
        assert_eq!(bus_label_escape_bytes(b""), Some(b"_".to_vec()));
        assert_eq!(
            bus_label_escape_bytes(b"123abc"),
            Some(b"_3123abc".to_vec())
        );
        assert_eq!(
            bus_label_escape_bytes(b"foo_bar"),
            Some(b"foo_5fbar".to_vec())
        );
    }

    #[test]
    fn unescape_keeps_invalid_escapes_literal() {
        assert_eq!(bus_label_unescape_bytes(b"_xz_2"), Some(b"_xz_2".to_vec()));
    }

    #[test]
    fn unescape_preserves_decoded_nul() {
        assert_eq!(bus_label_unescape_bytes(b"_00A"), Some(vec![0, b'A']));
    }
}
