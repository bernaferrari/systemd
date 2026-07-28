// SPDX-License-Identifier: LGPL-2.1-or-later
//
// Exact C ABI adapters for the small inline helpers in utf8.h and path-util.h.
//
// All behaviour lives in byte-oriented or scalar safe cores. This module is
// the deliberately narrow boundary which borrows a NUL-terminated C string
// for one call and returns either the original borrowed pointer or a fresh
// libc allocation, exactly as the corresponding C inline helper does.

use std::ffi::CStr;
use std::ptr;

use libc::c_char;

use crate::escape::malloc_c_string;
use crate::path_util::skip_dev_prefix_offset;
use crate::string_util::{try_utf8_escape_non_printable, valid_utf8_character};
use crate::utf8::{
    utf16_is_surrogate, utf16_is_trailing_surrogate, utf16_surrogate_pair_to_unichar,
};

/// Current C `utf8_is_valid()` policy over the visible bytes of a C string.
fn utf8_is_valid_bytes(bytes: &[u8]) -> bool {
    let mut offset = 0;
    while offset < bytes.len() {
        let Some((length, _)) = valid_utf8_character(&bytes[offset..]) else {
            return false;
        };
        offset += length;
    }
    true
}

/// Current C `ascii_is_valid()` policy over the visible bytes of a C string.
#[inline]
fn ascii_is_valid_bytes(bytes: &[u8]) -> bool {
    bytes.iter().all(|byte| (1..=0x7f).contains(byte))
}

/// Borrow a C string after the one null-pointer check shared by this slice.
///
/// # Safety
/// `input` must be null or point to a readable NUL-terminated byte string.
unsafe fn input_bytes<'a>(input: *const c_char) -> Option<&'a [u8]> {
    if input.is_null() {
        return None;
    }
    // SAFETY: the adapter's C ABI contract guarantees the input terminator.
    Some(unsafe { CStr::from_ptr(input) }.to_bytes())
}

/// C ABI for utf8.h's `utf8_is_valid()` inline helper.
///
/// # Safety
/// `str_` must be null or a readable NUL-terminated C string. A successful
/// result borrows the input and must not be freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_utf8_is_valid(str_: *const c_char) -> *mut c_char {
    // SAFETY: the entry-point contract is exactly input_bytes' contract.
    let Some(bytes) = (unsafe { input_bytes(str_) }) else {
        return ptr::null_mut();
    };
    if utf8_is_valid_bytes(bytes) {
        str_.cast_mut()
    } else {
        ptr::null_mut()
    }
}

/// C ABI for utf8.h's `ascii_is_valid()` inline helper.
///
/// # Safety
/// `str_` must be null or a readable NUL-terminated C string. A successful
/// result borrows the input and must not be freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_ascii_is_valid(str_: *const c_char) -> *mut c_char {
    // SAFETY: the entry-point contract is exactly input_bytes' contract.
    let Some(bytes) = (unsafe { input_bytes(str_) }) else {
        return ptr::null_mut();
    };
    if ascii_is_valid_bytes(bytes) {
        str_.cast_mut()
    } else {
        ptr::null_mut()
    }
}

/// C ABI for utf8.h's `utf8_escape_non_printable()` inline helper.
///
/// # Safety
/// `str_` must be null or a readable NUL-terminated C string. The successful
/// result is a fresh libc allocation owned by the C caller and released with
/// `free(3)`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_utf8_escape_non_printable(str_: *const c_char) -> *mut c_char {
    // SAFETY: the entry-point contract is exactly input_bytes' contract.
    let Some(bytes) = (unsafe { input_bytes(str_) }) else {
        return ptr::null_mut();
    };
    match try_utf8_escape_non_printable(bytes, usize::MAX, false) {
        Ok(escaped) => malloc_c_string(&escaped),
        Err(()) => ptr::null_mut(),
    }
}

/// C ABI for utf8.h's `utf16_is_surrogate()` inline helper.
#[unsafe(no_mangle)]
pub extern "C" fn rs_utf16_is_surrogate(c: u16) -> bool {
    utf16_is_surrogate(c)
}

/// C ABI for utf8.h's `utf16_is_trailing_surrogate()` inline helper.
#[unsafe(no_mangle)]
pub extern "C" fn rs_utf16_is_trailing_surrogate(c: u16) -> bool {
    utf16_is_trailing_surrogate(c)
}

/// C ABI for utf8.h's `utf16_surrogate_pair_to_unichar()` inline helper.
#[unsafe(no_mangle)]
pub extern "C" fn rs_utf16_surrogate_pair_to_unichar(lead: u16, trail: u16) -> u32 {
    utf16_surrogate_pair_to_unichar(lead, trail)
}

/// C ABI for path-util.h's `skip_dev_prefix()` inline helper.
///
/// # Safety
/// `path` must be null or a readable NUL-terminated C string. A successful
/// result always borrows `path` and must not be freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_skip_dev_prefix(path: *const c_char) -> *const c_char {
    // SAFETY: the entry-point contract is exactly input_bytes' contract.
    let Some(bytes) = (unsafe { input_bytes(path) }) else {
        return ptr::null();
    };
    let offset = skip_dev_prefix_offset(bytes);
    // SAFETY: `offset` is derived from the visible bytes of `path`, so it is
    // within the same borrowed C allocation (including its terminating NUL).
    unsafe { path.add(offset) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utf8_core_rejects_current_c_noncharacters_and_overlong_encodings() {
        assert!(utf8_is_valid_bytes("a€".as_bytes()));
        assert!(!utf8_is_valid_bytes(b"\xef\xb7\x90")); // U+FDD0
        assert!(!utf8_is_valid_bytes(b"\xef\xbf\xbe")); // U+FFFE
        assert!(!utf8_is_valid_bytes(b"\xc0\x80")); // overlong NUL
        assert!(!utf8_is_valid_bytes(b"\xf8\x88\x80\x80\x80"));
    }

    #[test]
    fn skip_dev_prefix_preserves_current_component_matching() {
        assert_eq!(skip_dev_prefix_offset(b"/dev/tty0"), 5);
        assert_eq!(skip_dev_prefix_offset(b"//dev//"), 7);
        assert_eq!(skip_dev_prefix_offset(b"///dev///foo///bar"), 9);
        assert_eq!(skip_dev_prefix_offset(b"/./dev/foo"), 8);
        assert_eq!(skip_dev_prefix_offset(b"/devfoo"), 0);
    }
}
