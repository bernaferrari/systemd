// SPDX-License-Identifier: LGPL-2.1-or-later
//
// Exact C ABI adapters for escape.c's core cescape/cunescape helpers.
//
// All escape policy is expressed in safe byte-oriented helpers in the parent
// module. This file contains the only raw-pointer boundary: it validates the
// public nullable cases, borrows C input for the duration of a call, and
// transfers fresh malloc(3) output to the C caller.

use libc::c_char;
use std::ffi::CStr;
use std::ptr;

use super::{EINVAL, cescape_char_into, cunescape_one, malloc_c_string};

/// Borrow C input following escape.h's `s || n == 0` contract.
///
/// `SIZE_MAX` means a NUL-terminated C string, while every other length is a
/// byte count and can include embedded NUL bytes.
///
/// # Safety
/// For the sentinel form, `s` must be a non-null readable C string. For an
/// explicit non-zero length, `s` must be readable for exactly that many bytes.
unsafe fn cescape_input<'a>(s: *const c_char, n: usize) -> Option<&'a [u8]> {
    if n == usize::MAX {
        if s.is_null() {
            return None;
        }
        // SAFETY: guaranteed by this helper's documented sentinel contract.
        return Some(unsafe { CStr::from_ptr(s) }.to_bytes());
    }
    if s.is_null() {
        return (n == 0).then_some(&[]);
    }
    // SAFETY: guaranteed by this helper's documented explicit-length contract.
    Some(unsafe { std::slice::from_raw_parts(s.cast::<u8>(), n) })
}

/// C ABI for `cescape_char()`.
///
/// # Safety
/// `buf` must designate four writable bytes, as required by escape.h. No NUL
/// terminator is written; the function returns the number of output bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_cescape_char(c: c_char, buf: *mut c_char) -> i32 {
    if buf.is_null() {
        return EINVAL;
    }
    let mut escaped = [0; 4];
    let length = cescape_char_into(c as u8, &mut escaped);
    debug_assert!((1..=4).contains(&length));
    // SAFETY: `buf` is non-null and the C entry-point contract guarantees four
    // writable bytes. `escaped` contains at most four live, disjoint bytes.
    unsafe { ptr::copy_nonoverlapping(escaped.as_ptr(), buf.cast::<u8>(), length) };
    length as i32
}

/// C ABI for `cescape_length()`.
///
/// # Safety
/// `s` follows `cescape_input()`'s documented sentinel/explicit-length
/// contract. The returned pointer is a fresh malloc(3) allocation owned by
/// the caller and released with free(3).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_cescape_length(s: *const c_char, n: usize) -> *mut c_char {
    // SAFETY: the entry point has the same input contract as this helper.
    let Some(source) = (unsafe { cescape_input(s, n) }) else {
        return ptr::null_mut();
    };
    // Keep current C's pre-allocation overflow predicate, rather than relying
    // on a later Vec reservation failure with different observable behavior.
    if source.len() > (usize::MAX - 1) / 4 {
        return ptr::null_mut();
    }
    let mut escaped = Vec::new();
    if escaped
        .try_reserve_exact(source.len().saturating_mul(4))
        .is_err()
    {
        return ptr::null_mut();
    }
    for &byte in source {
        let mut one = [0; 4];
        let length = cescape_char_into(byte, &mut one);
        escaped.extend_from_slice(&one[..length]);
    }
    malloc_c_string(&escaped)
}

/// C ABI for escape.h's `cescape()` inline convenience function.
///
/// # Safety
/// `s` must be a non-null readable NUL-terminated C string. The returned
/// pointer has the same malloc(3) ownership as `rs_cescape_length()`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_cescape(s: *const c_char) -> *mut c_char {
    // SAFETY: `SIZE_MAX` selects the entry point's documented C-string form.
    unsafe { rs_cescape_length(s, usize::MAX) }
}

/// C ABI for `cunescape_one()`.
///
/// # Safety
/// `p` is a readable C string when `length == SIZE_MAX`, or readable for
/// `length` bytes otherwise. `ret` is writable for one char32_t. When the
/// `eight_bit` is non-null and writable for one bool on every call, matching
/// current C's asserted precondition. Current C initializes that bool only for
/// octal and `\\x` escapes and otherwise leaves its prior value unchanged.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_cunescape_one(
    p: *const c_char,
    length: usize,
    ret: *mut u32,
    eight_bit: *mut bool,
    accept_nul: bool,
) -> i32 {
    if p.is_null() || ret.is_null() || eight_bit.is_null() {
        return EINVAL;
    }
    let input = if length == usize::MAX {
        // SAFETY: the entry point guarantees that p is a readable C string.
        unsafe { CStr::from_ptr(p) }.to_bytes()
    } else {
        // SAFETY: the entry point guarantees exactly `length` readable bytes.
        unsafe { std::slice::from_raw_parts(p.cast::<u8>(), length) }
    };
    let result = match cunescape_one(input, accept_nul) {
        Ok(result) => result,
        Err(error) => return error,
    };
    // SAFETY: `ret` was checked and the entry-point contract grants one
    // writable char32_t and `eight_bit` was checked non-null. The bool is
    // written only on the exact C branches that initialize it.
    unsafe {
        *ret = result.ch;
        if result.eight_bit {
            *eight_bit = true;
        }
    }
    result.consumed as i32
}

/// C ABI for escape.h's `cunescape()` inline convenience function.
///
/// # Safety
/// `s` is a non-null readable C string and `ret` is non-null/writable for one
/// pointer. On success it receives a fresh malloc(3) allocation, published
/// only after every fallible operation succeeds. Explicit binary lengths are
/// handled by `rs_cunescape_length_with_prefix`, exactly as in escape.h.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_cunescape(
    s: *const c_char,
    flags: u32,
    ret: *mut *mut c_char,
) -> isize {
    // SAFETY: this inline-equivalent adapter forwards its C-string and output
    // pointer contract to the canonical explicit-length implementation.
    unsafe {
        super::full_abi::rs_cunescape_length_with_prefix(s, usize::MAX, ptr::null(), flags, ret)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cescape_char_handles_signed_c_char_as_an_unsigned_byte() {
        let mut output = [0 as c_char; 4];
        // SAFETY: output owns four writable C-char slots.
        let length = unsafe { rs_cescape_char(u8::MAX as c_char, output.as_mut_ptr()) };
        assert_eq!(length, 4);
        assert_eq!(output.map(|byte| byte as u8), *b"\\377");
    }

    #[test]
    fn cescape_length_accepts_embedded_nul_at_the_explicit_boundary() {
        let source = [b'a' as c_char, 0, b'\n' as c_char];
        // SAFETY: source has exactly the explicit readable byte length.
        let output = unsafe { rs_cescape_length(source.as_ptr(), source.len()) };
        assert!(!output.is_null());
        // SAFETY: output is our fresh NUL-terminated malloc allocation.
        let bytes = unsafe { CStr::from_ptr(output) }.to_bytes();
        assert_eq!(bytes, b"a\\000\\n");
        // SAFETY: ownership was transferred by the ABI function.
        unsafe { libc::free(output.cast()) };
    }

    #[test]
    fn cunescape_one_preserves_c_eight_bit_write_policy() {
        let input = b"n\0";
        let mut output = 0_u32;
        let mut untouched = false;
        // SAFETY: all passed pointers meet the documented C ABI contract.
        assert_eq!(
            unsafe {
                rs_cunescape_one(
                    input.as_ptr().cast(),
                    usize::MAX,
                    &mut output,
                    &mut untouched,
                    false,
                )
            },
            1
        );
        assert_eq!(output, b'\n' as u32);
        assert!(!untouched);
    }
}
