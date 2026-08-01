// SPDX-License-Identifier: LGPL-2.1-or-later
//
// Allocation-owning octal, decimal, and shell escape adapters.
//
// The byte policies stay safe; this module alone owns the fallible Vec and
// libc allocation boundaries used by the C ABI.

use libc::c_char;
use std::ffi::CStr;
use std::ptr;

use super::{append_cescape_char, char_is_cc, utf8_encoded_valid_unichar};

/// Allocate an output buffer with the exact overflow limit used by the C
/// escape helpers. `try_reserve_exact` turns allocation failure into the
/// C-facing NULL result instead of unwinding across the ABI boundary.
fn try_escape_buffer(input_len: usize) -> Result<Vec<u8>, ()> {
    let capacity = input_len
        .checked_mul(4)
        .and_then(|n| n.checked_add(1))
        .ok_or(())?;
    let mut result = Vec::new();
    result.try_reserve_exact(capacity).map_err(|_| ())?;
    Ok(result)
}

/// Byte-level equivalent of `octescape_full()`. `bad` is intentionally a
/// byte slice: C treats both inputs as arbitrary bytes, not UTF-8 text.
fn try_octescape_full(s: &[u8], bad: &[u8]) -> Result<Vec<u8>, ()> {
    let mut result = try_escape_buffer(s.len())?;
    for &u in s {
        if u < b' ' || u >= 127 || u == b'\\' || u == b'"' || bad.contains(&u) {
            result.push(b'\\');
            result.push(b'0' + (u >> 6));
            result.push(b'0' + ((u >> 3) & 7));
            result.push(b'0' + (u & 7));
        } else {
            result.push(u);
        }
    }
    Ok(result)
}

/// Escape bytes in \nnn octal style for \, ", and non-printable chars.
///
/// This infallible convenience API preserves the historical Rust-only
/// signature. C ABI callers use `try_octescape_full()` so allocation failure
/// is reported as NULL, just like current C.
pub fn octescape(s: &[u8]) -> Vec<u8> {
    try_octescape_full(s, &[]).expect("octescape allocation failed")
}

/// Byte-level equivalent of `decescape()`, including its checked C allocation
/// size. This is separate from the ABI shell so the escaping policy itself
/// remains wholly safe Rust.
fn try_decescape(s: &[u8], bad: &[u8]) -> Result<Vec<u8>, ()> {
    let mut result = try_escape_buffer(s.len())?;
    for &u in s {
        let need_escape = u < b' ' || u >= 127 || u == b'\\' || u == b'"' || bad.contains(&u);

        if need_escape {
            result.push(b'\\');
            result.push(b'0' + (u / 100));
            result.push(b'0' + ((u / 10) % 10));
            result.push(b'0' + (u % 10));
        } else {
            result.push(u);
        }
    }
    Ok(result)
}

/// Escape bytes in \nnn decimal style for \, ", control chars, DEL, and chars
/// in `bad`.
pub fn decescape(s: &[u8], bad: &[u8]) -> Vec<u8> {
    try_decescape(s, bad).expect("decescape allocation failed")
}

/// Byte-oriented implementation shared by this module's C ABI shells and the
/// strv adapter. The caller owns the Rust buffer until it is copied to
/// C-allocator storage.
pub(crate) fn try_strcpy_backslash_escaped(s: &[u8], bad: &[u8]) -> Result<Vec<u8>, ()> {
    let mut result = try_escape_buffer(s.len())?;
    let mut si = 0usize;

    while si < s.len() {
        let width = utf8_encoded_valid_unichar(&s[si..]);

        if width < 0 || char_is_cc(s[si]) {
            // The buffer reserves four bytes per input byte, so this
            // maximum-four-byte append cannot reallocate.
            append_cescape_char(&mut result, s[si]);
            si += 1;
        } else if width == 1 {
            if s[si] == b'\\' || bad.contains(&s[si]) {
                result.push(b'\\');
            }
            result.push(s[si]);
            si += 1;
        } else {
            let width = width as usize;
            result.extend_from_slice(&s[si..si + width]);
            si += width;
        }
    }
    Ok(result)
}

/// Shell-escape a valid Rust string, backslash-escaping chars in `bad`.
pub fn shell_escape(s: &str, bad: &str) -> String {
    let escaped = try_strcpy_backslash_escaped(s.as_bytes(), bad.as_bytes())
        .expect("shell_escape allocation failed");
    // Valid UTF-8 input remains valid: multi-byte units are copied unchanged
    // and only ASCII escape syntax is inserted around ASCII bytes.
    String::from_utf8(escaped).expect("shell_escape must preserve valid UTF-8")
}

/// Copy a Rust-owned escaped byte sequence into one C allocator allocation.
/// Escape output cannot contain an embedded NUL.
pub(crate) fn malloc_c_string(bytes: &[u8]) -> *mut c_char {
    let Some(allocation_size) = bytes.len().checked_add(1) else {
        return ptr::null_mut();
    };
    let allocation = crate::ffi::malloc(allocation_size).cast::<u8>();
    if allocation.is_null() {
        return ptr::null_mut();
    }

    // SAFETY: `allocation` owns exactly `bytes.len() + 1` writable bytes from
    // the C allocator; `bytes` is live and disjoint. The final NUL establishes
    // the C-string result whose ownership transfers to the caller.
    unsafe_ffi!({
        ptr::copy_nonoverlapping(bytes.as_ptr(), allocation, bytes.len());
        *allocation.add(bytes.len()) = 0;
    });
    allocation.cast::<c_char>()
}

/// Borrow an explicit-length C byte sequence, implementing the current C
/// `SIZE_MAX` sentinel and its `s || len == 0` precondition.
///
/// # Safety
/// When `len != SIZE_MAX`, a non-null `s` must be readable for `len` bytes.
/// When `len == SIZE_MAX`, `s` must be a readable NUL-terminated C string.
unsafe fn with_input_bytes<T>(
    s: *const c_char,
    len: usize,
    use_bytes: impl FnOnce(&[u8]) -> T,
) -> Option<T> {
    if len == usize::MAX {
        if s.is_null() {
            return None;
        }
        // SAFETY: upheld by this helper's documented sentinel contract.
        return Some(use_bytes(unsafe_ffi!(CStr::from_ptr(s)).to_bytes()));
    }
    if s.is_null() {
        return (len == 0).then(|| use_bytes(&[]));
    }
    // SAFETY: upheld by this helper's explicit-length contract.
    Some(use_bytes(unsafe_ffi!({
        std::slice::from_raw_parts(s.cast::<u8>(), len)
    })))
}

/// C ABI for `octescape()`.
///
/// # Safety
/// `s` follows `with_input_bytes()`'s explicit-length contract. The result is
/// a fresh `malloc(3)` allocation owned by the caller and released with free.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_octescape(s: *const c_char, len: usize) -> *mut c_char {
    // SAFETY: this entry point forwards its documented input contract.
    let Some(escaped) = (unsafe_ffi!(with_input_bytes(s, len, |bytes| try_octescape_full(
        bytes,
        &[]
    )))) else {
        return ptr::null_mut();
    };
    escaped
        .map(|bytes| malloc_c_string(&bytes))
        .unwrap_or(ptr::null_mut())
}

/// C ABI for `decescape()`.
///
/// # Safety
/// `s` follows `with_input_bytes()`'s contract. `bad` must be a non-null
/// readable NUL-terminated C string. Inputs are borrowed only for this call;
/// the returned malloc allocation is owned by the caller and released with
/// free.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_decescape(
    s: *const c_char,
    len: usize,
    bad: *const c_char,
) -> *mut c_char {
    if bad.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: the entry point's contract covers the borrowed `bad` string.
    let bad = unsafe_ffi!(CStr::from_ptr(bad));
    // SAFETY: the entry point's contract covers the explicit-length input.
    let Some(escaped) = (unsafe_ffi!(with_input_bytes(s, len, |bytes| try_decescape(
        bytes,
        bad.to_bytes()
    )))) else {
        return ptr::null_mut();
    };
    escaped
        .map(|bytes| malloc_c_string(&bytes))
        .unwrap_or(ptr::null_mut())
}

/// C ABI for `shell_escape()`.
///
/// # Safety
/// `s` and `bad` must be non-null readable NUL-terminated C strings. Both are
/// borrowed only for this call. The returned malloc allocation is owned by the
/// caller and released with free.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_shell_escape(s: *const c_char, bad: *const c_char) -> *mut c_char {
    if s.is_null() || bad.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: the entry point's C-string contract guarantees both pointers.
    let (s, bad) = unsafe_ffi!((CStr::from_ptr(s).to_bytes(), CStr::from_ptr(bad).to_bytes()));
    try_strcpy_backslash_escaped(s, bad)
        .map(|escaped| malloc_c_string(&escaped))
        .unwrap_or(ptr::null_mut())
}
