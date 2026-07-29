// SPDX-License-Identifier: LGPL-2.0-or-later
//
// PORT-SYNC: scope=basic.utf8; authority=src/basic/utf8.c,src/basic/utf8.h,src/basic/gunicode.c,src/basic/gunicode.h
//
// UTF-8 validation, encoding, decoding, and utility functions.
// Based on GLIB gutf8.c (Copyright 1999 Tom Tromey, 2000 Red Hat).

use libc::c_char;

use std::ffi::CStr;
use std::os::raw::c_void;
use std::ptr;

use crate::ffi::{Errno, SIZE_MAX};
use crate::gunicode::unichar_iswide;

// ── C dependencies (called via FFI) ──────────────────────────────────────

use crate::ffi::{free, malloc, realloc};

// ── Constants ─────────────────────────────────────────────────────────────

const UTF8_REPLACEMENT_CHARACTER: &[u8] = b"\xef\xbf\xbd"; // U+FFFD

// ── Private helpers (not exported) ───────────────────────────────────────

/// Check if a Unicode codepoint is a control character.
#[inline]
fn unichar_is_control(ch: u32) -> bool {
    // C0 range (except tab, newline) + C1 range
    (ch < 0x20 && ch != 0x09 && ch != 0x0A) || (0x7F..=0x9F).contains(&ch)
}

/// Count of characters used to encode one unicode char (from leading byte).
#[inline]
fn utf8_encoded_expected_len(c: u8) -> usize {
    if c < 0x80 {
        return 1;
    }
    if (c & 0xe0) == 0xc0 {
        return 2;
    }
    if (c & 0xf0) == 0xe0 {
        return 3;
    }
    if (c & 0xf8) == 0xf0 {
        return 4;
    }
    if (c & 0xfc) == 0xf8 {
        return 5;
    }
    if (c & 0xfe) == 0xfc {
        return 6;
    }
    0
}

/// Decode one unicode char from UTF-8. Returns byte count or `-EINVAL`.
///
/// # Safety
/// `str` must point to a readable sequence at least as long as indicated by
/// its leading byte, and `ret_unichar` must point to writable `u32` storage.
unsafe fn utf8_encoded_to_unichar_inner(str: *const c_char, ret_unichar: *mut u32) -> i32 {
    // SAFETY: this raw-pointer port is one audited FFI operation region; its
    // documented caller contract covers every pointer traversal and C call below.
    unsafe {
        let bytes = str as *const u8;
        let len = utf8_encoded_expected_len(*bytes);

        let unichar = match len {
            1 => *bytes as u32,
            2 => (*bytes as u32) & 0x1f,
            3 => (*bytes as u32) & 0x0f,
            4 => (*bytes as u32) & 0x07,
            5 => (*bytes as u32) & 0x03,
            6 => (*bytes as u32) & 0x01,
            _ => return Errno::EINVAL.to_neg_errno(), // -EINVAL
        };

        let mut acc = unichar;
        for i in 1..len {
            if ((*bytes.add(i)) & 0xc0) != 0x80 {
                return Errno::EINVAL.to_neg_errno();
            }
            acc <<= 6;
            acc |= (*bytes.add(i) as u32) & 0x3f;
        }

        *ret_unichar = acc;
        len as i32
    }
}

/// Expected encoded length from a unicode codepoint.
#[inline]
fn utf8_unichar_to_encoded_len(unichar: u32) -> usize {
    if unichar < 0x80 {
        return 1;
    }
    if unichar < 0x800 {
        return 2;
    }
    if unichar < 0x10000 {
        return 3;
    }
    if unichar < 0x200000 {
        return 4;
    }
    if unichar < 0x4000000 {
        return 5;
    }
    6
}

/// Encode single UCS-4 character as UTF-8 into a u8 buffer.
/// Returns byte count. Writes to out_utf8 if non-null. Does NOT NUL-terminate.
///
/// # Safety
/// When non-null, `out_utf8` must point to at least four writable bytes.
unsafe fn utf8_encode_unichar_raw(out_utf8: *mut u8, g: u32) -> usize {
    // SAFETY: this raw-pointer port is one audited FFI operation region; its
    // documented caller contract covers every pointer traversal and C call below.
    unsafe {
        if g < (1 << 7) {
            if !out_utf8.is_null() {
                *out_utf8 = g as u8;
            }
            1
        } else if g < (1 << 11) {
            if !out_utf8.is_null() {
                *out_utf8 = 0xc0 | ((g >> 6) & 0x1f) as u8;
                *out_utf8.add(1) = 0x80 | (g & 0x3f) as u8;
            }
            2
        } else if g < (1 << 16) {
            if !out_utf8.is_null() {
                *out_utf8 = 0xe0 | ((g >> 12) & 0x0f) as u8;
                *out_utf8.add(1) = 0x80 | ((g >> 6) & 0x3f) as u8;
                *out_utf8.add(2) = 0x80 | (g & 0x3f) as u8;
            }
            3
        } else if g < (1 << 21) {
            if !out_utf8.is_null() {
                *out_utf8 = 0xf0 | ((g >> 18) & 0x07) as u8;
                *out_utf8.add(1) = 0x80 | ((g >> 12) & 0x3f) as u8;
                *out_utf8.add(2) = 0x80 | ((g >> 6) & 0x3f) as u8;
                *out_utf8.add(3) = 0x80 | (g & 0x3f) as u8;
            }
            4
        } else {
            0
        }
    }
}

/// UTF-16 surrogate check.
#[inline]
pub(crate) fn utf16_is_surrogate(c: u16) -> bool {
    (0xD800..=0xDFFF).contains(&c)
}

#[inline]
pub(crate) fn utf16_is_trailing_surrogate(c: u16) -> bool {
    (0xDC00..=0xDFFF).contains(&c)
}

#[inline]
pub(crate) fn utf16_surrogate_pair_to_unichar(lead: u16, trail: u16) -> u32 {
    // The C inline accepts arbitrary char16_t values; its unsigned arithmetic
    // deliberately wraps outside a well-formed surrogate pair. Preserve that
    // defined ABI behaviour without debug-overflow panics crossing an FFI
    // caller that supplies malformed inputs.
    ((u32::from(lead).wrapping_sub(0xD800)) << 10)
        .wrapping_add(u32::from(trail).wrapping_sub(0xDC00))
        .wrapping_add(0x10000)
}

/// Reallocate a C string to its exact occupied size, retaining the original
/// allocation if shrinking fails, as C `str_realloc()` does.
///
/// # Safety
/// `p` must be null or own a live allocation from the C allocator containing
/// a NUL-terminated string of exactly `occupied_size` bytes including its
/// terminator. The returned pointer assumes ownership of `p`.
unsafe fn str_realloc(p: *mut c_char, occupied_size: usize) -> *mut c_char {
    if p.is_null() {
        return ptr::null_mut();
    }

    // SAFETY: ownership of p is transferred to realloc; on failure libc keeps
    // the original allocation live, exactly matching C str_realloc().
    let resized = unsafe { realloc(p.cast(), occupied_size) }.cast::<c_char>();
    if resized.is_null() { p } else { resized }
}

fn calloc_bytes(nmemb: usize, size: usize) -> *mut c_void {
    let total = match nmemb.checked_mul(size) {
        Some(v) => v,
        None => return ptr::null_mut(),
    };

    // SAFETY: malloc accepts the checked finite allocation size.
    let p = malloc(total);
    if p.is_null() {
        return ptr::null_mut();
    }

    // SAFETY: p owns total writable bytes returned by malloc.
    unsafe { ptr::write_bytes(p, 0, total) };
    p
}

/// hexchar equivalent (inline to avoid cross-module dep on hexdecoct).
#[inline]
fn hexchar(x: i32) -> c_char {
    const LOWERCASE_HEXDIGITS: &[u8; 16] = b"0123456789abcdef";
    LOWERCASE_HEXDIGITS[(x as u32 & 0x0f) as usize] as c_char
}

/// Advance past one UTF-8 character (equivalent to utf8_next_char macro).
///
/// # Safety
/// `p` must point to a readable byte. Its leading byte must describe a
/// sequence contained in the same allocation, or be an invalid leading byte
/// for which advancing by one remains within or one byte past the allocation.
#[inline]
unsafe fn utf8_next_char(p: *const c_char) -> *const c_char {
    // SAFETY: this raw-pointer port is one audited FFI operation region; its
    // documented caller contract covers every pointer traversal and C call below.
    unsafe { p.add(utf8_encoded_expected_len(*p as u8).max(1)) }
}

// ── FFI exports ──────────────────────────────────────────────────────────

#[unsafe(no_mangle)]
pub extern "C" fn rs_unichar_is_valid(ch: u32) -> bool {
    if ch >= 0x110000 {
        return false;
    }
    if (ch & 0xFFFFF800) == 0xD800 {
        return false;
    }
    if (ch >= 0xFDD0) && (ch <= 0xFDEF) {
        return false;
    }
    if (ch & 0xFFFE) == 0xFFFE {
        return false;
    }
    true
}

///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_utf8_is_valid_n(str: *const c_char, len_bytes: usize) -> *mut c_char {
    // SAFETY: this raw-pointer port is one audited FFI operation region; its
    // documented caller contract covers every pointer traversal and C call below.
    unsafe {
        if str.is_null() {
            return ptr::null_mut();
        }

        let mut i: usize = 0;
        loop {
            if len_bytes != SIZE_MAX {
                if i >= len_bytes {
                    break;
                }
            } else {
                if *str.add(i) == 0 {
                    break;
                }
            }

            if *str.add(i) == 0 {
                return ptr::null_mut(); // embedded NUL
            }

            let remaining = if len_bytes != SIZE_MAX {
                len_bytes - i
            } else {
                SIZE_MAX
            };
            let len = rs_utf8_encoded_valid_unichar(str.add(i), remaining);
            if len < 0 {
                return ptr::null_mut(); // invalid character
            }

            i += len as usize;
        }

        str as *mut c_char
    }
}

///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_ascii_is_valid_n(str: *const c_char, len: usize) -> *mut c_char {
    // SAFETY: this raw-pointer port is one audited FFI operation region; its
    // documented caller contract covers every pointer traversal and C call below.
    unsafe {
        if str.is_null() {
            return ptr::null_mut();
        }

        let mut i: usize = 0;
        loop {
            if len != SIZE_MAX {
                if i >= len {
                    break;
                }
            } else {
                if *str.add(i) == 0 {
                    break;
                }
            }

            let byte = *str.add(i) as u8;
            if byte >= 128 || byte == 0 {
                return ptr::null_mut();
            }
            i += 1;
        }

        str as *mut c_char
    }
}

///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_utf8_encoded_valid_unichar(str: *const c_char, length: usize) -> i32 {
    // SAFETY: this raw-pointer port is one audited FFI operation region; its
    // documented caller contract covers every pointer traversal and C call below.
    unsafe {
        if str.is_null() || length == 0 {
            return Errno::EINVAL.to_neg_errno();
        }

        let bytes = str as *const u8;
        let len = utf8_encoded_expected_len(*bytes);
        if len == 0 {
            return Errno::EINVAL.to_neg_errno(); // -EINVAL
        }
        if len > length {
            return Errno::EINVAL.to_neg_errno(); // truncated
        }
        if len == 1 {
            return 1; // ASCII is always valid
        }

        // Check continuation bytes have high bit set
        for i in 0..len {
            if (bytes.add(i).read() & 0x80) != 0x80 {
                return Errno::EINVAL.to_neg_errno();
            }
        }

        let mut unichar: u32 = 0;
        let r = utf8_encoded_to_unichar_inner(str, &mut unichar);
        if r < 0 {
            return r;
        }

        // Check encoded length matches value
        if utf8_unichar_to_encoded_len(unichar) != len {
            return Errno::EINVAL.to_neg_errno();
        }

        if !rs_unichar_is_valid(unichar) {
            return Errno::EINVAL.to_neg_errno();
        }

        len as i32
    }
}

///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_utf8_encoded_to_unichar(
    str: *const c_char,
    ret_unichar: *mut u32,
) -> i32 {
    // SAFETY: this raw-pointer port is one audited FFI operation region; its
    // documented caller contract covers every pointer traversal and C call below.
    unsafe { utf8_encoded_to_unichar_inner(str, ret_unichar) }
}

///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_utf8_to_ascii(
    str: *const c_char,
    replacement_char: c_char,
    ret: *mut *mut c_char,
) -> i32 {
    // SAFETY: this raw-pointer port is one audited FFI operation region; its
    // documented caller contract covers every pointer traversal and C call below.
    unsafe {
        let s = CStr::from_ptr(str);
        let byte_len = s.to_bytes().len();

        let Some(allocation_size) = byte_len.checked_add(1) else {
            return Errno::ENOMEM.to_neg_errno();
        };
        let ans = malloc(allocation_size);
        if ans.is_null() {
            return Errno::ENOMEM.to_neg_errno(); // -ENOMEM
        }

        let ans = ans as *mut c_char;
        let mut q = ans;
        let mut p = str;

        while *p != 0 {
            let remaining = SIZE_MAX;
            let l = rs_utf8_encoded_valid_unichar(p, remaining);
            if l < 0 {
                free(ans as *mut c_void); // match C's _cleanup_free_
                return l; // propagate error
            }

            if l == 1 {
                *q = *p;
            } else {
                *q = replacement_char as c_char;
            }
            q = q.add(1);
            p = p.add(l as usize);
        }
        *q = 0;

        *ret = ans as *mut c_char;
        0
    }
}

///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_utf8_escape_invalid(str: *const c_char) -> *mut c_char {
    // SAFETY: this raw-pointer port is one audited FFI operation region; its
    // documented caller contract covers every pointer traversal and C call below.
    unsafe {
        let s = CStr::from_ptr(str);
        let byte_len = s.to_bytes().len();

        // Worst case: every byte becomes UTF8_REPLACEMENT_CHARACTER (3 bytes) + NUL
        let Some(allocation_size) = byte_len
            .checked_mul(UTF8_REPLACEMENT_CHARACTER.len())
            .and_then(|size| size.checked_add(1))
        else {
            return ptr::null_mut();
        };
        let p = malloc(allocation_size);
        if p.is_null() {
            return ptr::null_mut();
        }

        let mut t = p as *mut u8;
        let mut pos = str;

        while *pos != 0 {
            let remaining = SIZE_MAX;
            let len = rs_utf8_encoded_valid_unichar(pos, remaining);
            if len > 0 {
                // Copy valid UTF-8 bytes
                for i in 0..len as usize {
                    *t.add(i) = *pos.add(i) as u8;
                }
                t = t.add(len as usize);
                pos = pos.add(len as usize);
            } else {
                // Replace with U+FFFD
                *t = UTF8_REPLACEMENT_CHARACTER[0];
                *t.add(1) = UTF8_REPLACEMENT_CHARACTER[1];
                *t.add(2) = UTF8_REPLACEMENT_CHARACTER[2];
                t = t.add(3);
                pos = pos.add(1);
            }
        }
        *t = 0;

        let occupied_size = t.offset_from(p.cast::<u8>()) as usize + 1;
        str_realloc(p as *mut c_char, occupied_size)
    }
}

///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_utf8_is_printable_newline(
    str: *const c_char,
    length: usize,
    allow_newline: bool,
) -> bool {
    // SAFETY: this raw-pointer port is one audited FFI operation region; its
    // documented caller contract covers every pointer traversal and C call below.
    unsafe {
        if str.is_null() {
            return false;
        }

        let mut remaining = length;
        let mut p = str;

        while remaining > 0 {
            let encoded_len = rs_utf8_encoded_valid_unichar(p, remaining);
            if encoded_len < 0 {
                return false;
            }

            let mut val: u32 = 0;
            if utf8_encoded_to_unichar_inner(p, &mut val) < 0 || unichar_is_control(val) {
                return false;
            }
            if !allow_newline && val == 0x0A {
                return false;
            }

            remaining -= encoded_len as usize;
            p = p.add(encoded_len as usize);
        }

        true
    }
}

///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_utf8_char_console_width(str: *const c_char) -> i32 {
    // SAFETY: this raw-pointer port is one audited FFI operation region; its
    // documented caller contract covers every pointer traversal and C call below.
    unsafe {
        let mut c: u32 = 0;
        let r = utf8_encoded_to_unichar_inner(str, &mut c);
        if r < 0 {
            return r;
        }

        if c == 0x09 {
            return 8; // tab width
        }

        if unichar_iswide(c) { 2 } else { 1 }
    }
}

///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_utf8_escape_non_printable_full(
    str: *const c_char,
    console_width: usize,
    force_ellipsis: bool,
) -> *mut c_char {
    // SAFETY: this raw-pointer port is one audited FFI operation region; its
    // documented caller contract covers every pointer traversal and C call below.
    unsafe {
        if console_width == 0 {
            let s = malloc(1);
            if s.is_null() {
                return ptr::null_mut();
            }
            *(s as *mut u8) = 0;
            return s as *mut c_char;
        }

        let s = CStr::from_ptr(str);
        let byte_len = s.to_bytes().len();
        // Worst case: each byte becomes \xHH (4 bytes) + ellipsis + NUL
        let Some(allocation_size) = byte_len
            .checked_mul(4)
            .and_then(|size| size.checked_add(UTF8_REPLACEMENT_CHARACTER.len() + 1))
        else {
            return ptr::null_mut();
        };
        let p = malloc(allocation_size);
        if p.is_null() {
            return ptr::null_mut();
        }

        let mut t = p as *mut u8;
        let mut pos = str;
        let mut n: usize = 0;
        let mut prev_t = t;

        'outer: loop {
            let saved_t = t;

            if *pos == 0 {
                if force_ellipsis {
                    // truncation
                    if n + 1 > console_width {
                        t = prev_t;
                    }
                    // ellipsis … = E2 80 A6
                    *t = 0xE2;
                    *t.add(1) = 0x80;
                    *t.add(2) = 0xA6;
                    t = t.add(3);
                }
                break;
            }

            let remaining = SIZE_MAX;
            let len = rs_utf8_encoded_valid_unichar(pos, remaining);
            if len > 0 {
                // Check if printable
                let printable = rs_utf8_is_printable_newline(pos, len as usize, true);
                if printable {
                    let w = rs_utf8_char_console_width(pos);
                    if w >= 0 && (n + w as usize) > console_width {
                        // truncation
                        if n + 1 > console_width {
                            t = prev_t;
                        }
                        *t = 0xE2;
                        *t.add(1) = 0x80;
                        *t.add(2) = 0xA6;
                        t = t.add(3);
                        break;
                    }
                    // Copy valid UTF-8 bytes
                    for i in 0..len as usize {
                        *t.add(i) = *pos.add(i) as u8;
                    }
                    t = t.add(len as usize);
                    pos = pos.add(len as usize);
                    n += w as usize;
                } else {
                    // Escape each byte as \xHH
                    for _ in 0..len {
                        if n + 4 > console_width {
                            // truncation
                            if n + 1 > console_width {
                                t = prev_t;
                            }
                            *t = 0xE2;
                            *t.add(1) = 0x80;
                            *t.add(2) = 0xA6;
                            t = t.add(3);
                            break 'outer;
                        }
                        *t = b'\\';
                        *t.add(1) = b'x';
                        *t.add(2) = hexchar((*pos >> 4) as i32) as u8;
                        *t.add(3) = hexchar((*pos) as i32) as u8;
                        t = t.add(4);
                        pos = pos.add(1);
                        n += 4;
                    }
                }
            } else {
                // Invalid byte: replace with U+FFFD
                if n + 1 > console_width {
                    // truncation
                    if n + 1 > console_width {
                        t = prev_t;
                    }
                    *t = 0xE2;
                    *t.add(1) = 0x80;
                    *t.add(2) = 0xA6;
                    t = t.add(3);
                    break;
                }
                *t = UTF8_REPLACEMENT_CHARACTER[0];
                *t.add(1) = UTF8_REPLACEMENT_CHARACTER[1];
                *t.add(2) = UTF8_REPLACEMENT_CHARACTER[2];
                t = t.add(3);
                pos = pos.add(1);
                n += 1;
            }

            prev_t = saved_t;
        }

        *t = 0;
        let occupied_size = t.offset_from(p.cast::<u8>()) as usize + 1;
        str_realloc(p as *mut c_char, occupied_size)
    }
}

///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_utf8_encode_unichar(out_utf8: *mut c_char, g: u32) -> usize {
    // SAFETY: this raw-pointer port is one audited FFI operation region; its
    // documented caller contract covers every pointer traversal and C call below.
    unsafe { utf8_encode_unichar_raw(out_utf8 as *mut u8, g) }
}

///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_utf16_encode_unichar(out: *mut u16, c: u32) -> usize {
    // SAFETY: this raw-pointer port is one audited FFI operation region; its
    // documented caller contract covers every pointer traversal and C call below.
    unsafe {
        match c {
            0..=0xD7FF | 0xE000..=0xFFFF => {
                *out = (c as u16).to_le();
                1
            }
            0x10000..=0x10FFFF => {
                let adjusted = c - 0x10000;
                *out = ((adjusted >> 10) as u16 + 0xD800).to_le();
                *out.add(1) = ((adjusted & 0x3FF) as u16 + 0xDC00).to_le();
                2
            }
            _ => 0, // invalid (surrogate)
        }
    }
}

///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_utf16_to_utf8(s: *const u16, length: usize) -> *mut c_char {
    // SAFETY: this raw-pointer port is one audited FFI operation region; its
    // documented caller contract covers every pointer traversal and C call below.
    unsafe {
        if length == 0 {
            let r = calloc_bytes(1, 1);
            return r as *mut c_char;
        }

        if s.is_null() {
            return ptr::null_mut();
        }

        let effective_length = if length == SIZE_MAX {
            let words = rs_char16_strlen(s);
            if words > SIZE_MAX / 2 {
                return ptr::null_mut();
            }
            words * 2
        } else {
            length
        };

        if effective_length > (SIZE_MAX - 1) / 2 {
            return ptr::null_mut();
        }

        let r = malloc(effective_length * 2 + 1);
        if r.is_null() {
            return ptr::null_mut();
        }

        let f = s as *const u8;
        let end = f.add(effective_length);
        let mut t = r as *mut u8;

        let mut pos = f;
        while pos.add(1) < end {
            let w1 = (pos.add(1).read() as u16) << 8 | pos.read() as u16;
            pos = pos.add(2);

            if !utf16_is_surrogate(w1) {
                t = t.add(utf8_encode_unichar_raw(t, w1 as u32));
                continue;
            }

            if utf16_is_trailing_surrogate(w1) {
                continue; // spurious trailing surrogate
            }

            if pos.add(1) >= end {
                break;
            }

            let w2 = (pos.add(1).read() as u16) << 8 | pos.read() as u16;
            pos = pos.add(2);

            if !utf16_is_trailing_surrogate(w2) {
                pos = pos.sub(2); // missing trailing surrogate
                continue;
            }

            t = t.add(utf8_encode_unichar_raw(
                t,
                utf16_surrogate_pair_to_unichar(w1, w2),
            ));
        }

        *t = 0;
        r as *mut c_char
    }
}

///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_utf8_to_utf16(s: *const c_char, length: usize) -> *mut u16 {
    // SAFETY: this raw-pointer port is one audited FFI operation region; its
    // documented caller contract covers every pointer traversal and C call below.
    unsafe {
        if length == 0 {
            let r = calloc_bytes(1, std::mem::size_of::<u16>());
            return r as *mut u16;
        }

        if s.is_null() {
            return ptr::null_mut();
        }

        let effective_length = if length == SIZE_MAX {
            CStr::from_ptr(s).to_bytes().len()
        } else {
            length
        };

        if effective_length > SIZE_MAX - 1 {
            return ptr::null_mut();
        }

        let Some(allocation_size) = effective_length
            .checked_add(1)
            .and_then(|words| words.checked_mul(std::mem::size_of::<u16>()))
        else {
            return ptr::null_mut();
        };
        let n = malloc(allocation_size);
        if n.is_null() {
            return ptr::null_mut();
        }

        let p = n as *mut u16;
        let mut q = p;
        let bytes = s as *const u8;
        let mut i: usize = 0;

        while i < effective_length {
            let e = utf8_encoded_expected_len(*bytes.add(i));
            if e <= 1 || i + e > effective_length {
                // Invalid or truncated — copy as-is
                *q = (*s.add(i) as u16).to_le();
                i += 1;
                q = q.add(1);
                continue;
            }

            let mut unichar: u32 = 0;
            let r = utf8_encoded_to_unichar_inner(s.add(i), &mut unichar);
            if r < 0 {
                // Invalid sequence — copy as-is
                *q = (*s.add(i) as u16).to_le();
                i += 1;
                q = q.add(1);
                continue;
            }

            let encoded = rs_utf16_encode_unichar(q, unichar);
            q = q.add(encoded);
            i += e;
        }

        *q = 0;
        n as *mut u16
    }
}

///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_char16_strlen(s: *const u16) -> usize {
    // SAFETY: this raw-pointer port is one audited FFI operation region; its
    // documented caller contract covers every pointer traversal and C call below.
    unsafe {
        if s.is_null() {
            return 0;
        }
        let mut n: usize = 0;
        let mut p = s;
        while *p != 0 {
            n += 1;
            p = p.add(1);
        }
        n
    }
}

///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_char16_strsize(s: *const u16) -> usize {
    // SAFETY: this raw-pointer port is one audited FFI operation region; its
    // documented caller contract covers every pointer traversal and C call below.
    unsafe {
        if s.is_null() {
            return 0;
        }
        (rs_char16_strlen(s) + 1) * std::mem::size_of::<u16>()
    }
}

///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_utf8_n_codepoints(str: *const c_char) -> usize {
    // SAFETY: this raw-pointer port is one audited FFI operation region; its
    // documented caller contract covers every pointer traversal and C call below.
    unsafe {
        let mut n: usize = 0;
        let mut p = str;

        while *p != 0 {
            let k = rs_utf8_encoded_valid_unichar(p, SIZE_MAX);
            if k < 0 {
                return SIZE_MAX;
            }
            p = p.add(k as usize);
            n += 1;
        }

        n
    }
}

///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_utf8_console_width(str: *const c_char) -> usize {
    // SAFETY: this raw-pointer port is one audited FFI operation region; its
    // documented caller contract covers every pointer traversal and C call below.
    unsafe {
        if str.is_null() || *str == 0 {
            return 0;
        }

        let mut n: usize = 0;
        let mut p = str;

        while *p != 0 {
            let w = rs_utf8_char_console_width(p);
            if w < 0 {
                return SIZE_MAX;
            }
            n += w as usize;
            p = utf8_next_char(p);
        }

        n
    }
}

///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_utf8_last_length(s: *const c_char, n: usize) -> usize {
    // SAFETY: this raw-pointer port is one audited FFI operation region; its
    // documented caller contract covers every pointer traversal and C call below.
    unsafe {
        if s.is_null() {
            return 0;
        }

        let mut remaining = if n == SIZE_MAX {
            CStr::from_ptr(s).to_bytes().len()
        } else {
            n
        };

        let mut p = s;
        let mut last: usize = 0;

        loop {
            if remaining == 0 {
                return last;
            }

            let r = rs_utf8_encoded_valid_unichar(p, remaining);
            let step = if r <= 0 { 1 } else { r as usize };
            p = p.add(step);
            remaining -= step;
            last = step;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    #[test]
    fn utf8_validation_accepts_valid_and_rejects_invalid() {
        let valid = CString::new("hello").unwrap();
        // SAFETY: the raw pointer is derived from a live allocation and is used only for the duration of this operation.
        assert!(!unsafe { rs_utf8_is_valid_n(valid.as_ptr(), 5) }.is_null());

        let invalid = [0xF0u8, 0x28, 0x8C, 0x28, 0];
        // SAFETY: the raw pointer is derived from a live allocation and is used only for the duration of this operation.
        assert!(
            unsafe { rs_utf8_is_valid_n(invalid.as_ptr() as *const c_char, invalid.len() - 1) }
                .is_null()
        );
    }

    #[test]
    fn utf8_encoded_valid_unichar_has_positive_and_negative_case() {
        let e_acute = CString::new("é").unwrap();
        assert_eq!(
            // SAFETY: the raw pointer is derived from a live allocation and is used only for the duration of this operation.
            unsafe { rs_utf8_encoded_valid_unichar(e_acute.as_ptr(), 2) },
            2
        );

        let bad = [0x80u8, 0];
        // SAFETY: the raw pointer is derived from a live allocation and is used only for the duration of this operation.
        assert!(unsafe { rs_utf8_encoded_valid_unichar(bad.as_ptr() as *const c_char, 1) } < 0);
    }
}
