// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/basic/string-util.c, src/basic/escape.c, src/basic/utf8.c
//
// Byte-oriented rendering, extension, and explicit erasure. The policy cores
// operate on borrowed byte slices; the few raw-pointer adapters are confined
// to the C ABI and C allocator boundary.

// Centralized unsafe expression boundary for this module.
macro_rules! unsafe_ffi {
    ($expression:expr) => {{
        // SAFETY: the enclosing helper documents and validates this operation.
        unsafe { $expression }
    }};
}
use std::ffi::{CStr, c_void};

use libc::c_char;

use crate::ffi::{malloc, realloc};

const XESCAPE_8_BIT: i32 = 1 << 0;
const XESCAPE_FORCE_ELLIPSIS: i32 = 1 << 1;
const UTF8_ELLIPSIS: &[u8] = b"\xe2\x80\xa6";
const ASCII_ELLIPSIS: &[u8] = b"...";

// SAFETY: this declares the exact C ABI of the locale helper. It has no
// pointer, ownership, or lifetime arguments; callers rely only on its boolean
// result while the linked C implementation retains its locale state.
unsafe extern "C" {
    /// Current C locale policy, including systemd's environment, thread, and
    /// cache behavior. `cellescape()` uses the same policy through
    /// `glyph_full(GLYPH_ELLIPSIS, false)`.
    fn is_locale_utf8() -> bool;
}

#[inline]
fn cellescape_ellipsis() -> &'static [u8] {
    // SAFETY: the C helper takes no pointers and returns its cached locale
    // policy. Reusing it avoids a second, subtly divergent locale implementation.
    if unsafe_ffi!(is_locale_utf8()) {
        UTF8_ELLIPSIS
    } else {
        ASCII_ELLIPSIS
    }
}

fn try_bytes(capacity: usize) -> Result<Vec<u8>, ()> {
    let mut output = Vec::new();
    output.try_reserve_exact(capacity).map_err(|_| ())?;
    Ok(output)
}

fn hexchar(nibble: u8) -> u8 {
    match nibble {
        0..=9 => b'0' + nibble,
        _ => b'a' + (nibble - 10),
    }
}

fn cescape_byte(byte: u8) -> ([u8; 4], usize) {
    match byte {
        0x07 => (*b"\\a\0\0", 2),
        0x08 => (*b"\\b\0\0", 2),
        0x0c => (*b"\\f\0\0", 2),
        0x0a => (*b"\\n\0\0", 2),
        0x0d => (*b"\\r\0\0", 2),
        0x09 => (*b"\\t\0\0", 2),
        0x0b => (*b"\\v\0\0", 2),
        b'\\' => (*b"\\\\\0\0", 2),
        b'\"' => (*b"\\\"\0\0", 2),
        b'\'' => (*b"\\'\0\0", 2),
        0x00..=0x1f | 0x7f..=0xff => (
            [
                b'\\',
                b'0' + (byte >> 6),
                b'0' + ((byte >> 3) & 7),
                b'0' + (byte & 7),
            ],
            4,
        ),
        _ => ([byte, 0, 0, 0], 1),
    }
}

/// Render the current C `cellescape()` policy into an already-sized buffer.
fn cellescape_bytes(buffer: &mut [u8], input: &[u8]) {
    debug_assert!(!buffer.is_empty());

    let mut written = 0;
    let mut recent_widths = [0usize; 4];
    let mut ring_index = 0;

    for &byte in input {
        let (escaped, width) = cescape_byte(byte);
        if width > buffer.len() - written - 1 {
            for _ in 0..recent_widths.len() {
                if buffer.len() - written >= 4 {
                    break;
                }
                ring_index = if ring_index == 0 { 3 } else { ring_index - 1 };
                let previous_width = recent_widths[ring_index];
                if previous_width == 0 {
                    break;
                }
                written -= previous_width;
            }

            match buffer.len() - written {
                4.. => {
                    let ellipsis = cellescape_ellipsis();
                    buffer[written..written + ellipsis.len()].copy_from_slice(ellipsis);
                    written += ellipsis.len();
                }
                3 => {
                    buffer[written..written + 2].copy_from_slice(b"..");
                    written += 2;
                }
                2 => {
                    buffer[written] = b'.';
                    written += 1;
                }
                _ => {}
            }
            buffer[written] = 0;
            return;
        }

        buffer[written..written + width].copy_from_slice(&escaped[..width]);
        written += width;
        recent_widths[ring_index] = width;
        ring_index = (ring_index + 1) % recent_widths.len();
    }

    buffer[written] = 0;
}

/// Validate one scalar using the same pre-Unicode UTF-8 rules as utf8.c.
///
/// This deliberately operates on bytes rather than `str`: current C rejects
/// overlong encodings, surrogates, and Unicode noncharacters, while its
/// callers may provide arbitrary non-NUL bytes.
pub(crate) fn valid_utf8_character(bytes: &[u8]) -> Option<(usize, u32)> {
    let first = *bytes.first()?;
    let length = match first {
        0x00..=0x7f => 1,
        0xc0..=0xdf => 2,
        0xe0..=0xef => 3,
        0xf0..=0xf7 => 4,
        // Current C accepts these prefixes initially, but all five/six-byte
        // sequences fail its canonical-length and Unicode-range checks.
        0xf8..=0xfd => return None,
        _ => return None,
    };
    if bytes.len() < length || bytes[1..length].iter().any(|byte| byte & 0xc0 != 0x80) {
        return None;
    }

    let mut codepoint = match length {
        1 => first as u32,
        2 => (first & 0x1f) as u32,
        3 => (first & 0x0f) as u32,
        4 => (first & 0x07) as u32,
        _ => unreachable!(),
    };
    for &byte in &bytes[1..length] {
        codepoint = (codepoint << 6) | u32::from(byte & 0x3f);
    }

    let shortest_length = match codepoint {
        0..=0x7f => 1,
        0x80..=0x7ff => 2,
        0x800..=0xffff => 3,
        _ => 4,
    };
    if shortest_length != length
        || codepoint >= 0x110000
        || (0xd800..=0xdfff).contains(&codepoint)
        || (0xfdd0..=0xfdef).contains(&codepoint)
        || codepoint & 0xfffe == 0xfffe
    {
        return None;
    }
    Some((length, codepoint))
}

fn unichar_is_control(codepoint: u32) -> bool {
    (codepoint < 0x20 && codepoint != 0x09 && codepoint != 0x0a)
        || (0x7f..=0x9f).contains(&codepoint)
}

fn console_width(valid_character: &[u8]) -> usize {
    // SAFETY: `valid_character` was accepted by `valid_utf8_character`, so it
    // has every byte that this raw helper reads and the helper returns a
    // non-negative width for valid input.
    let width = unsafe_ffi!({
        crate::utf8::rs_utf8_char_console_width(valid_character.as_ptr().cast::<c_char>())
    });
    debug_assert!(width >= 0);
    width as usize
}

/// Safe, byte-preserving implementation of `xescape_full(..., NULL, ...)`.
fn try_xescape_without_bad(input: &[u8], console_width: usize, flags: i32) -> Result<Vec<u8>, ()> {
    if console_width == 0 {
        return Ok(Vec::new());
    }

    let force_ellipsis = flags & XESCAPE_FORCE_ELLIPSIS != 0;
    let forced = usize::from(force_ellipsis) * 3;
    let mut body = console_width.min(usize::MAX - 1);
    if body > forced && input.len() <= (body - forced) / 4 {
        body = input
            .len()
            .checked_mul(4)
            .and_then(|length| length.checked_add(forced))
            .ok_or(())?;
    }
    let mut output = try_bytes(body)?;
    let allow_8_bit = flags & XESCAPE_8_BIT != 0;
    let mut previous = 0;
    let mut previous_previous = 0;

    for &byte in input {
        let start = output.len();
        let escaped = byte < b' ' || (!allow_8_bit && byte >= 127) || byte == b'\\';
        let required = if escaped { 4 } else { 1 };
        if body.saturating_sub(start) < required + forced {
            let dots = body.min(3);
            let offset = if body - dots >= start {
                start
            } else if body - dots >= previous {
                previous
            } else if body - dots >= previous_previous {
                previous_previous
            } else {
                body - dots
            };
            output.truncate(offset);
            output.extend_from_slice(&b"..."[..dots]);
            return Ok(output);
        }
        if escaped {
            output.extend_from_slice(&[b'\\', b'x', hexchar(byte >> 4), hexchar(byte & 0x0f)]);
        } else {
            output.push(byte);
        }
        previous_previous = previous;
        previous = start;
    }

    if force_ellipsis {
        let dots = body.min(3);
        let start = output.len();
        let offset = if body - dots >= start {
            start
        } else if body - dots >= previous {
            previous
        } else if body - dots >= previous_previous {
            previous_previous
        } else {
            body - dots
        };
        output.truncate(offset);
        output.extend_from_slice(&b"..."[..dots]);
    }
    Ok(output)
}

/// Safe, byte-preserving implementation of `utf8_escape_non_printable_full`.
pub(crate) fn try_utf8_escape_non_printable(
    input: &[u8],
    max_width: usize,
    force_ellipsis: bool,
) -> Result<Vec<u8>, ()> {
    if max_width == 0 {
        return Ok(Vec::new());
    }
    let capacity = input
        .len()
        .checked_mul(4)
        .and_then(|size| size.checked_add(3))
        .ok_or(())?;
    let mut output = try_bytes(capacity)?;
    let mut input_index = 0;
    let mut display_width: usize = 0;
    let mut previous = 0;

    loop {
        let start = output.len();
        if input_index == input.len() {
            if !force_ellipsis {
                return Ok(output);
            }
            if display_width
                .checked_add(1)
                .is_none_or(|width| width > max_width)
            {
                output.truncate(previous);
            }
            output.extend_from_slice(UTF8_ELLIPSIS);
            return Ok(output);
        }

        if let Some((length, codepoint)) = valid_utf8_character(&input[input_index..]) {
            let character = &input[input_index..input_index + length];
            if !unichar_is_control(codepoint) {
                let width = console_width(character);
                if display_width
                    .checked_add(width)
                    .is_none_or(|total| total > max_width)
                {
                    if display_width
                        .checked_add(1)
                        .is_none_or(|total| total > max_width)
                    {
                        output.truncate(previous);
                    }
                    output.extend_from_slice(UTF8_ELLIPSIS);
                    return Ok(output);
                }
                output.extend_from_slice(character);
                input_index += length;
                display_width = display_width.checked_add(width).ok_or(())?;
            } else {
                for _ in 0..length {
                    if display_width
                        .checked_add(4)
                        .is_none_or(|total| total > max_width)
                    {
                        if display_width
                            .checked_add(1)
                            .is_none_or(|total| total > max_width)
                        {
                            output.truncate(previous);
                        }
                        output.extend_from_slice(UTF8_ELLIPSIS);
                        return Ok(output);
                    }
                    let byte = input[input_index];
                    output.extend_from_slice(&[
                        b'\\',
                        b'x',
                        hexchar(byte >> 4),
                        hexchar(byte & 0x0f),
                    ]);
                    input_index += 1;
                    display_width = display_width.checked_add(4).ok_or(())?;
                }
            }
        } else {
            if display_width
                .checked_add(1)
                .is_none_or(|total| total > max_width)
            {
                if display_width
                    .checked_add(1)
                    .is_none_or(|total| total > max_width)
                {
                    output.truncate(previous);
                }
                output.extend_from_slice(UTF8_ELLIPSIS);
                return Ok(output);
            }
            output.extend_from_slice(b"\xef\xbf\xbd");
            input_index += 1;
            display_width = display_width.checked_add(1).ok_or(())?;
        }
        previous = start;
    }
}

fn malloc_c_string(bytes: &[u8]) -> *mut c_char {
    let Some(allocation_size) = bytes.len().checked_add(1) else {
        return std::ptr::null_mut();
    };
    let output = malloc(allocation_size).cast::<c_char>();
    if output.is_null() {
        return std::ptr::null_mut();
    }
    // SAFETY: `output` owns `bytes.len() + 1` C-allocator bytes.
    unsafe_ffi!({
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), output.cast::<u8>(), bytes.len());
        *output.add(bytes.len()) = 0;
    });
    output
}

/// C `cellescape()`: escape and ellipsize `s` into `buf` of size `len`.
///
/// # Safety
/// `buf` must be non-null and writable for `len > 0` bytes. `s` must be a
/// non-null readable NUL-terminated byte string.
pub unsafe fn rs_cellescape(buf: *mut c_char, len: usize, s: *const c_char) -> *mut c_char {
    if buf.is_null() || len == 0 || s.is_null() {
        return std::ptr::null_mut();
    }
    // SAFETY: the caller supplies a readable NUL-terminated input string.
    let input = unsafe_ffi!(CStr::from_ptr(s)).to_bytes();
    // SAFETY: the caller supplies a writable `len`-byte output range.
    let output = unsafe_ffi!(std::slice::from_raw_parts_mut(buf.cast::<u8>(), len));
    cellescape_bytes(output, input);
    buf
}

/// C `string_erase()`: erase visible bytes using the same explicit-bzero
/// primitive as the current C implementation.
///
/// # Safety
/// `x` must be null or a writable NUL-terminated byte string.
pub unsafe fn rs_string_erase(x: *mut c_char) -> *mut c_char {
    if x.is_null() {
        return std::ptr::null_mut();
    }
    // SAFETY: the caller supplies a readable NUL-terminated string.
    let length = unsafe_ffi!(CStr::from_ptr(x)).to_bytes().len();
    if length > 0 {
        // SAFETY: `x` is writable for its visible C-string bytes. libc's
        // explicit_bzero is specifically specified not to be optimized away.
        unsafe_ffi!(libc::explicit_bzero(x.cast::<c_void>(), length));
    }
    x
}

/// C `strextendn()`: append at most `l` bytes, stopping at the source NUL.
///
/// # Safety
/// `x` must be non-null and writable for one pointer whose current value is
/// null or uniquely-owned C-allocator storage containing a NUL-terminated
/// string. For non-zero `l`, `s` must be readable through its first NUL or for
/// `l` bytes, whichever comes first, and must not alias the allocation
/// currently held in `*x`.
pub unsafe fn rs_strextendn(x: *mut *mut c_char, s: *const c_char, l: usize) -> *mut c_char {
    if x.is_null() || (s.is_null() && l > 0) {
        return std::ptr::null_mut();
    }
    let mut append_length = 0usize;
    while append_length < l {
        // SAFETY: the contract guarantees each byte through the first NUL or
        // all `l` bytes is readable.
        if unsafe_ffi!(*s.add(append_length)) == 0 {
            break;
        }
        append_length += 1;
    }
    let append = if append_length == 0 {
        &[][..]
    } else {
        // SAFETY: the bounded scan above established this exact non-empty
        // readable prefix, which also proves `s` is non-null.
        unsafe_ffi!(std::slice::from_raw_parts(s.cast::<u8>(), append_length))
    };
    // SAFETY: `x` is writable for one pointer by the function contract.
    let current = unsafe_ffi!(*x);
    let existing_length = if current.is_null() {
        0
    } else {
        // SAFETY: non-null `*x` is a readable NUL-terminated C allocation.
        unsafe_ffi!(CStr::from_ptr(current)).to_bytes().len()
    };
    if append.is_empty() && !current.is_null() {
        return current;
    }
    let Some(allocation_size) = existing_length
        .checked_add(append.len())
        .and_then(|length| length.checked_add(1))
    else {
        return std::ptr::null_mut();
    };
    // SAFETY: `current` is null or a unique C allocation. The C `realloc`
    // contract leaves it intact when allocation fails.
    let replacement =
        unsafe_ffi!(realloc(current.cast::<c_void>(), allocation_size)).cast::<c_char>();
    if replacement.is_null() {
        return std::ptr::null_mut();
    }
    // SAFETY: `replacement` has the checked allocation size and `append` does
    // not alias it by this function's contract.
    unsafe_ffi!({
        std::ptr::copy_nonoverlapping(
            append.as_ptr(),
            replacement.add(existing_length).cast::<u8>(),
            append.len(),
        );
        *replacement.add(existing_length + append.len()) = 0;
        *x = replacement;
    });
    replacement
}

/// C `escape_non_printable_full()` with the current `XEscapeFlags` bit ABI.
///
/// # Safety
/// `str` must be a non-null readable NUL-terminated byte string. The result
/// is either null on allocation failure or a fresh C-allocator string owned by
/// the caller and released with `free(3)`.
pub unsafe fn rs_escape_non_printable_full(
    str_: *const c_char,
    console_width: usize,
    flags: i32,
) -> *mut c_char {
    if str_.is_null() {
        return std::ptr::null_mut();
    }
    // SAFETY: the caller supplies a readable NUL-terminated byte string.
    let input = unsafe_ffi!(CStr::from_ptr(str_)).to_bytes();
    let escaped = if flags & XESCAPE_8_BIT != 0 {
        try_xescape_without_bad(input, console_width, flags)
    } else {
        try_utf8_escape_non_printable(input, console_width, flags & XESCAPE_FORCE_ELLIPSIS != 0)
    };
    match escaped {
        Ok(bytes) => malloc_c_string(&bytes),
        Err(()) => std::ptr::null_mut(),
    }
}
