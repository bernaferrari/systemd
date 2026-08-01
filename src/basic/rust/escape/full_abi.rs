// SPDX-License-Identifier: LGPL-2.1-or-later
//
// Exact byte-oriented C ABI adapters for the allocating escape helpers.
//
// The implementations keep C strings and `char **` ownership at this small
// edge.  The escaping, unescaping, and quoting policies operate on safe byte
// slices and create a fresh C-allocator result only after they succeed.

// Centralized unsafe expression boundary for this module.
macro_rules! unsafe_ffi {
    ($expression:expr) => {{
        // SAFETY: the enclosing helper documents and validates this operation.
        unsafe { $expression }
    }};
}
use libc::c_char;
use std::ffi::CStr;
use std::ptr;

use super::{
    EINVAL, UnescapeFlags, append_cescape_char, char_is_cc, hexchar, malloc_c_string,
    try_cunescape_bytes, utf8_encoded_valid_unichar,
};

const ENOMEM: isize = -12;
const XESCAPE_8_BIT: u32 = 1 << 0;
const XESCAPE_FORCE_ELLIPSIS: u32 = 1 << 1;
const SHELL_ESCAPE_POSIX: u32 = 1 << 1;
const SHELL_ESCAPE_EMPTY: u32 = 1 << 2;
// Exact concatenation of fundamental/string-util.h's WHITESPACE and
// escape.h's SHELL_NEED_QUOTES. Keep this byte set rather than inferring shell
// syntax from Unicode or Rust's whitespace classifications: current C uses
// `strchr(WHITESPACE SHELL_NEED_QUOTES, *p)`.
const SHELL_QUOTE_BYTES: &[u8] = b" \t\n\r\"\\`$*?['()<>|&;!";

/// Reserve exactly enough capacity for an output constructed entirely from
/// safe bytes. Allocation failure is returned to the ABI shell as NULL or
/// -ENOMEM rather than panicking across C.
fn try_byte_buffer(capacity: usize) -> Result<Vec<u8>, ()> {
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(capacity).map_err(|_| ())?;
    Ok(bytes)
}

/// C's `cunescape_length_with_prefix()` algorithm on byte slices.
///
/// The current C implementation allocates `prefix.len() + source.len() + 1`.
/// The Rust result leaves out that final terminator because `malloc_c_string()`
/// supplies it at the ownership edge.
fn try_cunescape_with_prefix(source: &[u8], prefix: &[u8], flags: u32) -> Result<Vec<u8>, isize> {
    try_cunescape_bytes(source, prefix, UnescapeFlags::from_bits_retain(flags))
        .map_err(|error| error as isize)
}

/// C's `xescape_full()` on arbitrary C-string bytes.
fn try_xescape_full(
    source: &[u8],
    bad: Option<&[u8]>,
    console_width: usize,
    flags: u32,
) -> Result<Vec<u8>, ()> {
    if console_width == 0 {
        return Ok(Vec::new());
    }

    let forced_ellipsis = flags & XESCAPE_FORCE_ELLIPSIS != 0;
    let ellipsis_length = usize::from(forced_ellipsis) * 3;
    let mut body_length = console_width.min(usize::MAX - 1);
    if body_length > ellipsis_length && source.len() <= (body_length - ellipsis_length) / 4 {
        body_length = source
            .len()
            .checked_mul(4)
            .and_then(|length| length.checked_add(ellipsis_length))
            .ok_or(())?;
    }

    // C allocates `body_length + 1`; the final byte is installed by
    // `malloc_c_string()` after this safe byte construction is complete.
    let allocation = body_length.checked_add(1).ok_or(())?;
    let mut result = try_byte_buffer(allocation)?;
    let allow_8_bit = flags & XESCAPE_8_BIT != 0;
    let mut previous = 0;
    let mut previous2 = 0;

    for &byte in source {
        let start = result.len();
        let escape = byte < b' '
            || (!allow_8_bit && byte >= 127)
            || byte == b'\\'
            || bad.is_some_and(|bad| bad.contains(&byte));
        let width = if escape { 4 } else { 1 };
        if result
            .len()
            .checked_add(width)
            .and_then(|length| length.checked_add(ellipsis_length))
            .is_none_or(|length| length > body_length)
        {
            return Ok(with_ellipsis(result, body_length, previous, previous2));
        }

        if escape {
            result.extend_from_slice(&[b'\\', b'x', hexchar(byte >> 4), hexchar(byte & 0x0f)]);
        } else {
            result.push(byte);
        }
        previous2 = previous;
        previous = start;
    }

    if forced_ellipsis {
        Ok(with_ellipsis(result, body_length, previous, previous2))
    } else {
        Ok(result)
    }
}

/// Match C's two-entry rollback when appending an ellipsis after truncation.
fn with_ellipsis(
    mut result: Vec<u8>,
    body_length: usize,
    previous: usize,
    previous2: usize,
) -> Vec<u8> {
    let dots = body_length.min(3);
    let current = result.len();
    let offset = if body_length - dots >= current {
        current
    } else if body_length - dots >= previous {
        previous
    } else if body_length - dots >= previous2 {
        previous2
    } else {
        body_length - dots
    };
    result.truncate(offset);
    result.extend(std::iter::repeat_n(b'.', dots));
    result
}

/// Byte-level implementation of current C `shell_maybe_quote()`.
fn try_shell_maybe_quote(source: &[u8], flags: u32) -> Result<Vec<u8>, ()> {
    if flags & SHELL_ESCAPE_EMPTY != 0 && source.is_empty() {
        let mut result = try_byte_buffer(2)?;
        result.extend_from_slice(b"\"\"");
        return Ok(result);
    }

    let mut prefix_length = 0;
    while prefix_length < source.len() {
        let width = utf8_encoded_valid_unichar(&source[prefix_length..]);
        let byte = source[prefix_length];
        if width < 0 || char_is_cc(byte) || shell_needs_quotes(byte) {
            break;
        }
        prefix_length += width as usize;
    }

    if prefix_length == source.len() {
        let mut result = try_byte_buffer(source.len())?;
        result.extend_from_slice(source);
        return Ok(result);
    }

    let posix = flags & SHELL_ESCAPE_POSIX != 0;
    // Current C: POSIX marker (0/1), opening quote, four bytes per source
    // byte, closing quote, and NUL.
    let capacity = usize::from(posix)
        .checked_add(1)
        .and_then(|length| length.checked_add(source.len().checked_mul(4)?))
        .and_then(|length| length.checked_add(2))
        .ok_or(())?;
    let mut result = try_byte_buffer(capacity)?;
    if posix {
        result.extend_from_slice(b"$'");
    } else {
        result.push(b'"');
    }
    result.extend_from_slice(&source[..prefix_length]);

    let bad = if posix {
        b"\\'".as_slice()
    } else {
        b"\"\\`$".as_slice()
    };
    append_backslash_escaped(&mut result, &source[prefix_length..], bad);
    result.push(if posix { b'\'' } else { b'"' });
    Ok(result)
}

/// Exact C `WHITESPACE SHELL_NEED_QUOTES` byte predicate.
fn shell_needs_quotes(byte: u8) -> bool {
    SHELL_QUOTE_BYTES.contains(&byte)
}

/// Append C `strcpy_backslash_escaped()` output into an already-reserved
/// buffer. The caller provides C's four-bytes-per-input-byte capacity bound.
fn append_backslash_escaped(result: &mut Vec<u8>, source: &[u8], bad: &[u8]) {
    let mut index = 0;
    while index < source.len() {
        let width = utf8_encoded_valid_unichar(&source[index..]);
        if width < 0 || char_is_cc(source[index]) {
            append_cescape_char(result, source[index]);
            index += 1;
        } else if width == 1 {
            if source[index] == b'\\' || bad.contains(&source[index]) {
                result.push(b'\\');
            }
            result.push(source[index]);
            index += 1;
        } else {
            let width = width as usize;
            result.extend_from_slice(&source[index..index + width]);
            index += width;
        }
    }
}

/// C ABI for `cunescape_length_with_prefix()`.
///
/// # Safety
/// `s` is a non-null readable C string for `length == SIZE_MAX`, or readable
/// for exactly `length` bytes otherwise. `prefix`, when non-null, is a
/// readable C string. `ret` is non-null and writable for one pointer. On
/// success `*ret` becomes a fresh malloc(3) allocation, including any
/// accepted embedded NUL bytes, and the caller releases it with free(3).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_cunescape_length_with_prefix(
    s: *const c_char,
    length: usize,
    prefix: *const c_char,
    flags: u32,
    ret: *mut *mut c_char,
) -> isize {
    if s.is_null() || ret.is_null() {
        return EINVAL as isize;
    }
    // SAFETY: upheld by this entry point's explicit source contract.
    let source = if length == usize::MAX {
        unsafe_ffi!(CStr::from_ptr(s)).to_bytes()
    } else {
        // SAFETY: upheld by this entry point's explicit-length source contract.
        unsafe_ffi!(std::slice::from_raw_parts(s.cast::<u8>(), length))
    };
    let prefix = if prefix.is_null() {
        &[][..]
    } else {
        // SAFETY: upheld by this entry point's prefix C-string contract.
        unsafe_ffi!(CStr::from_ptr(prefix)).to_bytes()
    };

    let result = match try_cunescape_with_prefix(source, prefix, flags) {
        Ok(result) => result,
        Err(error) => return error,
    };
    if result.len() > isize::MAX as usize {
        return ENOMEM;
    }
    let allocation = malloc_c_string(&result);
    if allocation.is_null() {
        return ENOMEM;
    }
    // SAFETY: `ret` was checked non-null and the caller guarantees one
    // writable pointer. Publication is deliberately last, matching C.
    unsafe_ffi!(*ret = allocation);
    result.len() as isize
}

/// C ABI for `xescape_full()`.
///
/// # Safety
/// `s` is a non-null readable C string. `bad` is either null or a readable C
/// string. The fresh returned malloc(3) allocation belongs to the caller.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_xescape_full(
    s: *const c_char,
    bad: *const c_char,
    console_width: usize,
    flags: u32,
) -> *mut c_char {
    if s.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: upheld by this entry point's C-string contracts.
    let source = unsafe_ffi!(CStr::from_ptr(s)).to_bytes();
    let bad = if bad.is_null() {
        None
    } else {
        // SAFETY: upheld by this entry point's C-string contract.
        Some(unsafe_ffi!(CStr::from_ptr(bad)).to_bytes())
    };
    try_xescape_full(source, bad, console_width, flags)
        .map(|result| malloc_c_string(&result))
        .unwrap_or(ptr::null_mut())
}

/// C ABI for `shell_maybe_quote()`.
///
/// # Safety
/// `s` is a non-null readable C string. The returned malloc(3) allocation is
/// owned by the caller and released with free(3).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_shell_maybe_quote(s: *const c_char, flags: u32) -> *mut c_char {
    if s.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: upheld by this entry point's C-string contract.
    let source = unsafe_ffi!(CStr::from_ptr(s)).to_bytes();
    try_shell_maybe_quote(source, flags)
        .map(|result| malloc_c_string(&result))
        .unwrap_or(ptr::null_mut())
}

/// C ABI for `quote_command_line()`.
///
/// # Safety
/// `argv` is a non-null, readable, NULL-terminated array of non-null readable
/// C strings. On success a fresh malloc(3) allocation belongs to the caller.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_quote_command_line(
    argv: *const *mut c_char,
    flags: u32,
) -> *mut c_char {
    if argv.is_null() {
        return ptr::null_mut();
    }

    let mut result: Option<Vec<u8>> = None;
    for index in 0..=isize::MAX as usize {
        // SAFETY: upheld by the entry point's NULL-terminated argv contract.
        let argument = unsafe_ffi!(*argv.add(index));
        if argument.is_null() {
            return result
                .as_deref()
                .map(malloc_c_string)
                .unwrap_or(ptr::null_mut());
        }
        // SAFETY: upheld by the entry point's argv element C-string contract.
        let argument = unsafe_ffi!(CStr::from_ptr(argument)).to_bytes();
        let quoted = match try_shell_maybe_quote(argument, flags) {
            Ok(quoted) => quoted,
            Err(()) => return ptr::null_mut(),
        };
        match &mut result {
            Some(joined) => {
                let additional = quoted.len().saturating_add(1);
                if joined.try_reserve_exact(additional).is_err() {
                    return ptr::null_mut();
                }
                joined.push(b' ');
                joined.extend_from_slice(&quoted);
            }
            None => result = Some(quoted),
        }
    }

    // The contract requires a terminating NULL before pointer arithmetic can
    // overflow. Failing closed is preferable to wrapping an adversarial ABI.
    ptr::null_mut()
}

#[cfg(test)]
mod tests {
    use super::{SHELL_ESCAPE_POSIX, try_shell_maybe_quote};

    #[test]
    fn shell_maybe_quote_quotes_c_whitespace_space() {
        assert_eq!(
            try_shell_maybe_quote(b"hello world", 0).unwrap(),
            b"\"hello world\""
        );
        assert_eq!(
            try_shell_maybe_quote(b"hello world", SHELL_ESCAPE_POSIX).unwrap(),
            b"$'hello world'"
        );
    }
}
