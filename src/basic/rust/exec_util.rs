// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: scope=basic.exec-util; authority=src/shared/exec-util.c,src/shared/exec-util.h,src/shared/bootspec.c,src/shared/bootspec.h
//
// Exec command flags string table and embedded newline indentation.

use std::ffi::{CStr, c_void};
use std::os::raw::c_char;
use std::ptr;

use crate::ffi;

// ── Error types ──────────────────────────────────────────────────────────

/// Error constants matching the C return conventions.
const EINVAL: i32 = -22;
const ENOMEM: i32 = -12;

// ── Exec command flags enum ──────────────────────────────────────────────

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct ExecCommandFlags: u32 {
        const IGNORE_FAILURE = 1 << 0;
        const FULLY_PRIVILEGED = 1 << 1;
        const NO_SETUID = 1 << 2;
        const NO_ENV_EXPAND = 1 << 3;
        const VIA_SHELL = 1 << 4;
    }
}

static EXEC_COMMAND_STRINGS: [&str; 5] = [
    "ignore-failure",
    "privileged",
    "no-setuid",
    "no-env-expand",
    "via-shell",
];

const EXEC_COMMAND_FLAGS_ALL: u32 = (1 << EXEC_COMMAND_STRINGS.len()) - 1;

/// Parse a C string's bytes according to `exec_command_flags_from_string()`.
///
/// The C table is ASCII, but this deliberately stays byte-oriented so invalid
/// UTF-8 follows the C lookup path and returns `-EINVAL` instead of being
/// rejected by a Rust UTF-8 conversion before the lookup.
fn exec_command_flags_from_bytes(bytes: &[u8]) -> Result<ExecCommandFlags, i32> {
    if bytes == b"ambient" {
        return Ok(ExecCommandFlags::empty());
    }

    for (idx, &table_s) in EXEC_COMMAND_STRINGS.iter().enumerate() {
        if bytes == table_s.as_bytes() {
            return Ok(ExecCommandFlags::from_bits_retain(1 << idx));
        }
    }

    Err(EINVAL)
}

// ── exec_command_flags_to_string ─────────────────────────────────────────

/// Convert a single exec command flag bit to its string name.
/// Mirrors `exec_command_flags_to_string()` from exec-util.c.
pub fn exec_command_flags_to_string(flag: ExecCommandFlags) -> Option<&'static str> {
    let bits = flag.bits();
    for (idx, &s) in EXEC_COMMAND_STRINGS.iter().enumerate() {
        if bits == (1 << idx) {
            return Some(s);
        }
    }
    None
}

// ── exec_command_flags_from_string ───────────────────────────────────────

/// Parse a string into an exec command flag bit.
/// Mirrors `exec_command_flags_from_string()` from exec-util.c.
/// "ambient" maps to no bits set (0) for backward compatibility.
pub fn exec_command_flags_from_string(s: &str) -> Result<ExecCommandFlags, i32> {
    exec_command_flags_from_bytes(s.as_bytes())
}

// ── exec_command_flags_from_strv ─────────────────────────────────────────

/// Parse a list of flag name strings into a combined bitmask.
/// Mirrors `exec_command_flags_from_strv()` from exec-util.c.
pub fn exec_command_flags_from_strv(opts: &[&str]) -> Result<ExecCommandFlags, i32> {
    let mut flags = ExecCommandFlags::empty();
    for opt in opts {
        let fl = exec_command_flags_from_string(opt)?;
        flags |= fl;
    }
    Ok(flags)
}

// ── exec_command_flags_to_strv ───────────────────────────────────────────

/// Convert a bitmask into a list of flag name strings.
/// Mirrors `exec_command_flags_to_strv()` from exec-util.c.
/// Returns an empty Vec for zero flags.
pub fn exec_command_flags_to_strv(flags: ExecCommandFlags) -> Result<Vec<String>, i32> {
    if flags.bits() & !EXEC_COMMAND_FLAGS_ALL != 0 {
        return Err(EINVAL);
    }

    if flags.is_empty() {
        return Ok(Vec::new());
    }

    let mut result = Vec::new();
    for idx in 0..EXEC_COMMAND_STRINGS.len() {
        let bit = ExecCommandFlags::from_bits_retain(1 << idx);
        if flags.contains(bit) {
            let s = exec_command_flags_to_string(bit).ok_or(EINVAL)?;
            result.push(s.to_string());
        }
    }
    Ok(result)
}

// ── indent_embedded_newlines ─────────────────────────────────────────────

/// Return the byte result of `indent_embedded_newlines()` from bootspec.c.
///
/// This is the `strv_split_newlines()`/`strv_join()` behavior used by the C
/// source, not a plain string replacement: `\n` and `\r` runs are coalesced,
/// leading/trailing separators are suppressed, and a backslash quotes its next
/// byte. A trailing unquoted backslash is the C parser's `-EINVAL` error.
fn indent_embedded_newlines_bytes(cmdline: &[u8]) -> Result<Vec<u8>, i32> {
    const INDENT: &[u8] = b"\n              ";

    let mut words = Vec::<Vec<u8>>::new();
    let mut cursor = 0usize;

    loop {
        while cursor < cmdline.len() && matches!(cmdline[cursor], b'\n' | b'\r') {
            cursor += 1;
        }
        if cursor == cmdline.len() {
            break;
        }

        let mut word = Vec::new();
        loop {
            if cursor == cmdline.len() {
                words.try_reserve(1).map_err(|_| ENOMEM)?;
                words.push(word);
                break;
            }

            match cmdline[cursor] {
                b'\\' => {
                    cursor += 1;
                    if cursor == cmdline.len() {
                        return Err(EINVAL);
                    }
                    word.try_reserve(1).map_err(|_| ENOMEM)?;
                    word.push(cmdline[cursor]);
                    cursor += 1;
                }
                b'\n' | b'\r' => {
                    words.try_reserve(1).map_err(|_| ENOMEM)?;
                    words.push(word);
                    break;
                }
                byte => {
                    word.try_reserve(1).map_err(|_| ENOMEM)?;
                    word.push(byte);
                    cursor += 1;
                }
            }
        }
    }

    let separators = words.len().saturating_sub(1);
    let mut allocation_size = separators.checked_mul(INDENT.len()).ok_or(ENOMEM)?;
    for word in &words {
        allocation_size = allocation_size.checked_add(word.len()).ok_or(ENOMEM)?;
    }
    let mut result = Vec::new();
    result
        .try_reserve_exact(allocation_size)
        .map_err(|_| ENOMEM)?;
    for (index, word) in words.iter().enumerate() {
        if index > 0 {
            result.extend_from_slice(INDENT);
        }
        result.extend_from_slice(word);
    }
    Ok(result)
}

/// Fallible, exact Rust counterpart of `indent_embedded_newlines()`.
///
/// The input and result are UTF-8, while the parser itself follows the C
/// helper's byte rules. A trailing unquoted backslash returns `-EINVAL`.
pub fn try_indent_embedded_newlines(cmdline: &str) -> Result<String, i32> {
    let bytes = indent_embedded_newlines_bytes(cmdline.as_bytes())?;
    // Removing ASCII backslashes and replacing ASCII separators cannot make a
    // valid UTF-8 string invalid.
    Ok(String::from_utf8(bytes).expect("newline indentation preserves UTF-8"))
}

/// Indent embedded newlines with 14 spaces.
///
/// This established convenience API cannot express the C helper's parse
/// failure. Its C ABI counterpart, [`rs_indent_embedded_newlines`], returns
/// `-EINVAL` for a trailing unquoted backslash. Valid UTF-8 input without that
/// error follows the C `strv_split_newlines()`/`strv_join()` behavior exactly.
pub fn indent_embedded_newlines(cmdline: &str) -> String {
    match try_indent_embedded_newlines(cmdline) {
        Ok(indented) => indented,
        // The old infallible API cannot represent the C parser's `-EINVAL`.
        // Preserve its established non-panicking surface; C callers use the
        // exact fallible ABI facade below.
        Err(_) => cmdline.replace('\n', "\n              "),
    }
}

/// Allocate a C-owned NULL-terminated string vector for `flags`.
///
/// C's `exec_command_flags_to_strv()` builds the output via `strv_extend()`;
/// therefore both the vector and every entry must be individually releasable
/// by the C allocator through `strv_free()`.
fn allocate_exec_command_flags_strv(flags: u32) -> Result<*mut *mut c_char, i32> {
    if flags == 0 {
        return Ok(ptr::null_mut());
    }
    if flags & !EXEC_COMMAND_FLAGS_ALL != 0 {
        return Err(EINVAL);
    }

    let count = flags.count_ones() as usize;
    let Some(vector_size) = count
        .checked_add(1)
        .and_then(|slots| slots.checked_mul(std::mem::size_of::<*mut c_char>()))
    else {
        return Err(ENOMEM);
    };
    let vector = ffi::calloc(1, vector_size).cast::<*mut c_char>();
    if vector.is_null() {
        return Err(ENOMEM);
    }

    let mut initialized = 0usize;
    for (index, name) in EXEC_COMMAND_STRINGS.iter().enumerate() {
        if flags & (1 << index) == 0 {
            continue;
        }

        let Some(allocation_size) = name.len().checked_add(1) else {
            // SAFETY: vector owns exactly its initialized C-allocator entries.
            unsafe_ffi!(free_exec_command_flags_strv(vector, initialized));
            return Err(ENOMEM);
        };
        let string = ffi::malloc(allocation_size).cast::<c_char>();
        if string.is_null() {
            // SAFETY: vector owns exactly its initialized C-allocator entries.
            unsafe_ffi!(free_exec_command_flags_strv(vector, initialized));
            return Err(ENOMEM);
        }
        // SAFETY: `string` owns `name.len() + 1` writable bytes and the static
        // source has exactly `name.len()` readable bytes.
        unsafe_ffi!({
            ptr::copy_nonoverlapping(name.as_ptr().cast::<c_char>(), string, name.len());
            *string.add(name.len()) = 0;
            *vector.add(initialized) = string;
        });
        initialized += 1;
    }

    Ok(vector)
}

/// Release a partially-built vector returned by
/// [`allocate_exec_command_flags_strv`].
///
/// # Safety
/// `vector` must be the C-allocator vector allocated by that helper, with
/// exactly `initialized` owned C-allocator strings in its prefix.
unsafe fn free_exec_command_flags_strv(vector: *mut *mut c_char, initialized: usize) {
    for index in 0..initialized {
        // SAFETY: each initialized slot is a unique C-allocator allocation.
        unsafe_ffi!(ffi::free((*vector.add(index)).cast::<c_void>()));
    }
    // SAFETY: vector is the owning C-allocator base allocation.
    unsafe_ffi!(ffi::free(vector.cast::<c_void>()));
}

/// Allocate the C-owned result for `indent_embedded_newlines()`.
fn allocate_indented_cmdline(bytes: &[u8]) -> Result<*mut c_char, i32> {
    let output = indent_embedded_newlines_bytes(bytes)?;
    let Some(allocation_size) = output.len().checked_add(1) else {
        return Err(ENOMEM);
    };
    let allocation = ffi::malloc(allocation_size).cast::<c_char>();
    if allocation.is_null() {
        return Err(ENOMEM);
    }
    // SAFETY: allocation owns output.len() + 1 bytes and output is readable.
    unsafe_ffi!({
        ptr::copy_nonoverlapping(output.as_ptr().cast::<c_char>(), allocation, output.len());
        *allocation.add(output.len()) = 0;
    });
    Ok(allocation)
}

// ── C ABI facades ────────────────────────────────────────────────────────

/// C ABI facade for `exec_command_flags_to_string()`.
///
/// The returned pointer borrows immutable process-lifetime storage and must
/// not be freed. Combined, zero, negative, and unknown values return NULL.
#[unsafe(no_mangle)]
pub extern "C" fn rs_exec_command_flags_to_string(flag: i32) -> *const c_char {
    match flag {
        1 => c"ignore-failure".as_ptr(),
        2 => c"privileged".as_ptr(),
        4 => c"no-setuid".as_ptr(),
        8 => c"no-env-expand".as_ptr(),
        16 => c"via-shell".as_ptr(),
        _ => ptr::null(),
    }
}

/// C ABI facade for `exec_command_flags_from_string()`.
///
/// # Safety
/// `s` must point to a readable NUL-terminated C string for this call. NULL
/// violates C's asserted precondition and fails closed with `-EINVAL`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_exec_command_flags_from_string(s: *const c_char) -> i32 {
    if s.is_null() {
        return EINVAL;
    }
    // SAFETY: the entry point contract guarantees a live C string.
    match exec_command_flags_from_bytes(unsafe_ffi!(CStr::from_ptr(s)).to_bytes()) {
        Ok(flags) => flags.bits() as i32,
        Err(error) => error,
    }
}

/// C ABI facade for `exec_command_flags_from_strv()`.
///
/// # Safety
/// `ex_opts` must be NULL or a readable NULL-terminated vector of readable
/// NUL-terminated strings. `ret` must be writable for one `int`. On failure,
/// including an invalid entry, `ret` is unchanged. A NULL `ret` violates C's
/// asserted precondition and fails closed with `-EINVAL`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_exec_command_flags_from_strv(
    ex_opts: *const *mut c_char,
    ret: *mut i32,
) -> i32 {
    if ret.is_null() {
        return EINVAL;
    }

    let mut flags = 0u32;
    if !ex_opts.is_null() {
        let mut index = 0usize;
        loop {
            // SAFETY: the entry point contract guarantees a NULL-terminated vector.
            let option = unsafe_ffi!(*ex_opts.add(index));
            if option.is_null() {
                break;
            }
            // SAFETY: every non-NULL vector entry is a readable C string.
            let parsed =
                match exec_command_flags_from_bytes(unsafe_ffi!(CStr::from_ptr(option)).to_bytes())
                {
                    Ok(flag) => flag,
                    Err(error) => return error,
                };
            flags |= parsed.bits();
            let Some(next_index) = index.checked_add(1) else {
                return ENOMEM;
            };
            index = next_index;
        }
    }

    // SAFETY: ret is non-null and writable by the entry point contract.
    unsafe_ffi!(*ret = flags as i32);
    0
}

/// C ABI facade for `exec_command_flags_to_strv()`.
///
/// # Safety
/// `ret` must be writable for one `char **`. On success a non-empty output is
/// a C-allocator-owned, NULL-terminated vector whose entries are individually
/// C-allocator-owned; the C caller must release it with `strv_free()`. Empty
/// flags publish NULL. On error `ret` is unchanged. A NULL output pointer and
/// a negative input violate C's asserted preconditions and fail closed with
/// `-EINVAL`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_exec_command_flags_to_strv(
    flags: i32,
    ret: *mut *mut *mut c_char,
) -> i32 {
    if ret.is_null() || flags < 0 {
        return EINVAL;
    }

    match allocate_exec_command_flags_strv(flags as u32) {
        Ok(vector) => {
            // SAFETY: ret is non-null and writable by the entry point contract.
            unsafe_ffi!(*ret = vector);
            0
        }
        Err(error) => error,
    }
}

/// C ABI facade for the `bootspec.c` helper `indent_embedded_newlines()`.
///
/// # Safety
/// `cmdline` must be a readable NUL-terminated C string and `ret_cmdline`
/// must be writable for one `char *`. On success the latter receives a fresh
/// C-allocator allocation owned by the caller and releasable with `free(3)`.
/// On error it is unchanged. NULL inputs violate C's asserted precondition and
/// fail closed with `-EINVAL`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_indent_embedded_newlines(
    cmdline: *mut c_char,
    ret_cmdline: *mut *mut c_char,
) -> i32 {
    if cmdline.is_null() || ret_cmdline.is_null() {
        return EINVAL;
    }
    // SAFETY: cmdline is a live C string by the entry point contract.
    match allocate_indented_cmdline(unsafe_ffi!(CStr::from_ptr(cmdline.cast_const())).to_bytes()) {
        Ok(result) => {
            // SAFETY: ret_cmdline is writable by the entry point contract.
            unsafe_ffi!(*ret_cmdline = result);
            0
        }
        Err(error) => error,
    }
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_flags_to_string_valid() {
        assert_eq!(
            exec_command_flags_to_string(ExecCommandFlags::IGNORE_FAILURE),
            Some("ignore-failure")
        );
        assert_eq!(
            exec_command_flags_to_string(ExecCommandFlags::FULLY_PRIVILEGED),
            Some("privileged")
        );
        assert_eq!(
            exec_command_flags_to_string(ExecCommandFlags::NO_SETUID),
            Some("no-setuid")
        );
        assert_eq!(
            exec_command_flags_to_string(ExecCommandFlags::NO_ENV_EXPAND),
            Some("no-env-expand")
        );
        assert_eq!(
            exec_command_flags_to_string(ExecCommandFlags::VIA_SHELL),
            Some("via-shell")
        );
    }

    #[test]
    fn test_flags_to_string_invalid() {
        assert!(exec_command_flags_to_string(ExecCommandFlags::empty()).is_none());
        let combined = ExecCommandFlags::IGNORE_FAILURE | ExecCommandFlags::FULLY_PRIVILEGED;
        assert!(exec_command_flags_to_string(combined).is_none());
        let out_of_range = ExecCommandFlags::from_bits_retain(1 << 5);
        assert!(exec_command_flags_to_string(out_of_range).is_none());
    }

    #[test]
    fn test_flags_from_string_valid() {
        assert_eq!(
            exec_command_flags_from_string("ignore-failure"),
            Ok(ExecCommandFlags::IGNORE_FAILURE)
        );
        assert_eq!(
            exec_command_flags_from_string("privileged"),
            Ok(ExecCommandFlags::FULLY_PRIVILEGED)
        );
        assert_eq!(
            exec_command_flags_from_string("no-setuid"),
            Ok(ExecCommandFlags::NO_SETUID)
        );
        assert_eq!(
            exec_command_flags_from_string("no-env-expand"),
            Ok(ExecCommandFlags::NO_ENV_EXPAND)
        );
        assert_eq!(
            exec_command_flags_from_string("via-shell"),
            Ok(ExecCommandFlags::VIA_SHELL)
        );
    }

    #[test]
    fn test_flags_from_string_ambient() {
        assert_eq!(
            exec_command_flags_from_string("ambient"),
            Ok(ExecCommandFlags::empty())
        );
    }

    #[test]
    fn test_flags_from_string_invalid() {
        assert!(exec_command_flags_from_string("foobar").is_err());
        assert!(exec_command_flags_from_string("").is_err());
    }

    #[test]
    fn test_flags_roundtrip() {
        for idx in 0..EXEC_COMMAND_STRINGS.len() {
            let flag = ExecCommandFlags::from_bits_retain(1 << idx);
            let name = exec_command_flags_to_string(flag).unwrap();
            assert_eq!(exec_command_flags_from_string(name), Ok(flag));
        }
    }

    #[test]
    fn test_flags_from_strv_valid() {
        let result = exec_command_flags_from_strv(&["ignore-failure", "privileged"]).unwrap();
        assert_eq!(
            result,
            ExecCommandFlags::IGNORE_FAILURE | ExecCommandFlags::FULLY_PRIVILEGED
        );
    }

    #[test]
    fn test_flags_from_strv_empty() {
        let result = exec_command_flags_from_strv(&[]).unwrap();
        assert_eq!(result, ExecCommandFlags::empty());
    }

    #[test]
    fn test_flags_from_strv_invalid_entry() {
        assert!(exec_command_flags_from_strv(&["ignore-failure", "foobar"]).is_err());
    }

    #[test]
    fn test_flags_to_strv_valid() {
        let flags = ExecCommandFlags::IGNORE_FAILURE | ExecCommandFlags::FULLY_PRIVILEGED;
        let result = exec_command_flags_to_strv(flags).unwrap();
        assert_eq!(result.len(), 2);
        assert!(result.contains(&"ignore-failure".to_string()));
        assert!(result.contains(&"privileged".to_string()));
    }

    #[test]
    fn test_flags_to_strv_zero() {
        let result = exec_command_flags_to_strv(ExecCommandFlags::empty()).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_flags_to_strv_all_flags() {
        let all = ExecCommandFlags::IGNORE_FAILURE
            | ExecCommandFlags::FULLY_PRIVILEGED
            | ExecCommandFlags::NO_SETUID
            | ExecCommandFlags::NO_ENV_EXPAND
            | ExecCommandFlags::VIA_SHELL;
        let result = exec_command_flags_to_strv(all).unwrap();
        assert_eq!(result.len(), 5);
    }

    #[test]
    fn test_flags_to_strv_rejects_unknown_bits() {
        let unknown = ExecCommandFlags::from_bits_retain(1 << 5);
        assert_eq!(exec_command_flags_to_strv(unknown), Err(EINVAL));
    }

    #[test]
    fn test_indent_no_newlines() {
        assert_eq!(indent_embedded_newlines("hello world"), "hello world");
    }

    #[test]
    fn test_indent_with_newlines() {
        assert_eq!(
            indent_embedded_newlines("line1\nline2"),
            "line1\n              line2"
        );
    }

    #[test]
    fn test_indent_multiple_newlines() {
        assert_eq!(
            indent_embedded_newlines("a\nb\nc"),
            "a\n              b\n              c"
        );
    }

    #[test]
    fn test_indent_empty() {
        assert_eq!(indent_embedded_newlines(""), "");
    }

    #[test]
    fn test_indent_coalesces_and_suppresses_newline_runs() {
        assert_eq!(
            indent_embedded_newlines("\n\rline1\n\nline2\r"),
            "line1\n              line2"
        );
    }

    #[test]
    fn test_indent_unescapes_the_next_byte_like_extract_first_word() {
        assert_eq!(indent_embedded_newlines("line1\\\nline2"), "line1\nline2");
        assert_eq!(indent_embedded_newlines_bytes(b"line1\\"), Err(EINVAL));
        assert_eq!(try_indent_embedded_newlines("line1\\"), Err(EINVAL));
    }

    #[test]
    fn test_flags_from_strv_ambient() {
        let result = exec_command_flags_from_strv(&["ambient"]).unwrap();
        assert_eq!(result, ExecCommandFlags::empty());
    }

    #[test]
    fn test_flags_from_strv_mixed() {
        let result = exec_command_flags_from_strv(&["ambient", "privileged"]).unwrap();
        assert_eq!(result, ExecCommandFlags::FULLY_PRIVILEGED);
    }
}
