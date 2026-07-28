// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: scope=basic.string-table; authority=src/basic/string-table.c,src/basic/string-table.h,src/basic/parse-util.c,src/basic/parse-util.h
//
// Generic string table lookup helpers: index↔string conversion with
// optional boolean parsing and numeric fallback.

use crate::ffi::Errno;
use std::ffi::{CStr, c_char};
use std::ptr;

// ── parse_boolean ─────────────────────────────────────────────────────────

/// Parse a boolean string. Returns `Some(true)` for truthy values,
/// `Some(false)` for falsy values, `None` for unrecognised strings.
///
/// Mirrors the C `parse_boolean()` from parse-util.h.
pub fn parse_boolean(s: &str) -> Option<bool> {
    match s {
        "1" | "yes" | "y" | "true" | "t" | "on" => Some(true),
        "0" | "no" | "n" | "false" | "f" | "off" => Some(false),
        _ => None,
    }
}

// ── safe_atou ─────────────────────────────────────────────────────────────

/// Parse an unsigned integer from a string (base 10).
/// Returns `Ok(value)` on success, `Err(Errno::EINVAL)` on failure.
pub fn safe_atou(s: &str) -> Result<u32, Errno> {
    u32::from_str_radix(s.trim(), 10).map_err(|_| Errno::EINVAL)
}

// ── string_table_lookup_to_string ─────────────────────────────────────────

pub fn string_table_lookup_to_string<'a>(table: &'a [&'a str], i: isize) -> Option<&'a str> {
    if i < 0 {
        return None;
    }
    table.get(i as usize).copied()
}

// ── string_table_lookup_from_string ───────────────────────────────────────

pub fn string_table_lookup_from_string(table: &[&str], key: &str) -> Result<isize, Errno> {
    for (i, entry) in table.iter().enumerate() {
        if *entry == key {
            return Ok(i as isize);
        }
    }
    Err(Errno::EINVAL)
}

// ── string_table_lookup_from_string_with_boolean ──────────────────────────

pub fn string_table_lookup_from_string_with_boolean(
    table: &[&str],
    key: &str,
    yes: isize,
) -> Result<isize, Errno> {
    if let Some(b) = parse_boolean(key) {
        if !b {
            return Ok(0);
        }
        return Ok(yes);
    }
    string_table_lookup_from_string(table, key)
}

// ── string_table_lookup_to_string_fallback ────────────────────────────────

pub fn string_table_lookup_to_string_fallback(
    table: &[&str],
    i: isize,
    max: usize,
) -> Result<String, Errno> {
    // C first converts `size_t max` to `ssize_t`; preserve that target-width
    // conversion instead of comparing against an unbounded Rust `usize`.
    if i < 0 || i > max as isize {
        return Err(Errno::ERANGE);
    }

    let idx = i as usize;
    if idx < table.len() && !table[idx].is_empty() {
        Ok(table[idx].to_string())
    } else {
        Ok(format!("{}", i))
    }
}

// ── string_table_lookup_from_string_fallback ──────────────────────────────

pub fn string_table_lookup_from_string_fallback(
    table: &[&str],
    s: &str,
    max: usize,
) -> Result<isize, Errno> {
    if let Ok(i) = string_table_lookup_from_string(table, s) {
        return Ok(i);
    }

    let u = safe_atou(s)?;
    if u > max as u32 {
        return Err(Errno::EINVAL);
    }

    Ok(u as isize)
}

// ── C ABI facade ─────────────────────────────────────────────────────────

/// Look up an enumerated table entry by signed index.
///
/// # Safety
///
/// When `i` is in `[0, len)`, `table` must point to an array of at least
/// `len` readable `const char *` elements. The returned pointer is borrowed
/// from that array and every non-NULL entry must remain a live NUL-terminated
/// C string for the caller's use. As in C, a NULL `table` for an in-range
/// index violates the assertion precondition.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_string_table_lookup_to_string(
    table: *const *const c_char,
    len: usize,
    i: isize,
) -> *const c_char {
    if i < 0 || i >= len as isize {
        return ptr::null();
    }

    assert!(
        !table.is_null(),
        "C string-table table is required in range"
    );
    // SAFETY: the documented C ABI requires an array containing `len`
    // readable pointers, and the range check above establishes `i < len`.
    unsafe { *table.add(i as usize) }
}

/// Look up an opaque C string in an enumerated table.
///
/// # Safety
///
/// A non-NULL `table` must point to `len` readable pointer entries, and each
/// non-NULL entry plus a non-NULL `key` must be a live NUL-terminated C
/// string. The function borrows every input only for this call. A NULL table
/// follows C's `assert_return()` failure path and yields `-EINVAL`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_string_table_lookup_from_string(
    table: *const *const c_char,
    len: usize,
    key: *const c_char,
) -> isize {
    if table.is_null() || key.is_null() {
        return -(libc::EINVAL as isize);
    }

    // SAFETY: the documented C ABI guarantees `key` is a live C string after
    // the NULL check above.
    let key = unsafe { CStr::from_ptr(key) }.to_bytes();
    for index in 0..len {
        // SAFETY: the documented C ABI guarantees a readable `len`-element
        // pointer array.
        let entry = unsafe { *table.add(index) };
        if entry.is_null() {
            continue;
        }
        // SAFETY: each non-NULL table entry is a live C string by contract.
        if unsafe { CStr::from_ptr(entry) }.to_bytes() == key {
            return index as isize;
        }
    }

    -(libc::EINVAL as isize)
}

/// Look up a table entry, accepting C's case-insensitive boolean spellings.
///
/// # Safety
///
/// This has the same table and C-string requirements as
/// [`rs_string_table_lookup_from_string`]. `key` is borrowed only for the
/// duration of the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_string_table_lookup_from_string_with_boolean(
    table: *const *const c_char,
    len: usize,
    key: *const c_char,
    yes: isize,
) -> isize {
    if key.is_null() {
        return -(libc::EINVAL as isize);
    }

    // SAFETY: `key` is non-NULL and the documented ABI forwards C's string
    // validity precondition to the shared parser.
    match unsafe { crate::parse_util::rs_parse_boolean(key) } {
        0 => 0,
        value if value > 0 => yes,
        _ => {
            // SAFETY: this facade forwards the documented table/C-string
            // contract unchanged to the basic lookup helper.
            unsafe { rs_string_table_lookup_from_string(table, len, key) }
        }
    }
}

/// Allocate the table spelling of `i`, or its decimal fallback, with libc.
///
/// # Safety
///
/// `table` must be a readable `len`-element pointer array when the index is
/// in range; non-NULL entries must be live C strings. `ret` is an asserted C
/// precondition and must be a writable `char *` slot. On success it receives
/// an allocation released with `free()`. On every error it remains unchanged.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_string_table_lookup_to_string_fallback(
    table: *const *const c_char,
    len: usize,
    i: isize,
    max: usize,
    ret: *mut *mut c_char,
) -> i32 {
    assert!(!table.is_null(), "C string-table table is required");
    assert!(!ret.is_null(), "C string-table output is required");

    // C first converts `size_t max` to `ssize_t`; preserve that target-width
    // conversion instead of comparing against an unbounded Rust `usize`.
    if i < 0 || i > max as isize {
        return -libc::ERANGE;
    }

    let allocated = if (i as usize) < len {
        // SAFETY: the documented C ABI guarantees a readable `len`-element
        // pointer array and this branch establishes `i < len`.
        let entry = unsafe { *table.add(i as usize) };
        if entry.is_null() {
            ptr::null_mut()
        } else {
            // SAFETY: the documented C ABI guarantees `entry` is a live C
            // string. `strdup` returns libc-owned storage or NULL.
            let duplicate = unsafe { libc::strdup(entry) };
            if duplicate.is_null() {
                return -libc::ENOMEM;
            }
            duplicate
        }
    } else {
        ptr::null_mut()
    };
    let allocated = if allocated.is_null() {
        // Avoid a Rust-allocator OOM path for C's asprintf_safe() fallback.
        // The range check above makes `i` non-negative; an isize decimal
        // spelling fits in this fixed buffer together with its terminator.
        let mut decimal = [0 as c_char; 32];
        let mut value = i as usize;
        let mut start = decimal.len() - 1;
        loop {
            start -= 1;
            decimal[start] = b'0' as c_char + (value % 10) as c_char;
            value /= 10;
            if value == 0 {
                break;
            }
        }
        // SAFETY: the suffix beginning at `start` is a local, NUL-terminated
        // ASCII decimal C string; strdup returns libc-owned storage or NULL.
        let copy = unsafe { libc::strdup(decimal[start..].as_ptr()) };
        if copy.is_null() {
            return -libc::ENOMEM;
        }
        copy
    } else {
        allocated
    };

    // SAFETY: `ret` is the caller-provided writable output slot; publication
    // occurs only after allocation succeeds, matching C's transactional API.
    unsafe { *ret = allocated };
    0
}

/// Parse a table spelling or C `safe_atou()` decimal fallback.
///
/// # Safety
///
/// This has the same table requirements as
/// [`rs_string_table_lookup_from_string`]. A non-NULL `s` must be a live
/// NUL-terminated C string and is borrowed only for this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_string_table_lookup_from_string_fallback(
    table: *const *const c_char,
    len: usize,
    s: *const c_char,
    max: usize,
) -> isize {
    if s.is_null() {
        return -(libc::EINVAL as isize);
    }

    // SAFETY: this facade forwards the documented table/C-string contract.
    let index = unsafe { rs_string_table_lookup_from_string(table, len, s) };
    if index >= 0 {
        return index;
    }

    let mut value = 0_u32;
    // SAFETY: `s` is a live C string by this function's documented contract,
    // and `value` is a valid writable output slot for the duration of call.
    if unsafe { crate::parse_util::safe_atou_full_inner(s, 10, &mut value) } < 0
        || (value as u128) > (max as u128)
    {
        return -(libc::EINVAL as isize);
    }

    value as isize
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── parse_boolean ──────────────────────────────────────────────────

    #[test]
    fn test_parse_boolean_true_values() {
        assert_eq!(parse_boolean("1"), Some(true));
        assert_eq!(parse_boolean("yes"), Some(true));
        assert_eq!(parse_boolean("y"), Some(true));
        assert_eq!(parse_boolean("true"), Some(true));
        assert_eq!(parse_boolean("t"), Some(true));
        assert_eq!(parse_boolean("on"), Some(true));
    }

    #[test]
    fn test_parse_boolean_false_values() {
        assert_eq!(parse_boolean("0"), Some(false));
        assert_eq!(parse_boolean("no"), Some(false));
        assert_eq!(parse_boolean("n"), Some(false));
        assert_eq!(parse_boolean("false"), Some(false));
        assert_eq!(parse_boolean("f"), Some(false));
        assert_eq!(parse_boolean("off"), Some(false));
    }

    #[test]
    fn test_parse_boolean_unrecognised() {
        assert_eq!(parse_boolean("maybe"), None);
        assert_eq!(parse_boolean("YES"), None);
        assert_eq!(parse_boolean(""), None);
        assert_eq!(parse_boolean("2"), None);
    }

    // ── safe_atou ──────────────────────────────────────────────────────

    #[test]
    fn test_safe_atou_valid() {
        assert_eq!(safe_atou("0"), Ok(0));
        assert_eq!(safe_atou("42"), Ok(42));
        assert_eq!(safe_atou("4294967295"), Ok(u32::MAX));
    }

    #[test]
    fn test_safe_atou_invalid() {
        assert_eq!(safe_atou(""), Err(Errno::EINVAL));
        assert_eq!(safe_atou("abc"), Err(Errno::EINVAL));
        assert_eq!(safe_atou("-1"), Err(Errno::EINVAL));
    }

    #[test]
    fn test_safe_atou_whitespace() {
        assert_eq!(safe_atou(" 42 "), Ok(42));
    }

    // ── string_table_lookup_to_string ──────────────────────────────────

    #[test]
    fn test_to_string_valid() {
        let table = ["zero", "one", "two"];
        assert_eq!(string_table_lookup_to_string(&table, 0), Some("zero"));
        assert_eq!(string_table_lookup_to_string(&table, 1), Some("one"));
        assert_eq!(string_table_lookup_to_string(&table, 2), Some("two"));
    }

    #[test]
    fn test_to_string_out_of_range() {
        let table = ["zero", "one"];
        assert_eq!(string_table_lookup_to_string(&table, 2), None);
        assert_eq!(string_table_lookup_to_string(&table, -1), None);
    }

    // ── string_table_lookup_from_string ────────────────────────────────

    #[test]
    fn test_from_string_found() {
        let table = ["alpha", "beta", "gamma"];
        assert_eq!(string_table_lookup_from_string(&table, "beta"), Ok(1));
        assert_eq!(string_table_lookup_from_string(&table, "alpha"), Ok(0));
    }

    #[test]
    fn test_from_string_not_found() {
        let table = ["alpha", "beta"];
        assert_eq!(
            string_table_lookup_from_string(&table, "delta"),
            Err(Errno::EINVAL)
        );
    }

    // ── string_table_lookup_from_string_with_boolean ───────────────────

    #[test]
    fn test_with_boolean_true() {
        let table = ["zero", "one"];
        assert_eq!(
            string_table_lookup_from_string_with_boolean(&table, "yes", 42),
            Ok(42)
        );
    }

    #[test]
    fn test_with_boolean_false() {
        let table = ["zero", "one"];
        assert_eq!(
            string_table_lookup_from_string_with_boolean(&table, "no", 42),
            Ok(0)
        );
    }

    #[test]
    fn test_with_boolean_falls_through_to_table() {
        let table = ["zero", "one"];
        assert_eq!(
            string_table_lookup_from_string_with_boolean(&table, "one", 42),
            Ok(1)
        );
    }

    #[test]
    fn test_with_boolean_unrecognised_not_in_table() {
        let table = ["zero", "one"];
        assert_eq!(
            string_table_lookup_from_string_with_boolean(&table, "unknown", 42),
            Err(Errno::EINVAL)
        );
    }

    // ── string_table_lookup_to_string_fallback ─────────────────────────

    #[test]
    fn test_to_string_fallback_in_table() {
        let table = ["zero", "one", "two"];
        assert_eq!(
            string_table_lookup_to_string_fallback(&table, 1, 10),
            Ok("one".to_string())
        );
    }

    #[test]
    fn test_to_string_fallback_out_of_table_numeric() {
        let table = ["zero", "one"];
        assert_eq!(
            string_table_lookup_to_string_fallback(&table, 5, 10),
            Ok("5".to_string())
        );
    }

    #[test]
    fn test_to_string_fallback_negative() {
        let table = ["zero", "one"];
        assert_eq!(
            string_table_lookup_to_string_fallback(&table, -1, 10),
            Err(Errno::ERANGE)
        );
    }

    #[test]
    fn test_to_string_fallback_exceeds_max() {
        let table = ["zero", "one"];
        assert_eq!(
            string_table_lookup_to_string_fallback(&table, 15, 10),
            Err(Errno::ERANGE)
        );
    }

    // ── string_table_lookup_from_string_fallback ───────────────────────

    #[test]
    fn test_from_string_fallback_found_in_table() {
        let table = ["alpha", "beta", "gamma"];
        assert_eq!(
            string_table_lookup_from_string_fallback(&table, "beta", 10),
            Ok(1)
        );
    }

    #[test]
    fn test_from_string_fallback_numeric() {
        let table = ["alpha", "beta"];
        assert_eq!(
            string_table_lookup_from_string_fallback(&table, "5", 10),
            Ok(5)
        );
    }

    #[test]
    fn test_from_string_fallback_not_found_not_numeric() {
        let table = ["alpha", "beta"];
        assert_eq!(
            string_table_lookup_from_string_fallback(&table, "xyz", 10),
            Err(Errno::EINVAL)
        );
    }

    #[test]
    fn test_from_string_fallback_numeric_exceeds_max() {
        let table = ["alpha"];
        assert_eq!(
            string_table_lookup_from_string_fallback(&table, "99", 10),
            Err(Errno::EINVAL)
        );
    }
}
