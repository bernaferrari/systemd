// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: scope=basic.env-util; authority=src/basic/env-util.c,src/basic/env-util.h
//
// Environment variable validation functions.
//
// The ordinary Rust API accepts `&str`; the deliberately narrow C ABI
// adapters below preserve C-string byte semantics, including invalid UTF-8
// rejection and NULL-terminated string-vector traversal.

use std::ffi::CStr;

use libc::c_char;

use crate::string_util::valid_utf8_character;

// ── Constants ─────────────────────────────────────────────────────────────

/// Default fallback for `_SC_ARG_MAX` when the system call unexpectedly fails.
const DEFAULT_ARG_MAX: usize = 2097152;

// ── Internal: arg_max ─────────────────────────────────────────────────────

/// Return the system's `_SC_ARG_MAX` value.
///
/// This is the same `sysconf(_SC_ARG_MAX)` query made by C `sc_arg_max()`.
fn arg_max() -> usize {
    // SAFETY: `sysconf` has no pointer arguments and `_SC_ARG_MAX` is a
    // platform constant supplied by libc.
    let value = unsafe_ffi!(libc::sysconf(libc::_SC_ARG_MAX));
    usize::try_from(value)
        .ok()
        .filter(|value| *value > 0)
        .unwrap_or(DEFAULT_ARG_MAX)
}

#[inline]
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

fn env_name_is_valid_bytes(bytes: &[u8]) -> bool {
    !bytes.is_empty()
        && !bytes[0].is_ascii_digit()
        && bytes.len() <= arg_max().saturating_sub(2)
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
}

fn env_value_is_valid_bytes(bytes: &[u8]) -> bool {
    utf8_is_valid_bytes(bytes) && bytes.len() <= arg_max().saturating_sub(3)
}

fn env_assignment_is_valid_bytes(bytes: &[u8]) -> bool {
    let Some(eq) = bytes.iter().position(|byte| *byte == b'=') else {
        return false;
    };

    env_name_is_valid_bytes(&bytes[..eq])
        && env_value_is_valid_bytes(&bytes[eq + 1..])
        && bytes.len() <= arg_max().saturating_sub(1)
}

// ── env_name_is_valid ─────────────────────────────────────────────────────

/// Check whether `name` is a valid POSIX environment variable name.
///
/// A valid name:
/// - is non-empty,
/// - does not start with a digit,
/// - contains only `[A-Za-z0-9_]`,
/// - and is shorter than `arg_max - 2`.
///
/// Corresponds to `env_name_is_valid()` in env-util.c.
pub fn env_name_is_valid(name: &str) -> bool {
    env_name_is_valid_bytes(name.as_bytes())
}

// ── env_name_is_valid_n ───────────────────────────────────────────────────

/// Check whether the first `n` bytes of `s` form a valid env var name.
///
/// Mirrors `env_name_is_valid_n(e, n)` from the C code.
pub fn env_name_is_valid_n(s: &str, n: usize) -> bool {
    s.as_bytes().get(..n).is_some_and(env_name_is_valid_bytes)
}

// ── env_value_is_valid ────────────────────────────────────────────────────

/// Check whether `value` is a valid environment variable value.
///
/// A value is valid if it is valid UTF-8 and shorter than `arg_max - 3`.
///
/// Corresponds to `env_value_is_valid()` in env-util.c.
pub fn env_value_is_valid(value: &str) -> bool {
    env_value_is_valid_bytes(value.as_bytes())
}

// ── env_assignment_is_valid ───────────────────────────────────────────────

/// Check whether `assignment` is a valid `NAME=VALUE` environment assignment.
///
/// The string must contain an `=`, the part before it must be a valid name,
/// and the total length must be shorter than `arg_max - 1`.
///
/// Corresponds to `env_assignment_is_valid()` in env-util.c.
pub fn env_assignment_is_valid(assignment: &str) -> bool {
    env_assignment_is_valid_bytes(assignment.as_bytes())
}

// ── strv_env_is_valid ─────────────────────────────────────────────────────

/// Check whether all entries in `assignments` are valid `NAME=VALUE` pairs
/// with no duplicate names.
///
/// Corresponds to `strv_env_is_valid()` in env-util.c.
pub fn strv_env_is_valid(assignments: &[&str]) -> bool {
    for (i, entry) in assignments.iter().enumerate() {
        if !env_assignment_is_valid(entry) {
            return false;
        }

        let name_i = match entry.find('=') {
            Some(pos) => &entry[..pos],
            None => return false,
        };

        // Check for duplicates in subsequent entries
        for other in &assignments[i + 1..] {
            let other_eq = match other.find('=') {
                Some(pos) => pos,
                None => return false,
            };
            let other_name = &other[..other_eq];
            if name_i == other_name {
                return false;
            }
        }
    }
    true
}

// ── strv_env_name_is_valid ────────────────────────────────────────────────

/// Check whether all entries in `names` are valid env var names with no duplicates.
///
/// Corresponds to `strv_env_name_is_valid()` in env-util.c.
pub fn strv_env_name_is_valid(names: &[&str]) -> bool {
    for (i, name) in names.iter().enumerate() {
        if !env_name_is_valid(name) {
            return false;
        }
        // Check for duplicates
        for other in &names[i + 1..] {
            if *name == *other {
                return false;
            }
        }
    }
    true
}

// ── strv_env_name_or_assignment_is_valid ──────────────────────────────────

/// Check whether all entries are valid env names *or* assignments with no duplicates.
///
/// Each entry is accepted if it passes `env_assignment_is_valid` **or**
/// `env_name_is_valid`.  Duplicate entries (by exact string match) are rejected.
///
/// Corresponds to `strv_env_name_or_assignment_is_valid()` in env-util.c.
pub fn strv_env_name_or_assignment_is_valid(entries: &[&str]) -> bool {
    for (i, entry) in entries.iter().enumerate() {
        if !env_assignment_is_valid(entry) && !env_name_is_valid(entry) {
            return false;
        }
        // Check for duplicates
        for other in &entries[i + 1..] {
            if *entry == *other {
                return false;
            }
        }
    }
    true
}

// ── C ABI adapters ───────────────────────────────────────────────────────

/// Borrow the visible bytes of a C string for the duration of one adapter.
///
/// # Safety
/// `input` must be null or point to a readable NUL-terminated C string.
unsafe fn c_string_bytes<'a>(input: *const c_char) -> Option<&'a [u8]> {
    if input.is_null() {
        return None;
    }

    // SAFETY: the adapter's public contract requires a readable terminator.
    Some(unsafe_ffi!(CStr::from_ptr(input)).to_bytes())
}

/// Get one element from a NULL-terminated C string vector.
///
/// # Safety
/// `list` must be null or point to a readable NULL-terminated vector whose
/// non-null members are readable NUL-terminated C strings.
unsafe fn strv_entry<'a>(list: *const *mut c_char, index: usize) -> Option<&'a [u8]> {
    if list.is_null() {
        return None;
    }

    // SAFETY: the adapter's public contract guarantees this vector slot is
    // readable until its terminator.
    let entry = unsafe_ffi!(*list.add(index));
    // SAFETY: every non-null vector member satisfies c_string_bytes' contract.
    unsafe_ffi!(c_string_bytes(entry))
}

/// C ABI for `env_name_is_valid()`.
///
/// # Safety
/// `e` must be null or point to a readable NUL-terminated C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_env_name_is_valid(e: *const c_char) -> bool {
    // SAFETY: the entry-point contract is exactly c_string_bytes' contract.
    unsafe_ffi!(c_string_bytes(e)).is_some_and(env_name_is_valid_bytes)
}

/// C ABI for `env_value_is_valid()`.
///
/// # Safety
/// `e` must be null or point to a readable NUL-terminated C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_env_value_is_valid(e: *const c_char) -> bool {
    // SAFETY: the entry-point contract is exactly c_string_bytes' contract.
    unsafe_ffi!(c_string_bytes(e)).is_some_and(env_value_is_valid_bytes)
}

/// C ABI for `env_assignment_is_valid()`.
///
/// # Safety
/// `e` must be null or point to a readable NUL-terminated C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_env_assignment_is_valid(e: *const c_char) -> bool {
    // The C implementation asserts for NULL. The shadow ABI remains
    // fail-closed for that invalid call instead of dereferencing it.
    // SAFETY: the entry-point contract is exactly c_string_bytes' contract.
    unsafe_ffi!(c_string_bytes(e)).is_some_and(env_assignment_is_valid_bytes)
}

/// C ABI for `strv_env_is_valid()`.
///
/// # Safety
/// `entries` must be null or point to a readable NULL-terminated vector whose
/// non-null members are readable NUL-terminated C strings.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_strv_env_is_valid(entries: *const *mut c_char) -> bool {
    let mut index = 0;
    loop {
        // SAFETY: the entry-point contract is exactly strv_entry's contract.
        let Some(entry) = (unsafe_ffi!(strv_entry(entries, index))) else {
            return true;
        };
        if !env_assignment_is_valid_bytes(entry) {
            return false;
        }
        let name_len = entry
            .iter()
            .position(|byte| *byte == b'=')
            .expect("validated environment assignment contains '='");

        let mut following = index + 1;
        // SAFETY: as above, including every later vector slot.
        while let Some(other) = unsafe_ffi!(strv_entry(entries, following)) {
            if other.get(name_len) == Some(&b'=') && other[..name_len] == entry[..name_len] {
                return false;
            }
            following += 1;
        }
        index += 1;
    }
}

/// C ABI for `strv_env_name_is_valid()`.
///
/// # Safety
/// `names` must be null or point to a readable NULL-terminated vector whose
/// non-null members are readable NUL-terminated C strings.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_strv_env_name_is_valid(names: *const *mut c_char) -> bool {
    let mut index = 0;
    loop {
        // SAFETY: the entry-point contract is exactly strv_entry's contract.
        let Some(name) = (unsafe_ffi!(strv_entry(names, index))) else {
            return true;
        };
        if !env_name_is_valid_bytes(name) {
            return false;
        }

        let mut following = index + 1;
        // SAFETY: as above, including every later vector slot.
        while let Some(other) = unsafe_ffi!(strv_entry(names, following)) {
            if other == name {
                return false;
            }
            following += 1;
        }
        index += 1;
    }
}

/// C ABI for `strv_env_name_or_assignment_is_valid()`.
///
/// # Safety
/// `entries` must be null or point to a readable NULL-terminated vector whose
/// non-null members are readable NUL-terminated C strings.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_strv_env_name_or_assignment_is_valid(
    entries: *const *mut c_char,
) -> bool {
    let mut index = 0;
    loop {
        // SAFETY: the entry-point contract is exactly strv_entry's contract.
        let Some(entry) = (unsafe_ffi!(strv_entry(entries, index))) else {
            return true;
        };
        if !env_assignment_is_valid_bytes(entry) && !env_name_is_valid_bytes(entry) {
            return false;
        }

        let mut following = index + 1;
        // SAFETY: as above, including every later vector slot.
        while let Some(other) = unsafe_ffi!(strv_entry(entries, following)) {
            if other == entry {
                return false;
            }
            following += 1;
        }
        index += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── env_name_is_valid ──────────────────────────────────────────────

    #[test]
    fn test_env_name_valid_simple() {
        assert!(env_name_is_valid("FOO"));
        assert!(env_name_is_valid("FOO_BAR"));
        assert!(env_name_is_valid("FOO_1"));
        assert!(env_name_is_valid("_underscore"));
        assert!(env_name_is_valid("a"));
        assert!(env_name_is_valid("PATH"));
    }

    #[test]
    fn test_env_name_invalid_starts_with_digit() {
        assert!(!env_name_is_valid("1FOO"));
        assert!(!env_name_is_valid("0"));
        assert!(!env_name_is_valid("9abc"));
    }

    #[test]
    fn test_env_name_invalid_empty() {
        assert!(!env_name_is_valid(""));
    }

    #[test]
    fn test_env_name_invalid_special_chars() {
        assert!(!env_name_is_valid("FOO-BAR"));
        assert!(!env_name_is_valid("FOO.BAR"));
        assert!(!env_name_is_valid("FOO BAR"));
        assert!(!env_name_is_valid("FOO=BAR"));
    }

    #[test]
    fn test_env_name_invalid_too_long() {
        let long_name = "A".repeat(DEFAULT_ARG_MAX);
        assert!(!env_name_is_valid(&long_name));
    }

    // ── env_value_is_valid ─────────────────────────────────────────────

    #[test]
    fn test_env_value_valid() {
        assert!(env_value_is_valid("hello"));
        assert!(env_value_is_valid(""));
        assert!(env_value_is_valid("/usr/bin:/usr/local/bin"));
    }

    #[test]
    fn test_env_value_invalid_too_long() {
        let long_value = "a".repeat(DEFAULT_ARG_MAX);
        assert!(!env_value_is_valid(&long_value));
    }

    // ── env_assignment_is_valid ────────────────────────────────────────

    #[test]
    fn test_env_assignment_valid() {
        assert!(env_assignment_is_valid("FOO=bar"));
        assert!(env_assignment_is_valid("PATH=/usr/bin"));
        assert!(env_assignment_is_valid("A="));
        assert!(env_assignment_is_valid("_=value"));
    }

    #[test]
    fn test_env_assignment_invalid_no_equals() {
        assert!(!env_assignment_is_valid("NO_EQUALS"));
        assert!(!env_assignment_is_valid(""));
    }

    #[test]
    fn test_env_assignment_invalid_bad_name() {
        assert!(!env_assignment_is_valid("1FOO=bar"));
        assert!(!env_assignment_is_valid("FOO BAR=value"));
    }

    #[test]
    fn test_env_assignment_invalid_too_long() {
        let long_assignment = format!("A={}", "b".repeat(DEFAULT_ARG_MAX));
        assert!(!env_assignment_is_valid(&long_assignment));
    }

    // ── strv_env_is_valid ──────────────────────────────────────────────

    #[test]
    fn test_strv_env_valid_unique() {
        assert!(strv_env_is_valid(&["A=1", "B=2", "C=3"]));
    }

    #[test]
    fn test_strv_env_invalid_duplicate_name() {
        assert!(!strv_env_is_valid(&["A=1", "A=2"]));
    }

    #[test]
    fn test_strv_env_invalid_bad_entry() {
        assert!(!strv_env_is_valid(&["A=1", "INVALID", "C=3"]));
    }

    #[test]
    fn test_strv_env_valid_empty() {
        assert!(strv_env_is_valid(&[]));
    }

    #[test]
    fn test_strv_env_valid_single() {
        assert!(strv_env_is_valid(&["PATH=/usr/bin"]));
    }

    // ── strv_env_name_is_valid ─────────────────────────────────────────

    #[test]
    fn test_strv_env_name_valid_unique() {
        assert!(strv_env_name_is_valid(&["FOO", "BAR", "BAZ"]));
    }

    #[test]
    fn test_strv_env_name_invalid_duplicate() {
        assert!(!strv_env_name_is_valid(&["FOO", "FOO"]));
    }

    #[test]
    fn test_strv_env_name_invalid_bad_name() {
        assert!(!strv_env_name_is_valid(&["FOO", "1BAD", "BAR"]));
    }

    #[test]
    fn test_strv_env_name_valid_empty() {
        assert!(strv_env_name_is_valid(&[]));
    }

    // ── strv_env_name_or_assignment_is_valid ───────────────────────────

    #[test]
    fn test_strv_env_name_or_assignment_valid_mixed() {
        assert!(strv_env_name_or_assignment_is_valid(&["FOO", "BAR=value"]));
    }

    #[test]
    fn test_strv_env_name_or_assignment_invalid_duplicate() {
        assert!(!strv_env_name_or_assignment_is_valid(&["FOO", "FOO"]));
    }

    #[test]
    fn test_strv_env_name_or_assignment_invalid_entry() {
        assert!(!strv_env_name_or_assignment_is_valid(&["1BAD"]));
    }

    #[test]
    fn test_strv_env_name_or_assignment_valid_empty() {
        assert!(strv_env_name_or_assignment_is_valid(&[]));
    }
}
