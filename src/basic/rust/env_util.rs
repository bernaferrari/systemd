// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/basic/env-util.c (validation subset)
//
// Environment variable validation functions.
// Pure Rust — no syscalls, no raw pointer traversal.

// ── Constants ─────────────────────────────────────────────────────────────

/// Default fallback for `_SC_ARG_MAX` when the system call is unavailable.
/// Linux typically reports 2097152; we use a conservative constant.
const DEFAULT_ARG_MAX: usize = 2097152;

// ── Internal: arg_max ─────────────────────────────────────────────────────

/// Return the system's `_SC_ARG_MAX` value.
///
/// In the C version this calls `sysconf(_SC_ARG_MAX)`.  For the pure-Rust
/// port we read `/proc/sys/kernel/arg_max` on Linux (the common case for
/// systemd) and fall back to `DEFAULT_ARG_MAX` otherwise.
fn arg_max() -> usize {
    #[cfg(target_os = "linux")]
    {
        std::fs::read_to_string("/proc/sys/kernel/arg_max")
            .ok()
            .and_then(|s| s.trim().parse::<usize>().ok())
            .filter(|&v| v > 0)
            .unwrap_or(DEFAULT_ARG_MAX)
    }
    #[cfg(not(target_os = "linux"))]
    {
        DEFAULT_ARG_MAX
    }
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
    if name.is_empty() {
        return false;
    }

    let bytes = name.as_bytes();

    // Must not start with a digit
    if bytes[0].is_ascii_digit() {
        return false;
    }

    // Length check: name must fit within arg_max - 2
    let max = arg_max();
    if name.len() > max.saturating_sub(2) {
        return false;
    }

    // All characters must be [A-Za-z0-9_]
    bytes
        .iter()
        .all(|&b| b.is_ascii_alphanumeric() || b == b'_')
}

// ── env_name_is_valid_n ───────────────────────────────────────────────────

/// Check whether the first `n` bytes of `s` form a valid env var name.
///
/// Mirrors `env_name_is_valid_n(e, n)` from the C code.
pub fn env_name_is_valid_n(s: &str, n: usize) -> bool {
    if n == 0 {
        return false;
    }
    let prefix = match s.char_indices().nth(n) {
        Some((idx, _)) => &s[..idx],
        None => s,
    };
    if prefix.len() < n {
        return false;
    }
    env_name_is_valid(prefix)
}

// ── env_value_is_valid ────────────────────────────────────────────────────

/// Check whether `value` is a valid environment variable value.
///
/// A value is valid if it is non-empty (the caller passed a real string)
/// and shorter than `arg_max - 3`.
///
/// Corresponds to `env_value_is_valid()` in env-util.c.
pub fn env_value_is_valid(value: &str) -> bool {
    let max = arg_max();
    value.len() <= max.saturating_sub(3)
}

// ── env_assignment_is_valid ───────────────────────────────────────────────

/// Check whether `assignment` is a valid `NAME=VALUE` environment assignment.
///
/// The string must contain an `=`, the part before it must be a valid name,
/// and the total length must be shorter than `arg_max - 1`.
///
/// Corresponds to `env_assignment_is_valid()` in env-util.c.
pub fn env_assignment_is_valid(assignment: &str) -> bool {
    let eq_pos = match assignment.find('=') {
        Some(pos) => pos,
        None => return false,
    };

    let name_part = &assignment[..eq_pos];
    if !env_name_is_valid(name_part) {
        return false;
    }

    let max = arg_max();
    assignment.len() <= max.saturating_sub(1)
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
