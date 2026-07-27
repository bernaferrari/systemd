// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/basic/string-table.c
//
// Generic string table lookup helpers: index↔string conversion with
// optional boolean parsing and numeric fallback.

use crate::ffi::Errno;

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
    if i < 0 || (i as usize) > max {
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
