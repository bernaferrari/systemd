// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/fundamental/strv.h
//
// String vector (strv) utilities. In Rust, this maps to Vec<&str> / Vec<String>
// operations with systemd-style naming.

use alloc::string::String;
use alloc::vec::Vec;

/// Iterate over a string vector.
/// PORT-SYNC: mirrors STRV_FOREACH() macro.
pub fn strv_foreach<'a>(l: &'a [&'a str]) -> impl Iterator<Item = &'a str> {
    l.iter().copied()
}

/// Check if a string vector contains a given string.
pub fn strv_contains(l: &[&str], s: &str) -> bool {
    l.contains(&s)
}

/// Check if a string vector is empty or NULL.
pub fn strv_isempty(l: &[&str]) -> bool {
    l.is_empty()
}

/// Get the length of a string vector.
pub fn strv_length(l: &[&str]) -> usize {
    l.len()
}

/// Find the index of a string in a vector.
pub fn strv_idx(l: &[&str], s: &str) -> Option<usize> {
    l.iter().position(|&item| item == s)
}

/// Join strings with a separator.
pub fn strv_join(l: &[&str], separator: &str) -> String {
    l.join(separator)
}

/// Check if two string vectors are equal (same elements, same order).
pub fn strv_equal(a: &[&str], b: &[&str]) -> bool {
    a.len() == b.len() && a.iter().zip(b.iter()).all(|(x, y)| x == y)
}

/// Find a string prefix match in a vector. Returns the index and the matched string.
pub fn strv_startswith<'a>(l: &[&'a str], prefix: &str) -> Option<(usize, &'a str)> {
    l.iter()
        .enumerate()
        .find_map(|(i, &s)| s.strip_prefix(prefix).map(|rest| (i, rest)))
}

/// Filter a string vector, keeping only elements that match a predicate.
pub fn strv_filter<'a>(l: &[&'a str], pred: impl Fn(&str) -> bool) -> Vec<&'a str> {
    l.iter().copied().filter(|&s| pred(s)).collect()
}

/// Extend a string vector with unique elements.
pub fn strv_extend_unique<'a>(l: &mut Vec<&'a str>, s: &'a str) {
    if !strv_contains(l, s) {
        l.push(s);
    }
}

/// Take ownership of a string vector, leaving an empty one.
/// PORT-SYNC: mirrors TAKE_PTR for strv.
pub fn strv_take(l: &mut Vec<String>) -> Vec<String> {
    core::mem::take(l)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn test_strv_foreach() {
        let v = ["a", "b", "c"];
        let collected: Vec<_> = strv_foreach(&v).collect();
        assert_eq!(collected, vec!["a", "b", "c"]);
    }

    #[test]
    fn test_strv_contains() {
        let v = ["foo", "bar", "baz"];
        assert!(strv_contains(&v, "bar"));
        assert!(!strv_contains(&v, "qux"));
    }

    #[test]
    fn test_strv_isempty() {
        assert!(strv_isempty(&[]));
        assert!(!strv_isempty(&["a"]));
    }

    #[test]
    fn test_strv_length() {
        assert_eq!(strv_length(&[]), 0);
        assert_eq!(strv_length(&["a", "b"]), 2);
    }

    #[test]
    fn test_strv_idx() {
        let v = ["x", "y", "z"];
        assert_eq!(strv_idx(&v, "y"), Some(1));
        assert_eq!(strv_idx(&v, "w"), None);
    }

    #[test]
    fn test_strv_join() {
        let v = ["a", "b", "c"];
        assert_eq!(strv_join(&v, ":"), "a:b:c");
        assert_eq!(strv_join(&v, ""), "abc");
        assert_eq!(strv_join(&[], ","), "");
    }

    #[test]
    fn test_strv_equal() {
        assert!(strv_equal(&["a", "b"], &["a", "b"]));
        assert!(!strv_equal(&["a", "b"], &["b", "a"]));
        assert!(!strv_equal(&["a"], &["a", "b"]));
    }

    #[test]
    fn test_strv_startswith() {
        let v = ["hello world", "foo bar"];
        assert_eq!(strv_startswith(&v, "hello"), Some((0, " world")));
        assert_eq!(strv_startswith(&v, "foo"), Some((1, " bar")));
        assert_eq!(strv_startswith(&v, "baz"), None);
    }

    #[test]
    fn test_strv_filter() {
        let v = ["abc", "def", "ab", "xyz"];
        let filtered = strv_filter(&v, |s| s.starts_with("ab"));
        assert_eq!(filtered, vec!["abc", "ab"]);
    }

    #[test]
    fn test_strv_extend_unique() {
        let mut v: Vec<&str> = vec!["a", "b"];
        strv_extend_unique(&mut v, "c");
        assert_eq!(v, vec!["a", "b", "c"]);
        strv_extend_unique(&mut v, "a");
        assert_eq!(v, vec!["a", "b", "c"]); // no duplicate
    }

    #[test]
    fn test_strv_take() {
        let mut v = vec![String::from("a"), String::from("b")];
        let taken = strv_take(&mut v);
        assert_eq!(taken, vec![String::from("a"), String::from("b")]);
        assert!(v.is_empty());
    }
}
