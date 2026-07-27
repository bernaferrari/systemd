// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/basic/proc-cmdline.c
//
// Proc cmdline utility functions (pure string subset).
// Skipped: all functions that read /proc/cmdline, filter pid1 args,
//          parse callbacks, get_key/get_bool (depend on file I/O, strv).

// ── Internal helpers ───────────────────────────────────────────────────────

fn relaxed_equal_char(a: u8, b: u8) -> bool {
    let a_is_sep = a == b'_' || a == b'-' || a == b'.';
    let b_is_sep = b == b'_' || b == b'-' || b == b'.';
    a == b || (a_is_sep && b_is_sep)
}

// ── Public API ─────────────────────────────────────────────────────────────

/// Much like `str.starts_with()`, but considers "-", "_", and "." equivalent.
pub fn proc_cmdline_key_startswith<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    let s_bytes = s.as_bytes();
    let prefix_bytes = prefix.as_bytes();
    let mut any_relaxed = false;

    for (i, &pc) in prefix_bytes.iter().enumerate() {
        if i >= s_bytes.len() {
            return None;
        }
        if s_bytes[i] == pc {
            continue;
        }
        if relaxed_equal_char(s_bytes[i], pc) {
            any_relaxed = true;
            continue;
        }
        return None;
    }

    let remaining = &s[prefix_bytes.len()..];
    if any_relaxed && remaining.contains('_') {
        let normalized: &'static str = Box::leak(remaining.replace('_', "-").into_boxed_str());
        Some(normalized)
    } else {
        Some(remaining)
    }
}

/// Much like string equality, but considers "-" and "_" equivalent.
///
/// Port of `proc_cmdline_key_streq()` from proc-cmdline.c.
pub fn proc_cmdline_key_streq(x: &str, y: &str) -> bool {
    if x.len() != y.len() {
        return false;
    }
    let xb = x.as_bytes();
    let yb = y.as_bytes();
    for i in 0..xb.len() {
        if !relaxed_equal_char(xb[i], yb[i]) {
            return false;
        }
    }
    true
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── proc_cmdline_key_startswith tests ────────────────────────────────

    #[test]
    fn test_startswith_exact_match() {
        assert_eq!(proc_cmdline_key_startswith("hello", "hello"), Some(""));
    }

    #[test]
    fn test_startswith_partial_match() {
        assert_eq!(
            proc_cmdline_key_startswith("hello_world", "hello"),
            Some("_world")
        );
    }

    #[test]
    fn test_startswith_no_match() {
        assert_eq!(proc_cmdline_key_startswith("goodbye", "hello"), None);
    }

    #[test]
    fn test_startswith_underscore_dash_equiv() {
        assert_eq!(
            proc_cmdline_key_startswith("hello_world", "hello-world"),
            Some("")
        );
    }

    #[test]
    fn test_startswith_dash_underscore_equiv() {
        assert_eq!(
            proc_cmdline_key_startswith("hello-world", "hello_world"),
            Some("")
        );
    }

    #[test]
    fn test_startswith_prefix_longer_than_string() {
        assert_eq!(proc_cmdline_key_startswith("hi", "hello"), None);
    }

    #[test]
    fn test_startswith_empty_prefix() {
        assert_eq!(
            proc_cmdline_key_startswith("anything", ""),
            Some("anything")
        );
    }

    #[test]
    fn test_startswith_empty_both() {
        assert_eq!(proc_cmdline_key_startswith("", ""), Some(""));
    }

    #[test]
    fn test_startswith_empty_string_nonempty_prefix() {
        assert_eq!(proc_cmdline_key_startswith("", "abc"), None);
    }

    #[test]
    fn test_startswith_mixed_separators() {
        assert_eq!(proc_cmdline_key_startswith("a_b-c_d", "a-b_c"), Some("-d"));
    }

    #[test]
    fn test_startswith_longer_remainder() {
        assert_eq!(
            proc_cmdline_key_startswith("systemd.log_level=debug", "systemd.log_level"),
            Some("=debug")
        );
    }

    // ── proc_cmdline_key_streq tests ─────────────────────────────────────

    #[test]
    fn test_streq_equal() {
        assert!(proc_cmdline_key_streq("hello", "hello"));
    }

    #[test]
    fn test_streq_not_equal() {
        assert!(!proc_cmdline_key_streq("hello", "world"));
    }

    #[test]
    fn test_streq_underscore_dash_equiv() {
        assert!(proc_cmdline_key_streq("hello_world", "hello-world"));
    }

    #[test]
    fn test_streq_dash_underscore_equiv() {
        assert!(proc_cmdline_key_streq("hello-world", "hello_world"));
    }

    #[test]
    fn test_streq_empty_strings() {
        assert!(proc_cmdline_key_streq("", ""));
    }

    #[test]
    fn test_streq_different_lengths() {
        assert!(!proc_cmdline_key_streq("abc", "abcd"));
    }

    #[test]
    fn test_streq_mixed_separators() {
        assert!(proc_cmdline_key_streq("a_b-c_d", "a-b_c-d"));
    }

    #[test]
    fn test_streq_same_string_no_separators() {
        assert!(proc_cmdline_key_streq("abc", "abc"));
    }

    #[test]
    fn test_streq_empty_vs_nonempty() {
        assert!(!proc_cmdline_key_streq("", "a"));
    }

    #[test]
    fn test_streq_all_dashes_vs_all_underscores() {
        assert!(proc_cmdline_key_streq("a-b-c", "a_b_c"));
    }

    #[test]
    fn test_streq_kernel_param() {
        assert!(proc_cmdline_key_streq(
            "systemd.log_level",
            "systemd-log_level"
        ));
    }

    #[test]
    fn test_streq_partial_mismatch() {
        assert!(!proc_cmdline_key_streq("abc", "abd"));
    }
}
