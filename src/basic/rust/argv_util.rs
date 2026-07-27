// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/basic/argv-util.c, src/basic/argv-util.h
//
// argv utility functions (pure computation subset).
// Skipped: invoked_by_systemd (uses getenv, parse_pid, getpid_cached),
//          save_argc_argv (modifies globals),
//          rename_process_full (uses prctl, mmap, program_invocation_name).

// ── Internal helpers ───────────────────────────────────────────────────────

/// Equivalent to last_path_component() from path-util.c.
/// Returns the last component of a file path.
fn last_path_component(path: &str) -> &str {
    if path.is_empty() {
        return "";
    }
    let trimmed = path.trim_end_matches('/');
    if trimmed.is_empty() {
        return "/";
    }
    match trimmed.rfind('/') {
        Some(i) => &trimmed[i + 1..],
        None => trimmed,
    }
}

// ── Public API ──────────────────────────────────────────────────────────────

/// Check if the current executable name (argv[0]) contains the given token.
/// Equivalent to C invoked_as().
///
/// Returns false if argv is empty, argv[0] is empty, or token is empty.
pub fn invoked_as(argv: &[&str], token: &str) -> bool {
    if argv.is_empty() || argv[0].is_empty() {
        return false;
    }
    if token.is_empty() {
        return false;
    }
    last_path_component(argv[0]).contains(token)
}

/// Scan command line for indications the user asks for help.
/// Equivalent to C argv_looks_like_help().
///
/// Detects four ways of asking for help:
/// 1. argc <= 1 (zero or one argument)
/// 2. argv[1] == "help"
/// 3. "--help" anywhere in argv[1..]
/// 4. "-h" anywhere in argv[1..]
pub fn argv_looks_like_help(argc: i32, argv: &[&str]) -> bool {
    if argc <= 1 {
        return true;
    }
    if argv.len() < 2 {
        return true;
    }
    // Check argv[1] == "help"
    if argv[1] == "help" {
        return true;
    }
    // Check if --help or -h in argv[1..]
    argv[1..].iter().any(|&a| a == "--help" || a == "-h")
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── last_path_component tests ─────────────────────────────────────────

    #[test]
    fn test_last_path_component_simple() {
        assert_eq!(last_path_component("/usr/bin/test"), "test");
    }

    #[test]
    fn test_last_path_component_no_slash() {
        assert_eq!(last_path_component("test"), "test");
    }

    #[test]
    fn test_last_path_component_trailing_slash() {
        assert_eq!(last_path_component("/usr/bin/test/"), "test");
    }

    #[test]
    fn test_last_path_component_root() {
        assert_eq!(last_path_component("/"), "/");
    }

    #[test]
    fn test_last_path_component_empty() {
        assert_eq!(last_path_component(""), "");
    }

    #[test]
    fn test_last_path_component_single_component() {
        assert_eq!(last_path_component("/foo"), "foo");
    }

    #[test]
    fn test_last_path_component_nested() {
        assert_eq!(last_path_component("/a/b/c/d"), "d");
    }

    // ── invoked_as tests ──────────────────────────────────────────────────

    #[test]
    fn test_invoked_as_empty_argv() {
        assert!(!invoked_as(&[], "test"));
    }

    #[test]
    fn test_invoked_as_empty_argv0() {
        assert!(!invoked_as(&[""], "test"));
    }

    #[test]
    fn test_invoked_as_empty_token() {
        assert!(!invoked_as(&["/usr/bin/systemd"], ""));
    }

    #[test]
    fn test_invoked_as_match() {
        assert!(invoked_as(&["/usr/bin/systemd"], "systemd"));
    }

    #[test]
    fn test_invoked_as_basename_match() {
        assert!(invoked_as(&["/usr/sbin/udevadm"], "udevadm"));
    }

    #[test]
    fn test_invoked_as_no_match() {
        assert!(!invoked_as(&["/usr/bin/systemd"], "docker"));
    }

    #[test]
    fn test_invoked_as_partial_match() {
        assert!(invoked_as(&["/usr/bin/systemd-udevd"], "systemd"));
    }

    #[test]
    fn test_invoked_as_no_path() {
        assert!(invoked_as(&["systemd"], "systemd"));
    }

    // ── argv_looks_like_help tests ────────────────────────────────────────

    #[test]
    fn test_argv_looks_like_help_zero_argc() {
        assert!(argv_looks_like_help(0, &[]));
    }

    #[test]
    fn test_argv_looks_like_help_one_argc() {
        assert!(argv_looks_like_help(1, &["prog"]));
    }

    #[test]
    fn test_argv_looks_like_help_negative_argc() {
        assert!(argv_looks_like_help(-1, &[]));
    }

    #[test]
    fn test_argv_looks_like_help_explicit_help() {
        assert!(argv_looks_like_help(2, &["prog", "help"]));
    }

    #[test]
    fn test_argv_looks_like_help_double_dash() {
        assert!(argv_looks_like_help(2, &["prog", "--help"]));
    }

    #[test]
    fn test_argv_looks_like_help_short_h() {
        assert!(argv_looks_like_help(2, &["prog", "-h"]));
    }

    #[test]
    fn test_argv_looks_like_help_not_help() {
        assert!(!argv_looks_like_help(2, &["prog", "--foo"]));
    }

    #[test]
    fn test_argv_looks_like_help_in_middle() {
        assert!(argv_looks_like_help(3, &["prog", "--foo", "--help"]));
    }

    #[test]
    fn test_argv_looks_like_help_h_in_middle() {
        assert!(argv_looks_like_help(3, &["prog", "-v", "-h"]));
    }

    #[test]
    fn test_argv_looks_like_help_only_args() {
        assert!(!argv_looks_like_help(3, &["prog", "arg1", "arg2"]));
    }
}
