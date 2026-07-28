// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: scope=basic.argv-util; authority=src/basic/argv-util.c,src/basic/argv-util.h
//
// argv utility functions (pure computation subset).
// Skipped: invoked_by_systemd (uses getenv, parse_pid, getpid_cached),
//          save_argc_argv (modifies globals),
//          rename_process_full (uses prctl, mmap, program_invocation_name).

use std::ffi::CStr;
use std::os::unix::ffi::OsStrExt;

use libc::c_char;

// ── Internal helpers ───────────────────────────────────────────────────────

/// Equivalent to last_path_component() from path-util.c.
/// Returns the last component of a file path.
fn last_path_component(path: &str) -> &str {
    if path.is_empty() {
        return "";
    }
    let mut component_end = path.len();
    while component_end > 0 && path.as_bytes()[component_end - 1] == b'/' {
        component_end -= 1;
    }
    if component_end == 0 {
        return &path[path.len() - 1..];
    }
    let component_start = path[..component_end]
        .rfind('/')
        .map_or(0, |slash| slash + 1);
    &path[component_start..]
}

/// Byte-preserving counterpart of C's `last_path_component()`.
fn last_path_component_bytes(path: &[u8]) -> &[u8] {
    if path.is_empty() {
        return path;
    }
    let mut component_end = path.len();
    while component_end > 0 && path[component_end - 1] == b'/' {
        component_end -= 1;
    }
    if component_end == 0 {
        return &path[path.len() - 1..];
    }
    let component_start = path[..component_end]
        .iter()
        .rposition(|&byte| byte == b'/')
        .map_or(0, |slash| slash + 1);
    &path[component_start..]
}

fn invoked_as_bytes(progname: Option<&[u8]>, token: Option<&[u8]>) -> bool {
    let (Some(progname), Some(token)) = (progname, token) else {
        return false;
    };
    !progname.is_empty()
        && !token.is_empty()
        && last_path_component_bytes(progname)
            .windows(token.len())
            .any(|candidate| candidate == token)
}

fn argv_looks_like_help_bytes(argc: i32, argv: &[&[u8]]) -> bool {
    if argc <= 1 {
        return true;
    }
    if argv.len() < 2 {
        return false;
    }
    argv.get(1).is_some_and(|argument| *argument == b"help")
        || argv[1..]
            .iter()
            .any(|argument| *argument == b"--help" || *argument == b"-h")
}

// ── Public API ──────────────────────────────────────────────────────────────

/// Check if the current executable name (argv[0]) contains the given token.
/// Equivalent to C invoked_as().
///
/// Returns false if argv is empty, argv[0] is empty, or token is empty.
pub fn invoked_as(argv: &[&str], token: &str) -> bool {
    invoked_as_bytes(
        argv.first().map(|argument| argument.as_bytes()),
        Some(token.as_bytes()),
    )
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
    let argv = argv
        .iter()
        .map(|argument| argument.as_bytes())
        .collect::<Vec<_>>();
    argv_looks_like_help_bytes(argc, &argv)
}

/// C ABI mirror of `invoked_as()`.
///
/// # Safety
///
/// `argv`, when non-null, must point to a live vector whose first element is
/// null or a live NUL-terminated string. `token` must be null or a live
/// NUL-terminated string. Neither input is retained.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_invoked_as(argv: *mut *mut c_char, token: *const c_char) -> bool {
    // SAFETY: upheld by this entry point's pointer contract.
    let argv0 = if argv.is_null() {
        None
    } else {
        // SAFETY: the entry-point contract guarantees `argv` is readable.
        let argv0 = unsafe { *argv };
        // SAFETY: a nonnull argv[0] satisfies the entry-point C-string contract.
        (!argv0.is_null()).then(|| unsafe { CStr::from_ptr(argv0) }.to_bytes())
    };
    // SAFETY: upheld by this entry point's pointer contract.
    let token = (!token.is_null()).then(|| unsafe { CStr::from_ptr(token) }.to_bytes());

    // C's secure_getenv() ignores the override in secure execution. Keep an
    // owned OsString-derived byte vector so no environment pointer escapes the
    // boundary, and preserve non-UTF-8 values exactly on Unix.
    // SAFETY: getauxval() takes no pointers and transfers no ownership.
    let invoked_as_override = if unsafe { libc::getauxval(libc::AT_SECURE) } == 0 {
        std::env::var_os("SYSTEMD_INVOKED_AS").map(|value| value.as_bytes().to_vec())
    } else {
        None
    };
    invoked_as_bytes(invoked_as_override.as_deref().or(argv0), token)
}

/// C ABI mirror of `argv_looks_like_help()`.
///
/// # Safety
///
/// For `argc > 1`, `argv` must point to a null-terminated vector of at least
/// `argc` live NUL-terminated argument strings. The vector and all strings are
/// borrowed for this call only.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_argv_looks_like_help(
    argc: libc::c_int,
    argv: *mut *mut c_char,
) -> bool {
    if argc <= 1 {
        return true;
    }
    if argv.is_null() {
        return false;
    }

    // C's strv helpers use the vector's terminating null, not argc, after the
    // initial argc check. Keep the traversal confined to this audited FFI edge.
    let mut index = 1;
    loop {
        // SAFETY: the entry-point contract guarantees a null-terminated vector.
        let argument = unsafe { *argv.add(index) };
        if argument.is_null() {
            return false;
        }
        // SAFETY: the entry-point contract guarantees a live C string.
        let argument = unsafe { CStr::from_ptr(argument) }.to_bytes();
        if argument == b"help" || argument == b"--help" || argument == b"-h" {
            return true;
        }
        index += 1;
    }
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
        assert_eq!(last_path_component("/usr/bin/test/"), "test/");
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

    #[test]
    fn test_last_path_component_bytes_preserves_trailing_slash() {
        assert_eq!(last_path_component_bytes(b"/a/\xff/"), b"\xff/");
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
