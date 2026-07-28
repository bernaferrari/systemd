// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: scope=shared.credential-validators; authority=src/shared/creds-util.c,src/shared/creds-util.h
//
// Credential validation pure functions.

use std::ffi::CStr;

use libc::c_char;

// ── Constants ─────────────────────────────────────────────────────────────

const NAME_MAX: usize = 255;
const FDNAME_MAX: usize = 255;

/// Check if a string is a valid filename (no '/', not "." or "..", length ≤ NAME_MAX).
/// Port of C `filename_is_valid()`.
fn filename_is_valid_bytes(name: &[u8]) -> bool {
    if name.is_empty() {
        return false;
    }
    if name == b"." || name == b".." {
        return false;
    }
    if name.contains(&b'/') {
        return false;
    }
    name.len() <= NAME_MAX
}

pub fn filename_is_valid(name: &str) -> bool {
    filename_is_valid_bytes(name.as_bytes())
}

/// Check if a string is valid for $LISTEN_FDNAMES: printable ASCII, no ':', length ≤ FDNAME_MAX.
/// Port of C `fdname_is_valid()`.
fn fdname_is_valid_bytes(name: &[u8]) -> bool {
    name.len() <= FDNAME_MAX
        && name
            .iter()
            .all(|&byte| (b' '..=b'~').contains(&byte) && byte != b':')
}

pub fn fdname_is_valid(name: &str) -> bool {
    fdname_is_valid_bytes(name.as_bytes())
}

// ── Public API ────────────────────────────────────────────────────────────

/// Check if a credential name is valid.
///
/// Port of C `credential_name_valid()`.
/// Credential names must be valid as both filenames and fdnames.
pub fn credential_name_valid(name: &str) -> bool {
    credential_name_valid_bytes(name.as_bytes())
}

fn credential_name_valid_bytes(name: &[u8]) -> bool {
    filename_is_valid_bytes(name) && fdname_is_valid_bytes(name)
}

/// Check if a credential glob expression is valid.
///
/// Port of C `credential_glob_valid()`.
/// Only trailing asterisk wildcards are allowed. No `?`, `[`, or `]` characters
/// are permitted (except the trailing `*`).
pub fn credential_glob_valid(name: &str) -> bool {
    credential_glob_valid_bytes(name.as_bytes())
}

fn credential_glob_valid_bytes(name: &[u8]) -> bool {
    if name.is_empty() {
        return false;
    }

    // Find first glob character (or end of string)
    let n = name
        .iter()
        .position(|&byte| matches!(byte, b'*' | b'?' | b'[' | b']'));

    // No glob found — validate as regular credential name
    let n = match n {
        None => return credential_name_valid_bytes(name),
        Some(idx) => idx,
    };

    let glob_part = &name[n..];

    // Only allow trailing "*", no other glob characters
    if glob_part != b"*" {
        return false;
    }

    // Allow complete wildcard "*"
    if n == 0 {
        return true;
    }

    // Validate the portion before the wildcard
    let prefix = &name[..n];
    credential_name_valid_bytes(prefix)
}

/// C ABI mirror of `credential_name_valid()`.
///
/// # Safety
///
/// `name` must be null or point to a live NUL-terminated byte string for the
/// duration of this call. The storage is borrowed and never retained.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_credential_name_valid(name: *const c_char) -> bool {
    if name.is_null() {
        return false;
    }

    // SAFETY: the entry-point contract guarantees a live NUL-terminated
    // string after the null check.
    let name = unsafe { CStr::from_ptr(name) }.to_bytes();
    credential_name_valid_bytes(name)
}

/// C ABI mirror of `credential_glob_valid()`.
///
/// # Safety
///
/// `name` must be null or point to a live NUL-terminated byte string for the
/// duration of this call. The storage is borrowed and never retained.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_credential_glob_valid(name: *const c_char) -> bool {
    if name.is_null() {
        return false;
    }

    // SAFETY: the entry-point contract guarantees a live NUL-terminated
    // string after the null check.
    let name = unsafe { CStr::from_ptr(name) }.to_bytes();
    credential_glob_valid_bytes(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── credential_name_valid tests ────────────────────────────────────

    #[test]
    fn name_valid_simple() {
        assert!(credential_name_valid("mycred"));
    }

    #[test]
    fn name_valid_with_hyphen() {
        assert!(credential_name_valid("my-cred"));
    }

    #[test]
    fn name_valid_with_underscore() {
        assert!(credential_name_valid("my_cred"));
    }

    #[test]
    fn name_valid_with_dot() {
        assert!(credential_name_valid("my.cred"));
    }

    #[test]
    fn name_valid_with_printable_ascii() {
        assert!(credential_name_valid("my credential+value=@host"));
    }

    #[test]
    fn name_valid_empty_rejected() {
        assert!(!credential_name_valid(""));
    }

    #[test]
    fn name_valid_dot_rejected() {
        assert!(!credential_name_valid("."));
    }

    #[test]
    fn name_valid_dotdot_rejected() {
        assert!(!credential_name_valid(".."));
    }

    #[test]
    fn name_valid_slash_rejected() {
        assert!(!credential_name_valid("my/cred"));
    }

    #[test]
    fn name_valid_too_long_rejected() {
        assert!(!credential_name_valid(&"a".repeat(256)));
    }

    #[test]
    fn name_valid_max_length_accepted() {
        assert!(credential_name_valid(&"a".repeat(255)));
    }

    #[test]
    fn name_valid_colon_rejected() {
        // ':' is invalid for fdnames
        assert!(!credential_name_valid("my:cred"));
    }

    #[test]
    fn name_valid_control_char_rejected() {
        assert!(!credential_name_valid("my\x01cred"));
        assert!(!credential_name_valid("my\ncred"));
        assert!(!credential_name_valid("my\0cred"));
    }

    // ── credential_glob_valid tests ────────────────────────────────────

    #[test]
    fn glob_valid_simple_name() {
        assert!(credential_glob_valid("mycred"));
    }

    #[test]
    fn glob_valid_trailing_wildcard() {
        assert!(credential_glob_valid("mycred*"));
    }

    #[test]
    fn glob_valid_full_wildcard() {
        assert!(credential_glob_valid("*"));
    }

    #[test]
    fn glob_valid_prefix_with_hyphen() {
        assert!(credential_glob_valid("my-cred*"));
    }

    #[test]
    fn glob_valid_empty_rejected() {
        assert!(!credential_glob_valid(""));
    }

    #[test]
    fn glob_valid_question_mark_rejected() {
        assert!(!credential_glob_valid("mycred?"));
    }

    #[test]
    fn glob_valid_bracket_rejected() {
        assert!(!credential_glob_valid("mycred[abc]"));
    }

    #[test]
    fn glob_valid_leading_wildcard_rejected() {
        assert!(!credential_glob_valid("*mycred"));
    }

    #[test]
    fn glob_valid_multiple_wildcards_rejected() {
        assert!(!credential_glob_valid("my*cred*"));
    }

    #[test]
    fn glob_valid_wildcard_with_invalid_prefix_rejected() {
        assert!(!credential_glob_valid("my/cred*"));
    }

    #[test]
    fn glob_valid_trailing_wildcard_with_dot_prefix() {
        // ".foo" is rejected by filename_is_valid (starts with .? No, it's not hidden_or_backup
        // but filename_is_valid doesn't reject dot files. Actually filename_is_valid checks
        // for "." and ".." only, not leading dot. So ".foo*" with prefix ".foo" -
        // filename_is_valid(".foo") should be true (it's not "." or "..", no slash, len ok)
        // fdname_is_valid(".foo") should also be true (printable ASCII, no colon)
        assert!(credential_glob_valid(".foo*"));
    }

    #[test]
    fn glob_valid_no_glob_acts_as_name_valid() {
        // When there's no glob, it should behave like credential_name_valid
        assert!(credential_glob_valid("valid-name"));
        assert!(!credential_glob_valid("invalid/name"));
        assert!(!credential_glob_valid(""));
    }
}
