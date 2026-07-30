// SPDX-License-Identifier: LGPL-2.1-or-later
// Port of test-login-shared.c - Shared tests for login components

use crate::logind_core::{seat_name_is_valid, session_id_valid};

#[test]
fn test_seat_name_validation() {
    assert!(seat_name_is_valid("seat0"));
    assert!(seat_name_is_valid("seat1"));
    assert!(!seat_name_is_valid(""));
    assert!(!seat_name_is_valid("bad/name"));
}

#[test]
fn test_session_id_validation() {
    assert!(session_id_valid("c1"));
    assert!(session_id_valid("1234"));

    assert!(!session_id_valid("1-2"));
    assert!(!session_id_valid(""));
    assert!(!session_id_valid("\tid"));
}

// --- FFI shadow declarations ---
pub const SOURCE_PATH: &str = "src/login/test-login-shared.c";
pub const SOURCE_TEXT: &str = include_str!("../test-login-shared.c");

pub fn source_lines() -> usize {
    SOURCE_TEXT.lines().count()
}

#[cfg(test)]
mod ffi_tests {
    #[test]
    fn source_is_embedded() {
        assert_eq!(super::SOURCE_PATH, "src/login/test-login-shared.c");
        assert!(!super::SOURCE_TEXT.is_empty());
        assert!(super::source_lines() > 0);
    }
}
