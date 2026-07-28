// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: scope=basic.runtime_scope; authority=src/basic/runtime-scope.c,src/basic/runtime-scope.h
//
// Runtime scope enum, string tables, and socket mode helper.

use crate::ffi::Errno;
use std::ffi::{CStr, c_char, c_int, c_uint};

// ── Enums ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum RuntimeScope {
    System = 0,
    User = 1,
    Global = 2,
}

pub const RUNTIME_SCOPE_MAX: usize = 3;

impl RuntimeScope {
    pub const INVALID: Self = RuntimeScope::System; // sentinel; use Option for "invalid"

    pub fn from_i32(val: i32) -> Option<Self> {
        match val {
            0 => Some(RuntimeScope::System),
            1 => Some(RuntimeScope::User),
            2 => Some(RuntimeScope::Global),
            _ => None,
        }
    }

    pub fn to_i32(self) -> i32 {
        self as i32
    }
}

// ── String tables ────────────────────────────────────────────────────────

static RUNTIME_SCOPE_NAMES: &[&str] = &["system", "user", "global"];

static RUNTIME_SCOPE_CMDLINE: &[&str] = &["--system", "--user", "--global"];

/* C ABI tables deliberately carry their terminating NUL.  They are borrowed
 * process-lifetime storage, matching DEFINE_STRING_TABLE_LOOKUP(). */
static RUNTIME_SCOPE_NAMES_C: [&[u8]; RUNTIME_SCOPE_MAX] = [b"system\0", b"user\0", b"global\0"];
static RUNTIME_SCOPE_CMDLINE_C: [&[u8]; RUNTIME_SCOPE_MAX] =
    [b"--system\0", b"--user\0", b"--global\0"];

// ── runtime_scope_to_string ─────────────────────────────────────────────

pub fn runtime_scope_to_string(scope: RuntimeScope) -> Option<&'static str> {
    RUNTIME_SCOPE_NAMES.get(scope as usize).copied()
}

// ── runtime_scope_from_string ───────────────────────────────────────────

pub fn runtime_scope_from_string(s: &str) -> Result<RuntimeScope, Errno> {
    for (i, name) in RUNTIME_SCOPE_NAMES.iter().enumerate() {
        if *name == s {
            return Ok(RuntimeScope::from_i32(i as i32).unwrap());
        }
    }
    Err(Errno::EINVAL)
}

// ── runtime_scope_cmdline_option_to_string ──────────────────────────────

pub fn runtime_scope_cmdline_option_to_string(scope: RuntimeScope) -> Option<&'static str> {
    RUNTIME_SCOPE_CMDLINE.get(scope as usize).copied()
}

// ── runtime_scope_to_socket_mode ────────────────────────────────────────

pub const MODE_INVALID: u32 = 0xFFFFFFFF;

pub fn runtime_scope_to_socket_mode(scope: RuntimeScope) -> u32 {
    match scope {
        RuntimeScope::System => 0o666,
        RuntimeScope::User => 0o600,
        RuntimeScope::Global => MODE_INVALID,
    }
}

/// C facade for `runtime_scope_to_string()`.
///
/// The returned pointer borrows immutable process-lifetime storage. Invalid
/// enum integers return NULL, as generated C string-table lookups do.
#[unsafe(no_mangle)]
pub extern "C" fn rs_runtime_scope_to_string(scope: c_int) -> *const c_char {
    RUNTIME_SCOPE_NAMES_C
        .get(scope as usize)
        .map_or(std::ptr::null(), |name| name.as_ptr().cast())
}

/// C facade for `runtime_scope_from_string()`.
///
/// # Safety
///
/// `s` must point to a readable NUL-terminated C string when non-NULL. NULL
/// and unknown byte strings return `-EINVAL` without modifying caller state.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_runtime_scope_from_string(s: *const c_char) -> c_int {
    if s.is_null() {
        return Errno::EINVAL.to_neg_errno();
    }

    // SAFETY: `s` is non-NULL and this function's documented C ABI requires
    // it to point to a readable NUL-terminated string.
    let bytes = unsafe { CStr::from_ptr(s) }.to_bytes();
    match bytes {
        b"system" => RuntimeScope::System as c_int,
        b"user" => RuntimeScope::User as c_int,
        b"global" => RuntimeScope::Global as c_int,
        _ => Errno::EINVAL.to_neg_errno(),
    }
}

/// C facade for `runtime_scope_cmdline_option_to_string()`.
///
/// The returned pointer borrows immutable process-lifetime storage. Invalid
/// enum integers return NULL.
#[unsafe(no_mangle)]
pub extern "C" fn rs_runtime_scope_cmdline_option_to_string(scope: c_int) -> *const c_char {
    RUNTIME_SCOPE_CMDLINE_C
        .get(scope as usize)
        .map_or(std::ptr::null(), |option| option.as_ptr().cast())
}

/// C facade for `runtime_scope_to_socket_mode()`.
///
/// C accepts any integer; only system and user scopes select a mode. Every
/// other value, including global, maps to the unsigned `MODE_INVALID` value.
#[unsafe(no_mangle)]
pub extern "C" fn rs_runtime_scope_to_socket_mode(scope: c_int) -> c_uint {
    match scope {
        x if x == RuntimeScope::System as c_int => 0o666,
        x if x == RuntimeScope::User as c_int => 0o600,
        _ => MODE_INVALID,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_runtime_scope_from_i32_valid() {
        assert_eq!(RuntimeScope::from_i32(0), Some(RuntimeScope::System));
        assert_eq!(RuntimeScope::from_i32(1), Some(RuntimeScope::User));
        assert_eq!(RuntimeScope::from_i32(2), Some(RuntimeScope::Global));
    }

    #[test]
    fn test_runtime_scope_from_i32_invalid() {
        assert_eq!(RuntimeScope::from_i32(-1), None);
        assert_eq!(RuntimeScope::from_i32(3), None);
        assert_eq!(RuntimeScope::from_i32(100), None);
    }

    #[test]
    fn test_runtime_scope_to_i32_roundtrip() {
        for val in 0..3 {
            let scope = RuntimeScope::from_i32(val).unwrap();
            assert_eq!(scope.to_i32(), val);
        }
    }

    #[test]
    fn test_runtime_scope_to_string_all() {
        assert_eq!(
            runtime_scope_to_string(RuntimeScope::System),
            Some("system")
        );
        assert_eq!(runtime_scope_to_string(RuntimeScope::User), Some("user"));
        assert_eq!(
            runtime_scope_to_string(RuntimeScope::Global),
            Some("global")
        );
    }

    #[test]
    fn test_runtime_scope_from_string_valid() {
        assert_eq!(
            runtime_scope_from_string("system"),
            Ok(RuntimeScope::System)
        );
        assert_eq!(runtime_scope_from_string("user"), Ok(RuntimeScope::User));
        assert_eq!(
            runtime_scope_from_string("global"),
            Ok(RuntimeScope::Global)
        );
    }

    #[test]
    fn test_runtime_scope_from_string_invalid() {
        assert_eq!(runtime_scope_from_string("users"), Err(Errno::EINVAL));
        assert_eq!(runtime_scope_from_string(""), Err(Errno::EINVAL));
        assert_eq!(runtime_scope_from_string("SYSTEM"), Err(Errno::EINVAL));
    }

    #[test]
    fn test_runtime_scope_string_roundtrip() {
        for val in 0..3 {
            let scope = RuntimeScope::from_i32(val).unwrap();
            let s = runtime_scope_to_string(scope).unwrap();
            assert_eq!(runtime_scope_from_string(s), Ok(scope));
        }
    }

    #[test]
    fn test_runtime_scope_cmdline_option_to_string() {
        assert_eq!(
            runtime_scope_cmdline_option_to_string(RuntimeScope::System),
            Some("--system")
        );
        assert_eq!(
            runtime_scope_cmdline_option_to_string(RuntimeScope::User),
            Some("--user")
        );
        assert_eq!(
            runtime_scope_cmdline_option_to_string(RuntimeScope::Global),
            Some("--global")
        );
    }

    #[test]
    fn test_runtime_scope_to_socket_mode() {
        assert_eq!(runtime_scope_to_socket_mode(RuntimeScope::System), 0o666);
        assert_eq!(runtime_scope_to_socket_mode(RuntimeScope::User), 0o600);
        assert_eq!(
            runtime_scope_to_socket_mode(RuntimeScope::Global),
            MODE_INVALID
        );
    }

    #[test]
    fn test_runtime_scope_enum_equality() {
        assert_eq!(RuntimeScope::System, RuntimeScope::System);
        assert_ne!(RuntimeScope::System, RuntimeScope::User);
    }

    #[test]
    fn test_runtime_scope_copy() {
        let a = RuntimeScope::User;
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn test_runtime_scope_max_constant() {
        assert_eq!(RUNTIME_SCOPE_MAX, 3);
    }
}
