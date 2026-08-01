// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: scope=basic.process-util-str-tables; authority=src/basic/process-util.c,src/basic/process-util.h,src/basic/string-table.c,src/basic/string-table.h,src/basic/parse-util.c,src/basic/parse-util.h
//
// Process utility string tables (sigchld_code, sched_policy)
// and process parameter validators.

use crate::ffi::{Errno, clear_errno, get_errno, is_whitespace, strtoul};
use crate::ffi_string_table::{self, Entry as FfiEntry};
use libc::c_char;
use std::ffi::CStr;

// ── sigchld_code table ────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum SigchldCode {
    Exited = 1,
    Killed = 2,
    Dumped = 3,
    Trapped = 4,
    Stopped = 5,
    Continued = 6,
}

static SIGCHLD_CODE_TABLE: &[FfiEntry] = &[
    (1, b"exited\0"),
    (2, b"killed\0"),
    (3, b"dumped\0"),
    (4, b"trapped\0"),
    (5, b"stopped\0"),
    (6, b"continued\0"),
];

pub fn sigchld_code_to_string(code: i32) -> Option<&'static str> {
    ffi_string_table::to_str(SIGCHLD_CODE_TABLE, code)
}

pub fn sigchld_code_from_string(s: &str) -> Result<i32, i32> {
    ffi_string_table::from_str(SIGCHLD_CODE_TABLE, s).ok_or(Errno::EINVAL.to_neg_errno())
}

// ── sched_policy table ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum SchedPolicy {
    Other = 0,
    Fifo = 1,
    Rr = 2,
    Batch = 3,
    Idle = 5,
    Ext = 7,
}

static SCHED_POLICY_TABLE: &[FfiEntry] = &[
    (0, b"other\0"),
    (1, b"fifo\0"),
    (2, b"rr\0"),
    (3, b"batch\0"),
    (5, b"idle\0"),
    (7, b"ext\0"),
];

pub fn sched_policy_to_string(policy: i32) -> Option<&'static str> {
    ffi_string_table::to_str(SCHED_POLICY_TABLE, policy)
}

pub fn sched_policy_from_string(s: &str) -> Result<i32, i32> {
    if let Some(policy) = ffi_string_table::from_str(SCHED_POLICY_TABLE, s) {
        return Ok(policy);
    }

    sched_policy_numeric_fallback_bytes(s.as_bytes()).ok_or(Errno::EINVAL.to_neg_errno())
}

/// Match `string_table_lookup_from_string_fallback()` for the numeric path.
///
/// The C helper first delegates named entries to the table, then accepts the
/// same unsigned integer spellings as `safe_atou()` up to `INT_MAX`. This is
/// deliberately byte-oriented: the public Rust API is UTF-8, but the C ABI
/// below must also preserve the invalid result for non-UTF-8 input.
fn sched_policy_numeric_fallback_bytes(input: &[u8]) -> Option<i32> {
    let mut start = 0;
    while start < input.len() && is_whitespace(input[start]) {
        start += 1;
    }

    let (digits, base) = match input.get(start..) {
        Some(bytes) if bytes.starts_with(b"0b") || bytes.starts_with(b"0B") => (&bytes[2..], 2),
        Some(bytes) if bytes.starts_with(b"0o") || bytes.starts_with(b"0O") => (&bytes[2..], 8),
        Some(bytes) => (bytes, 0),
        None => return None,
    };

    parse_unsigned_c_integer(digits, base)
        .filter(|&value| value <= i32::MAX as u32)
        .map(|value| value as i32)
}

/// Parse the numeric fallback using the C library's `strtoul()` semantics.
///
/// The caller passes a temporary NUL-backed byte string, so this remains a
/// safe Rust helper while keeping libc's locale-aware conversion behavior.
fn parse_unsigned_c_integer(digits: &[u8], base: i32) -> Option<u32> {
    let c_input = std::ffi::CString::new(digits).ok()?;
    let mut end = std::ptr::null_mut();

    clear_errno();
    // SAFETY: `c_input` is a live NUL-terminated C string and `end` is a
    // writable local end-pointer for the duration of this call.
    let value = unsafe_ffi!(strtoul(c_input.as_ptr(), &mut end, base));
    if get_errno() != 0 || end.is_null() || end == c_input.as_ptr().cast_mut() {
        return None;
    }
    // SAFETY: `end` was produced by `strtoul()` for the live `c_input` buffer.
    if unsafe_ffi!(*end) != 0 {
        return None;
    }
    if value != 0 && digits.first() == Some(&b'-') {
        return None;
    }

    u32::try_from(value).ok()
}

/// C ABI facade for `sigchld_code_to_string()`.
///
/// The returned pointer is borrowed immutable static storage. Invalid values
/// return NULL, exactly like the C `DEFINE_STRING_TABLE_LOOKUP` expansion.
#[unsafe(no_mangle)]
pub extern "C" fn rs_sigchld_code_to_string(code: i32) -> *const c_char {
    ffi_string_table::to_ptr(SIGCHLD_CODE_TABLE, code)
}

/// C ABI facade for `sigchld_code_from_string()`.
///
/// # Safety
///
/// `s` may be NULL, which returns `-EINVAL`. A non-NULL pointer must reference
/// a live NUL-terminated C string for this call; it remains C-owned.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_sigchld_code_from_string(s: *const c_char) -> i32 {
    // SAFETY: this forwards the documented C-string contract unchanged.
    unsafe_ffi!(ffi_string_table::from_ptr(
        SIGCHLD_CODE_TABLE,
        s,
        Errno::EINVAL.to_neg_errno()
    ))
}

/// C ABI facade for `sched_policy_to_string_alloc()`.
///
/// On success this publishes a fresh C-allocator-owned string through `ret`;
/// callers release it with `free(3)`. The C API accepts every non-negative
/// `int`, using a named table entry where available and a decimal fallback for
/// table gaps. Negative values return `-ERANGE` without modifying `*ret`.
///
/// # Safety
///
/// `ret` must point to writable pointer storage for this call. On success the
/// returned allocation belongs to the caller and must be released by the C
/// allocator. A null `ret` is outside the C contract and fails closed here.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_sched_policy_to_string_alloc(
    policy: i32,
    ret: *mut *mut c_char,
) -> i32 {
    if ret.is_null() {
        return Errno::EINVAL.to_neg_errno();
    }
    if policy < 0 {
        return Errno::ERANGE.to_neg_errno();
    }

    let mut fallback = [0_u8; 11]; // INT_MAX decimal digits plus the NUL.
    let named = ffi_string_table::to_ptr(SCHED_POLICY_TABLE, policy);
    let source = if !named.is_null() {
        named
    } else {
        let mut number = policy as u32;
        // Keep the final byte as the terminator while filling decimal digits
        // backwards. `INT_MAX` uses all ten preceding byte slots.
        let mut cursor = fallback.len() - 2;
        loop {
            fallback[cursor] = b'0' + (number % 10) as u8;
            number /= 10;
            if number == 0 {
                break;
            }
            cursor -= 1;
        }
        fallback[cursor..].as_ptr().cast::<c_char>()
    };

    // SAFETY: `source` is either a checked static C string or the local
    // NUL-terminated fallback buffer. `strdup()` returns C-allocator storage.
    let allocated = unsafe_ffi!(libc::strdup(source));
    if allocated.is_null() {
        return Errno::ENOMEM.to_neg_errno();
    }

    // SAFETY: required by this entry point's documented output contract.
    unsafe_ffi!(*ret = allocated);
    0
}

/// C ABI facade for `sched_policy_from_string()`.
///
/// # Safety
///
/// `s` may be NULL, which returns `-EINVAL`. Any non-NULL pointer must be a
/// live NUL-terminated C string for the duration of the call and remains owned
/// by C.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_sched_policy_from_string(s: *const c_char) -> i32 {
    if s.is_null() {
        return Errno::EINVAL.to_neg_errno();
    }

    // SAFETY: `s` is non-NULL and satisfies this entry point's documented
    // C-string contract; the bytes are borrowed only for this call.
    let input = unsafe_ffi!(CStr::from_ptr(s)).to_bytes();
    if let Some(policy) = SCHED_POLICY_TABLE.iter().find_map(|&(policy, name)| {
        (ffi_string_table::entry_cstr(name).to_bytes() == input).then_some(policy)
    }) {
        return policy;
    }

    sched_policy_numeric_fallback_bytes(input).unwrap_or_else(|| Errno::EINVAL.to_neg_errno())
}

// ── Validators ─────────────────────────────────────────────────────────────

const PRIO_MIN_VAL: i32 = -20;
const PRIO_MAX_VAL: i32 = 20;

pub fn nice_is_valid(n: i32) -> bool {
    n >= PRIO_MIN_VAL && n < PRIO_MAX_VAL
}

const SCHED_POLICY_VALUES: &[i32] = &[0, 1, 2, 3, 5, 7];

pub fn sched_policy_is_valid(policy: i32) -> bool {
    SCHED_POLICY_VALUES.contains(&policy)
}

const OOM_SCORE_ADJ_MIN: i32 = -1000;
const OOM_SCORE_ADJ_MAX: i32 = 1000;

pub fn oom_score_adjust_is_valid(oa: i32) -> bool {
    oa >= OOM_SCORE_ADJ_MIN && oa <= OOM_SCORE_ADJ_MAX
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sigchld_code_to_string_all() {
        assert_eq!(sigchld_code_to_string(1), Some("exited"));
        assert_eq!(sigchld_code_to_string(2), Some("killed"));
        assert_eq!(sigchld_code_to_string(3), Some("dumped"));
        assert_eq!(sigchld_code_to_string(4), Some("trapped"));
        assert_eq!(sigchld_code_to_string(5), Some("stopped"));
        assert_eq!(sigchld_code_to_string(6), Some("continued"));
    }

    #[test]
    fn test_sigchld_code_to_string_invalid() {
        assert!(sigchld_code_to_string(0).is_none());
        assert!(sigchld_code_to_string(7).is_none());
        assert!(sigchld_code_to_string(-1).is_none());
        assert!(sigchld_code_to_string(100).is_none());
    }

    #[test]
    fn test_sigchld_code_from_string_all() {
        assert_eq!(sigchld_code_from_string("exited"), Ok(1));
        assert_eq!(sigchld_code_from_string("killed"), Ok(2));
        assert_eq!(sigchld_code_from_string("dumped"), Ok(3));
        assert_eq!(sigchld_code_from_string("trapped"), Ok(4));
        assert_eq!(sigchld_code_from_string("stopped"), Ok(5));
        assert_eq!(sigchld_code_from_string("continued"), Ok(6));
    }

    #[test]
    fn test_sigchld_code_from_string_invalid() {
        assert_eq!(
            sigchld_code_from_string("unknown"),
            Err(Errno::EINVAL.to_neg_errno())
        );
        assert_eq!(
            sigchld_code_from_string(""),
            Err(Errno::EINVAL.to_neg_errno())
        );
    }

    #[test]
    fn test_sigchld_code_roundtrip() {
        for code in 1..=6 {
            let s = sigchld_code_to_string(code).unwrap();
            assert_eq!(sigchld_code_from_string(s), Ok(code));
        }
    }

    #[test]
    fn test_sched_policy_to_string_all() {
        assert_eq!(sched_policy_to_string(0), Some("other"));
        assert_eq!(sched_policy_to_string(1), Some("fifo"));
        assert_eq!(sched_policy_to_string(2), Some("rr"));
        assert_eq!(sched_policy_to_string(3), Some("batch"));
        assert_eq!(sched_policy_to_string(5), Some("idle"));
        assert_eq!(sched_policy_to_string(7), Some("ext"));
    }

    #[test]
    fn test_sched_policy_to_string_invalid() {
        assert!(sched_policy_to_string(4).is_none());
        assert!(sched_policy_to_string(6).is_none());
        assert!(sched_policy_to_string(-1).is_none());
    }

    #[test]
    fn test_sched_policy_from_string_all() {
        assert_eq!(sched_policy_from_string("other"), Ok(0));
        assert_eq!(sched_policy_from_string("fifo"), Ok(1));
        assert_eq!(sched_policy_from_string("rr"), Ok(2));
        assert_eq!(sched_policy_from_string("batch"), Ok(3));
        assert_eq!(sched_policy_from_string("idle"), Ok(5));
        assert_eq!(sched_policy_from_string("ext"), Ok(7));
    }

    #[test]
    fn test_sched_policy_from_string_numeric() {
        assert_eq!(sched_policy_from_string("4"), Ok(4));
        assert_eq!(sched_policy_from_string("6"), Ok(6));
        assert_eq!(sched_policy_from_string("0"), Ok(0));
        assert_eq!(sched_policy_from_string("-1"), Ok(-1));
    }

    #[test]
    fn test_sched_policy_from_string_invalid() {
        assert_eq!(
            sched_policy_from_string("unknown"),
            Err(Errno::EINVAL.to_neg_errno())
        );
        assert_eq!(
            sched_policy_from_string(""),
            Err(Errno::EINVAL.to_neg_errno())
        );
        assert_eq!(
            sched_policy_from_string("abc"),
            Err(Errno::EINVAL.to_neg_errno())
        );
    }

    #[test]
    fn test_sched_policy_roundtrip() {
        for &policy in &[0, 1, 2, 3, 5, 7] {
            let s = sched_policy_to_string(policy).unwrap();
            assert_eq!(sched_policy_from_string(s), Ok(policy));
        }
    }

    #[test]
    fn test_nice_is_valid() {
        assert!(nice_is_valid(-20));
        assert!(nice_is_valid(0));
        assert!(nice_is_valid(19));
        assert!(!nice_is_valid(20));
        assert!(!nice_is_valid(-21));
        assert!(!nice_is_valid(100));
    }

    #[test]
    fn test_sched_policy_is_valid() {
        assert!(sched_policy_is_valid(0));
        assert!(sched_policy_is_valid(1));
        assert!(sched_policy_is_valid(2));
        assert!(sched_policy_is_valid(3));
        assert!(sched_policy_is_valid(5));
        assert!(sched_policy_is_valid(7));
        assert!(!sched_policy_is_valid(4));
        assert!(!sched_policy_is_valid(6));
        assert!(!sched_policy_is_valid(-1));
    }

    #[test]
    fn test_oom_score_adjust_is_valid() {
        assert!(oom_score_adjust_is_valid(-1000));
        assert!(oom_score_adjust_is_valid(0));
        assert!(oom_score_adjust_is_valid(1000));
        assert!(!oom_score_adjust_is_valid(-1001));
        assert!(!oom_score_adjust_is_valid(1001));
    }
}
