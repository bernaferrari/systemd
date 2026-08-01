// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: scope=basic.basic-validators; authority=src/basic/cgroup-util.h,src/basic/io-util.h,src/basic/audit-util.h,src/basic/errno-list.h,src/basic/alloc-util.h,src/basic/string-util.h,src/basic/socket-util.h,src/basic/process-util.h,src/basic/pidref.h,src/basic/pidref.c,src/basic/fileio.h
//
// Small inline validation functions from various headers.

const CGROUP_WEIGHT_INVALID: u64 = u64::MAX;
const CGROUP_WEIGHT_MIN: u64 = 1;
const CGROUP_WEIGHT_MAX: u64 = 10_000;
const CGROUP_WEIGHT_DEFAULT: u64 = 100;

const CGROUP_BFQ_WEIGHT_MIN: u64 = 1;
const CGROUP_BFQ_WEIGHT_MAX: u64 = 1_000;
const CGROUP_BFQ_WEIGHT_DEFAULT: u64 = 100;

use libc::{c_char, c_int, c_uint, pid_t};

const ERRNO_MAX: c_int = 4095;
const PID_AUTOMATIC: pid_t = pid_t::MIN;

#[repr(C)]
pub struct PidRef {
    pid: libc::pid_t,
    fd: libc::c_int,
    fd_id: u64,
}

fn bool_string(value: bool, when_true: &'static [u8], when_false: &'static [u8]) -> *const c_char {
    if value {
        when_true.as_ptr().cast()
    } else {
        when_false.as_ptr().cast()
    }
}

/// Return `ptr` unless it is null or points to an empty C string.
///
/// # Safety
///
/// A non-null `ptr` must point to at least one readable `c_char`.
unsafe fn maybe_empty_string(ptr: *const c_char, replacement: &'static [u8]) -> *const c_char {
    if ptr.is_null() {
        return replacement.as_ptr().cast();
    }

    // SAFETY: guaranteed by this helper's caller contract.
    if unsafe_ffi!(*ptr) == 0 {
        replacement.as_ptr().cast()
    } else {
        ptr
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn rs_CGROUP_WEIGHT_IS_OK(x: u64) -> bool {
    x == CGROUP_WEIGHT_INVALID || (CGROUP_WEIGHT_MIN..=CGROUP_WEIGHT_MAX).contains(&x)
}

#[unsafe(no_mangle)]
pub extern "C" fn rs_BFQ_WEIGHT(io_weight: u64) -> u64 {
    if io_weight <= CGROUP_WEIGHT_DEFAULT {
        let difference = CGROUP_WEIGHT_DEFAULT.wrapping_sub(io_weight);
        let scaled = difference.wrapping_mul(CGROUP_BFQ_WEIGHT_DEFAULT - CGROUP_BFQ_WEIGHT_MIN)
            / (CGROUP_WEIGHT_DEFAULT - CGROUP_WEIGHT_MIN);
        CGROUP_BFQ_WEIGHT_DEFAULT.wrapping_sub(scaled)
    } else {
        let difference = io_weight.wrapping_sub(CGROUP_WEIGHT_DEFAULT);
        let scaled = difference.wrapping_mul(CGROUP_BFQ_WEIGHT_MAX - CGROUP_BFQ_WEIGHT_DEFAULT)
            / (CGROUP_WEIGHT_MAX - CGROUP_WEIGHT_DEFAULT);
        CGROUP_BFQ_WEIGHT_DEFAULT.wrapping_add(scaled)
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn rs_FILE_SIZE_VALID(l: u64) -> bool {
    (l >> 63) == 0
}

#[unsafe(no_mangle)]
pub extern "C" fn rs_FILE_SIZE_VALID_OR_INFINITY(l: u64) -> bool {
    l == u64::MAX || rs_FILE_SIZE_VALID(l)
}

#[unsafe(no_mangle)]
pub extern "C" fn rs_audit_session_is_valid(id: u32) -> bool {
    id > 0 && id != u32::MAX
}

#[unsafe(no_mangle)]
pub extern "C" fn rs_errno_is_valid(n: c_int) -> bool {
    n > 0 && n <= ERRNO_MAX
}

#[unsafe(no_mangle)]
pub extern "C" fn rs_VSOCK_CID_IS_REGULAR(cid: c_uint) -> bool {
    cid > 2 && cid < c_uint::MAX
}

#[unsafe(no_mangle)]
pub extern "C" fn rs_SIGINFO_CODE_IS_DEAD(code: c_int) -> bool {
    matches!(code, libc::CLD_EXITED | libc::CLD_KILLED | libc::CLD_DUMPED)
}

#[unsafe(no_mangle)]
pub extern "C" fn rs_pid_is_valid(p: pid_t) -> bool {
    p > 0
}

#[unsafe(no_mangle)]
pub extern "C" fn rs_pid_is_automatic(p: pid_t) -> bool {
    p == PID_AUTOMATIC
}

/// Check whether a C `PidRef` denotes a process.
///
/// # Safety
///
/// `pidref` must be null or point to a readable, properly aligned `PidRef`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_pidref_is_set(pidref: *const PidRef) -> bool {
    // SAFETY: after the null check, validity and alignment are guaranteed by
    // the caller contract.
    !pidref.is_null() && unsafe_ffi!((*pidref).pid > 0)
}

/// Check whether a C `PidRef` requests automatic acquisition.
///
/// # Safety
///
/// `pidref` must be null or point to a readable, properly aligned `PidRef`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_pidref_is_automatic(pidref: *const PidRef) -> bool {
    // SAFETY: after the null check, validity and alignment are guaranteed by
    // the caller contract.
    !pidref.is_null() && unsafe_ffi!((*pidref).pid == PID_AUTOMATIC)
}

/// Check whether a C `PidRef` is set or requests automatic acquisition.
///
/// # Safety
///
/// `pidref` must be null or point to a readable, properly aligned `PidRef`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_pidref_is_set_or_automatic(pidref: *const PidRef) -> bool {
    // SAFETY: forwarded unchanged under this function's identical contract.
    unsafe_ffi!(rs_pidref_is_set(pidref) || rs_pidref_is_automatic(pidref))
}

/// Check whether a set C `PidRef` represents a remote process.
///
/// # Safety
///
/// `pidref` must be null or point to a readable, properly aligned `PidRef`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_pidref_is_remote(pidref: *const PidRef) -> bool {
    // SAFETY: both calls/dereferences are covered by this function's caller
    // contract. Short-circuiting prevents a null dereference.
    unsafe_ffi!(rs_pidref_is_set(pidref) && (*pidref).fd == -libc::EREMOTE)
}

#[unsafe(no_mangle)]
pub extern "C" fn rs_size_multiply_overflow(size: usize, need: usize) -> bool {
    need != 0 && size > usize::MAX / need
}

#[unsafe(no_mangle)]
pub extern "C" fn rs_GREEDY_ALLOC_ROUND_UP(l: usize) -> usize {
    if l <= 2 {
        return 2;
    }

    l.checked_next_power_of_two().unwrap_or(l)
}

#[unsafe(no_mangle)]
pub extern "C" fn rs_file_offset_beyond_memory_size(x: libc::off_t) -> bool {
    // systemd requires _FILE_OFFSET_BITS=64 even on 32-bit targets.
    x >= 0 && (x as u64) > usize::MAX as u64
}

#[unsafe(no_mangle)]
pub extern "C" fn rs_strnull(s: *const c_char) -> *const c_char {
    if s.is_null() { c"(null)".as_ptr() } else { s }
}

#[unsafe(no_mangle)]
pub extern "C" fn rs_strna(s: *const c_char) -> *const c_char {
    if s.is_null() { c"n/a".as_ptr() } else { s }
}

#[unsafe(no_mangle)]
pub extern "C" fn rs_true_false(b: bool) -> *const c_char {
    bool_string(b, b"true\0", b"false\0")
}

#[unsafe(no_mangle)]
pub extern "C" fn rs_plus_minus(b: bool) -> *const c_char {
    bool_string(b, b"+\0", b"-\0")
}

#[unsafe(no_mangle)]
pub extern "C" fn rs_one_zero(b: bool) -> *const c_char {
    bool_string(b, b"1\0", b"0\0")
}

#[unsafe(no_mangle)]
pub extern "C" fn rs_enable_disable(b: bool) -> *const c_char {
    bool_string(b, b"enable\0", b"disable\0")
}

#[unsafe(no_mangle)]
pub extern "C" fn rs_enabled_disabled(b: bool) -> *const c_char {
    bool_string(b, b"enabled\0", b"disabled\0")
}

/// Substitute `"n/a"` for a null or empty C string.
///
/// # Safety
///
/// A non-null `p` must point to at least one readable `c_char`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_empty_to_na(p: *const c_char) -> *const c_char {
    // SAFETY: forwarded under this function's identical caller contract.
    unsafe_ffi!(maybe_empty_string(p, b"n/a\0"))
}

/// Substitute `"-"` for a null or empty C string.
///
/// # Safety
///
/// A non-null `s` must point to at least one readable `c_char`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_empty_to_dash(s: *const c_char) -> *const c_char {
    // SAFETY: forwarded under this function's identical caller contract.
    unsafe_ffi!(maybe_empty_string(s, b"-\0"))
}

/// Check whether a C string is null, empty, or exactly `"-"`.
///
/// # Safety
///
/// A non-null `s` must point to a readable NUL-terminated C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_empty_or_dash(s: *const c_char) -> bool {
    if s.is_null() {
        return true;
    }

    // SAFETY: the caller guarantees that `s` points to a readable
    // NUL-terminated string, so the first byte and, for "-", the next byte are
    // readable.
    let first = unsafe_ffi!(*s);
    // SAFETY: the same NUL-terminated caller contract makes `s.add(1)`
    // readable whenever the first byte is `'-'`.
    first == 0 || (first == b'-' as c_char && unsafe_ffi!(*s.add(1)) == 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::{CStr, CString};

    fn as_bytes(ptr: *const c_char) -> &'static [u8] {
        // SAFETY: the pointer is expected to reference a valid NUL-terminated C string for this call.
        unsafe_ffi!(CStr::from_ptr(ptr)).to_bytes()
    }

    #[test]
    fn cgroup_weight_validation_matches_header_rules() {
        assert!(rs_CGROUP_WEIGHT_IS_OK(CGROUP_WEIGHT_INVALID));
        assert!(rs_CGROUP_WEIGHT_IS_OK(CGROUP_WEIGHT_MIN));
        assert!(rs_CGROUP_WEIGHT_IS_OK(CGROUP_WEIGHT_MAX));
        assert!(!rs_CGROUP_WEIGHT_IS_OK(0));
        assert!(!rs_CGROUP_WEIGHT_IS_OK(CGROUP_WEIGHT_MAX + 1));
    }

    #[test]
    fn bfq_weight_matches_endpoints() {
        assert_eq!(rs_BFQ_WEIGHT(CGROUP_WEIGHT_MIN), CGROUP_BFQ_WEIGHT_MIN);
        assert_eq!(
            rs_BFQ_WEIGHT(CGROUP_WEIGHT_DEFAULT),
            CGROUP_BFQ_WEIGHT_DEFAULT
        );
        assert_eq!(rs_BFQ_WEIGHT(CGROUP_WEIGHT_MAX), CGROUP_BFQ_WEIGHT_MAX);
    }

    #[test]
    fn file_size_checks_match_signed_kernel_limit() {
        assert!(rs_FILE_SIZE_VALID(0));
        assert!(rs_FILE_SIZE_VALID(i64::MAX as u64));
        assert!(!rs_FILE_SIZE_VALID((i64::MAX as u64) + 1));
        assert!(rs_FILE_SIZE_VALID_OR_INFINITY(u64::MAX));
    }

    #[test]
    fn basic_integer_validators_match_c_helpers() {
        assert!(rs_audit_session_is_valid(1));
        assert!(!rs_audit_session_is_valid(0));
        assert!(rs_errno_is_valid(1));
        assert!(!rs_errno_is_valid(ERRNO_MAX + 1));
        assert!(rs_VSOCK_CID_IS_REGULAR(3));
        assert!(!rs_VSOCK_CID_IS_REGULAR(2));
    }

    #[test]
    fn siginfo_and_pid_helpers_match_headers() {
        assert!(rs_SIGINFO_CODE_IS_DEAD(libc::CLD_EXITED));
        assert!(rs_SIGINFO_CODE_IS_DEAD(libc::CLD_KILLED));
        assert!(!rs_SIGINFO_CODE_IS_DEAD(0));
        assert!(rs_pid_is_valid(1));
        assert!(!rs_pid_is_valid(0));
        assert!(rs_pid_is_automatic(PID_AUTOMATIC));
    }

    #[test]
    fn pidref_helpers_match_inline_c_logic() {
        let set = PidRef {
            pid: 7,
            fd: -libc::EREMOTE,
            fd_id: 0,
        };
        let automatic = PidRef {
            pid: PID_AUTOMATIC,
            fd: -1,
            fd_id: 0,
        };
        let unset = PidRef {
            pid: 0,
            fd: -1,
            fd_id: 0,
        };

        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        unsafe_ffi!({
            assert!(rs_pidref_is_set(&set));
            assert!(rs_pidref_is_remote(&set));
            assert!(rs_pidref_is_automatic(&automatic));
            assert!(rs_pidref_is_set_or_automatic(&automatic));
            assert!(!rs_pidref_is_set(&unset));
        })
    }

    #[test]
    fn allocation_helpers_preserve_overflow_behavior() {
        assert!(!rs_size_multiply_overflow(4, 8));
        assert!(rs_size_multiply_overflow(usize::MAX, 2));
        assert_eq!(rs_GREEDY_ALLOC_ROUND_UP(0), 2);
        assert_eq!(rs_GREEDY_ALLOC_ROUND_UP(2), 2);
        assert_eq!(rs_GREEDY_ALLOC_ROUND_UP(3), 4);
    }

    #[test]
    fn file_offset_limit_uses_size_max() {
        assert!(!rs_file_offset_beyond_memory_size(-1));
        assert!(!rs_file_offset_beyond_memory_size(0));
        assert_eq!(rs_file_offset_beyond_memory_size(usize::MAX as i64), false);
    }

    #[test]
    fn static_string_helpers_return_expected_literals() {
        assert_eq!(as_bytes(rs_strnull(std::ptr::null())), b"(null)");
        assert_eq!(as_bytes(rs_strna(std::ptr::null())), b"n/a");
        assert_eq!(as_bytes(rs_true_false(true)), b"true");
        assert_eq!(as_bytes(rs_plus_minus(false)), b"-");
        assert_eq!(as_bytes(rs_one_zero(true)), b"1");
        assert_eq!(as_bytes(rs_enable_disable(false)), b"disable");
        assert_eq!(as_bytes(rs_enabled_disabled(true)), b"enabled");
    }

    #[test]
    fn empty_string_helpers_match_c_semantics() {
        let empty = CString::new("").unwrap();
        let dash = CString::new("-").unwrap();
        let value = CString::new("value").unwrap();

        // SAFETY: the raw pointer is derived from a live allocation and is used only for the duration of this operation.
        unsafe_ffi!({
            assert_eq!(as_bytes(rs_empty_to_na(empty.as_ptr())), b"n/a");
            assert_eq!(as_bytes(rs_empty_to_dash(empty.as_ptr())), b"-");
            assert_eq!(as_bytes(rs_empty_to_na(value.as_ptr())), b"value");
            assert!(rs_empty_or_dash(std::ptr::null()));
            assert!(rs_empty_or_dash(empty.as_ptr()));
            assert!(rs_empty_or_dash(dash.as_ptr()));
            assert!(!rs_empty_or_dash(value.as_ptr()));
        })
    }
}
