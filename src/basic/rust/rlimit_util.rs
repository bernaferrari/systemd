// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/basic/rlimit-util.c

use crate::ffi::{Errno, malloc};
use crate::ffi_string_table::{self, Entry as FfiEntry};
use libc::{c_char, c_int, rlim_t, rlimit};
use std::ffi::{CStr, CString};
use std::ptr;

pub const RLIM_INFINITY: u64 = u64::MAX;
const PRIO_MAX: i32 = 20;
const PRIO_MIN: i32 = -20;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RLimit {
    pub cur: u64,
    pub max: u64,
}

const RLIMIT_TABLE: &[FfiEntry] = &[
    (9, b"AS\0"),
    (4, b"CORE\0"),
    (0, b"CPU\0"),
    (2, b"DATA\0"),
    (1, b"FSIZE\0"),
    (10, b"LOCKS\0"),
    (8, b"MEMLOCK\0"),
    (12, b"MSGQUEUE\0"),
    (13, b"NICE\0"),
    (7, b"NOFILE\0"),
    (6, b"NPROC\0"),
    (5, b"RSS\0"),
    (14, b"RTPRIO\0"),
    (15, b"RTTIME\0"),
    (11, b"SIGPENDING\0"),
    (3, b"STACK\0"),
];

fn parse_u64_systemd(value: &str) -> Result<u64, Errno> {
    let value = CString::new(value).map_err(|_| Errno::EINVAL)?;
    let mut parsed = 0;
    // SAFETY: `value` is a live NUL-terminated string and `parsed` is writable
    // for the duration of the canonical Rust safe_atou64 implementation.
    let result = unsafe_ffi!(crate::parse_util::rs_safe_atou64(
        value.as_ptr(),
        &mut parsed
    ));
    if result < 0 {
        return Err(Errno::from_raw(-result).unwrap_or(Errno::EINVAL));
    }
    Ok(parsed)
}

pub fn rlimit_to_string(resource: i32) -> Option<&'static str> {
    ffi_string_table::to_str(RLIMIT_TABLE, resource)
}

pub fn rlimit_from_string(value: &str) -> Result<i32, Errno> {
    ffi_string_table::from_str(RLIMIT_TABLE, value).ok_or(Errno::EINVAL)
}

pub fn rlimit_from_string_harder(value: &str) -> Result<i32, Errno> {
    if let Some(suffix) = value.strip_prefix("RLIMIT_") {
        return rlimit_from_string(suffix);
    }
    if let Some(suffix) = value.strip_prefix("Limit") {
        return rlimit_from_string(suffix);
    }

    rlimit_from_string(value)
}

pub fn rlimit_parse_u64(value: &str) -> Result<u64, Errno> {
    if value == "infinity" {
        return Ok(RLIM_INFINITY);
    }

    let parsed = parse_u64_systemd(value)?;
    if parsed >= RLIM_INFINITY {
        return Err(Errno::ERANGE);
    }
    Ok(parsed)
}

pub fn rlimit_parse_size(value: &str) -> Result<u64, Errno> {
    if value == "infinity" {
        return Ok(RLIM_INFINITY);
    }

    let c_value = CString::new(value).map_err(|_| Errno::EINVAL)?;
    let mut parsed = 0_u64;
    // SAFETY: the raw pointer is derived from a live allocation and is used only for the duration of this operation.
    let r = unsafe_ffi!(crate::parse_util::rs_parse_size(
        c_value.as_ptr(),
        1024,
        &mut parsed
    ));
    if r < 0 {
        return Err(Errno::from_raw(-r).unwrap_or(Errno::EINVAL));
    }
    if parsed >= RLIM_INFINITY {
        return Err(Errno::ERANGE);
    }

    Ok(parsed)
}

pub fn rlimit_parse_nice(value: &str) -> Result<u64, Errno> {
    let parsed = if let Some(rest) = value.strip_prefix('+') {
        let nice = parse_u64_systemd(rest)?;
        if nice >= PRIO_MAX as u64 {
            return Err(Errno::ERANGE);
        }
        20 - nice
    } else if let Some(rest) = value.strip_prefix('-') {
        let nice = parse_u64_systemd(rest)?;
        if nice > (-PRIO_MIN) as u64 {
            return Err(Errno::ERANGE);
        }
        20 + nice
    } else {
        let raw = parse_u64_systemd(value)?;
        if raw > (20 - PRIO_MIN) as u64 {
            return Err(Errno::ERANGE);
        }
        raw
    };

    Ok(parsed)
}

pub fn rlimit_format(limit: RLimit) -> String {
    if limit.cur >= RLIM_INFINITY && limit.max >= RLIM_INFINITY {
        "infinity".to_string()
    } else if limit.cur >= RLIM_INFINITY {
        format!("infinity:{}", limit.max)
    } else if limit.max >= RLIM_INFINITY {
        format!("{}:infinity", limit.cur)
    } else if limit.cur == limit.max {
        limit.cur.to_string()
    } else {
        format!("{}:{}", limit.cur, limit.max)
    }
}

// SAFETY: the caller supplies the lifetime and validity of the borrowed C
// string; this helper rejects NULL and never lets the borrow escape an ABI call.
unsafe fn c_input<'a>(value: *const c_char) -> Result<&'a str, Errno> {
    if value.is_null() {
        return Err(Errno::EINVAL);
    }

    // SAFETY: callers of the C ABI wrappers must provide a live NUL-terminated
    // string; the returned borrow is consumed before the wrapper returns.
    unsafe_ffi!(CStr::from_ptr(value))
        .to_str()
        .map_err(|_| Errno::EINVAL)
}

// SAFETY: the caller must provide a valid C string and writable `rlim_t`
// storage. The helper validates NULL and preserves the output on parse errors.
unsafe fn write_parsed(
    value: *const c_char,
    ret: *mut rlim_t,
    parser: fn(&str) -> Result<u64, Errno>,
) -> c_int {
    if ret.is_null() {
        return Errno::EINVAL.to_neg_errno();
    }
    // SAFETY: inherited from this helper's C-string contract.
    let parsed = match unsafe_ffi!(c_input(value)).and_then(parser) {
        Ok(parsed) => parsed,
        Err(error) => return error.to_neg_errno(),
    };

    // SAFETY: NULL was rejected above and the C ABI requires `ret` to point to
    // writable `rlim_t` storage. Output is written only after successful parse.
    unsafe_ffi!(*ret = parsed as rlim_t);
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn rs_rlimit_to_string(resource: c_int) -> *const c_char {
    ffi_string_table::to_ptr(RLIMIT_TABLE, resource)
}

/// # Safety
///
/// `value`, when non-NULL, must point to a live NUL-terminated C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_rlimit_from_string(value: *const c_char) -> c_int {
    // SAFETY: this forwards the entry point's documented C-string contract.
    unsafe_ffi!(ffi_string_table::from_ptr(
        RLIMIT_TABLE,
        value,
        Errno::EINVAL.to_neg_errno()
    ))
}

/// # Safety
///
/// A non-NULL `value` must point to a live NUL-terminated C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_rlimit_from_string_harder(value: *const c_char) -> c_int {
    // SAFETY: this forwards the entry point's C-string contract.
    match unsafe_ffi!(c_input(value)).and_then(rlimit_from_string_harder) {
        Ok(resource) => resource,
        Err(error) => error.to_neg_errno(),
    }
}

/// # Safety
///
/// `value` must be a live C string and `ret` must be writable `rlim_t` storage.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_rlimit_parse_nice(value: *const c_char, ret: *mut rlim_t) -> c_int {
    // SAFETY: this forwards the entry point's C-string/output contracts.
    unsafe_ffi!(write_parsed(value, ret, rlimit_parse_nice))
}

/// # Safety
///
/// `value` must be a live C string and `ret` must be writable `rlim_t` storage.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_rlimit_parse_u64(value: *const c_char, ret: *mut rlim_t) -> c_int {
    // SAFETY: this forwards the entry point's C-string/output contracts.
    unsafe_ffi!(write_parsed(value, ret, rlimit_parse_u64))
}

/// # Safety
///
/// `value` must be a live C string and `ret` must be writable `rlim_t` storage.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_rlimit_parse_size(value: *const c_char, ret: *mut rlim_t) -> c_int {
    // SAFETY: this forwards the entry point's C-string/output contracts.
    unsafe_ffi!(write_parsed(value, ret, rlimit_parse_size))
}

/// Format a resource limit into a C-allocator-owned string.
///
/// # Safety
///
/// `limit` must point to a live `struct rlimit` and `ret` must point to writable
/// `char *` storage. On success the caller owns the returned `libc::malloc`
/// allocation and must release it with `free(3)`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_rlimit_format(limit: *const rlimit, ret: *mut *mut c_char) -> c_int {
    if limit.is_null() || ret.is_null() {
        return Errno::EINVAL.to_neg_errno();
    }

    // SAFETY: both pointer contracts are documented above and NULL was rejected.
    let limit = unsafe_ffi!(&*limit);
    let formatted = rlimit_format(RLimit {
        cur: limit.rlim_cur as u64,
        max: limit.rlim_max as u64,
    });
    let bytes = formatted.as_bytes();
    let Some(allocation_size) = bytes.len().checked_add(1) else {
        return Errno::ENOMEM.to_neg_errno();
    };
    let allocation = malloc(allocation_size).cast::<u8>();
    if allocation.is_null() {
        return Errno::ENOMEM.to_neg_errno();
    }

    // SAFETY: `allocation` owns `bytes.len() + 1` writable bytes, the source is
    // live and disjoint, and `ret` is writable by the entry-point contract.
    unsafe_ffi!({
        ptr::copy_nonoverlapping(bytes.as_ptr(), allocation, bytes.len());
        *allocation.add(bytes.len()) = 0;
        *ret = allocation.cast::<c_char>();
    });
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rlimit_string_conversion_roundtrips_known_resources() {
        for (resource, name) in RLIMIT_TABLE {
            let name = ffi_string_table::entry_str(name);
            assert_eq!(rlimit_to_string(*resource), Some(name));
            assert_eq!(rlimit_from_string(name), Ok(*resource));
        }
    }

    #[test]
    fn rlimit_to_string_rejects_unknown_resources() {
        assert_eq!(rlimit_to_string(-1), None);
        assert_eq!(rlimit_to_string(16), None);
    }

    #[test]
    fn rlimit_from_string_is_case_sensitive_like_c() {
        assert_eq!(rlimit_from_string("CPU"), Ok(0));
        assert_eq!(rlimit_from_string("cpu"), Err(Errno::EINVAL));
        assert_eq!(rlimit_from_string("BOGUS"), Err(Errno::EINVAL));
    }

    #[test]
    fn rlimit_from_string_harder_accepts_known_prefixes() {
        assert_eq!(rlimit_from_string_harder("RLIMIT_CPU"), Ok(0));
        assert_eq!(rlimit_from_string_harder("LimitNOFILE"), Ok(7));
        assert_eq!(rlimit_from_string_harder("INVALID"), Err(Errno::EINVAL));
    }

    #[test]
    fn rlimit_parse_u64_handles_infinity_and_plain_numbers() {
        assert_eq!(rlimit_parse_u64("infinity"), Ok(RLIM_INFINITY));
        assert_eq!(rlimit_parse_u64("1024"), Ok(1024));
        assert_eq!(rlimit_parse_u64("0x400"), Ok(1024));
        assert_eq!(rlimit_parse_u64("0b100"), Ok(4));
        assert_eq!(rlimit_parse_u64("abc"), Err(Errno::EINVAL));
    }

    #[test]
    fn rlimit_parse_size_uses_shared_size_parser() {
        assert_eq!(rlimit_parse_size("infinity"), Ok(RLIM_INFINITY));
        assert_eq!(rlimit_parse_size("1K"), Ok(1024));
        assert_eq!(rlimit_parse_size("2M"), Ok(2 * 1024 * 1024));
        assert_eq!(rlimit_parse_size("garbage"), Err(Errno::EINVAL));
    }

    #[test]
    fn rlimit_parse_nice_matches_kernel_mapping_rules() {
        assert_eq!(rlimit_parse_nice("+0"), Ok(20));
        assert_eq!(rlimit_parse_nice("+19"), Ok(1));
        assert_eq!(rlimit_parse_nice("+0x13"), Ok(1));
        assert_eq!(rlimit_parse_nice("-0"), Ok(20));
        assert_eq!(rlimit_parse_nice("-20"), Ok(40));
        assert_eq!(rlimit_parse_nice("0"), Ok(0));
        assert_eq!(rlimit_parse_nice("40"), Ok(40));
    }

    #[test]
    fn rlimit_parse_nice_enforces_c_ranges() {
        assert_eq!(rlimit_parse_nice("+20"), Err(Errno::ERANGE));
        assert_eq!(rlimit_parse_nice("-21"), Err(Errno::ERANGE));
        assert_eq!(rlimit_parse_nice("41"), Err(Errno::ERANGE));
    }

    #[test]
    fn rlimit_format_matches_c_output_cases() {
        assert_eq!(
            rlimit_format(RLimit {
                cur: RLIM_INFINITY,
                max: RLIM_INFINITY,
            }),
            "infinity"
        );
        assert_eq!(
            rlimit_format(RLimit {
                cur: RLIM_INFINITY,
                max: 50,
            }),
            "infinity:50"
        );
        assert_eq!(
            rlimit_format(RLimit {
                cur: 10,
                max: RLIM_INFINITY
            }),
            "10:infinity"
        );
        assert_eq!(rlimit_format(RLimit { cur: 10, max: 10 }), "10");
        assert_eq!(rlimit_format(RLimit { cur: 10, max: 20 }), "10:20");
    }
}
