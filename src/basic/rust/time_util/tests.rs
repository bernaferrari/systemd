// SPDX-License-Identifier: LGPL-2.1-or-later
//
// Tests for the time utility shadow subset.

#[cfg(test)]
mod tests {
    use super::arithmetic::{
        rs_dual_timestamp_is_set, rs_timestamp_is_set, rs_triple_timestamp_is_set, rs_usec_add,
        rs_usec_sub_signed, rs_usec_sub_unsigned,
    };
    use super::conversion::{
        rs_map_clock_usec_raw, rs_timespec_load, rs_timespec_load_nsec, rs_timespec_store,
        rs_timespec_store_nsec, rs_timeval_load, rs_timeval_store, rs_triple_timestamp_by_clock,
    };
    use super::formatting::{
        rs_format_timespan, rs_parse_gmtoff, rs_timestamp_style_from_string,
        rs_timestamp_style_to_string,
    };
    use super::parsing::{
        rs_parse_sec, rs_parse_sec_def_infinity, rs_parse_sec_fix_0, rs_parse_time,
    };
    use super::types::{
        CLOCK_BOOTTIME, CLOCK_BOOTTIME_ALARM, CLOCK_MONOTONIC, CLOCK_REALTIME,
        CLOCK_REALTIME_ALARM, DualTimestamp, LibcTimespec, LibcTimeval, NSEC_INFINITY,
        NSEC_PER_SEC, TripleTimestamp, USEC_INFINITY, USEC_PER_DAY, USEC_PER_HOUR, USEC_PER_MINUTE,
        USEC_PER_MONTH, USEC_PER_MSEC, USEC_PER_SEC, USEC_PER_WEEK, USEC_PER_YEAR,
    };
    use libc::c_char;

    use crate::ffi::Errno;
    use std::ffi::{CStr, CString, c_long};

    // ── rs_map_clock_usec_raw ───────────────────────────────────────────────

    #[test]
    fn test_map_clock_usec_raw_future() {
        assert_eq!(rs_map_clock_usec_raw(100, 50, 200), 250);
    }

    #[test]
    fn test_map_clock_usec_raw_past() {
        assert_eq!(rs_map_clock_usec_raw(30, 50, 200), 180);
    }

    #[test]
    fn test_map_clock_usec_raw_same() {
        assert_eq!(rs_map_clock_usec_raw(50, 50, 200), 200);
    }

    #[test]
    fn test_map_clock_usec_raw_overflow_to_infinity() {
        let result = rs_map_clock_usec_raw(u64::MAX, 0, u64::MAX - 1);
        assert_eq!(result, USEC_INFINITY);
    }

    #[test]
    fn test_map_clock_usec_raw_underflow_to_zero() {
        assert_eq!(rs_map_clock_usec_raw(0, 100, 50), 0);
    }

    #[test]
    fn test_map_clock_usec_raw_zero_values() {
        assert_eq!(rs_map_clock_usec_raw(0, 0, 100), 100);
    }

    #[test]
    fn test_calendar_unit_constants_match_time_util_header() {
        assert_eq!(USEC_PER_MONTH, 2_629_800 * USEC_PER_SEC);
        assert_eq!(USEC_PER_YEAR, 31_557_600 * USEC_PER_SEC);
    }

    // ── rs_timespec_load ────────────────────────────────────────────────────

    #[test]
    fn test_timespec_load_null() {
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        let result = unsafe { rs_timespec_load(std::ptr::null()) };
        assert_eq!(result, 0);
    }

    #[test]
    fn test_timespec_load_valid() {
        let ts = LibcTimespec {
            tv_sec: 5,
            tv_nsec: 500_000_000,
        };
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        let result = unsafe { rs_timespec_load(&ts) };
        assert_eq!(result, 5 * USEC_PER_SEC + 500_000);
    }

    #[test]
    fn test_timespec_load_zero() {
        let ts = LibcTimespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        let result = unsafe { rs_timespec_load(&ts) };
        assert_eq!(result, 0);
    }

    #[test]
    fn test_timespec_load_negative_sec() {
        let ts = LibcTimespec {
            tv_sec: -1,
            tv_nsec: 0,
        };
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        let result = unsafe { rs_timespec_load(&ts) };
        assert_eq!(result, USEC_INFINITY);
    }

    #[test]
    fn test_timespec_load_negative_nsec() {
        let ts = LibcTimespec {
            tv_sec: 1,
            tv_nsec: -1,
        };
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        let result = unsafe { rs_timespec_load(&ts) };
        assert_eq!(result, USEC_INFINITY);
    }

    // ── rs_timespec_load_nsec ───────────────────────────────────────────────

    #[test]
    fn test_timespec_load_nsec_null() {
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        let result = unsafe { rs_timespec_load_nsec(std::ptr::null()) };
        assert_eq!(result, 0);
    }

    #[test]
    fn test_timespec_load_nsec_valid() {
        let ts = LibcTimespec {
            tv_sec: 2,
            tv_nsec: 500_000_000,
        };
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        let result = unsafe { rs_timespec_load_nsec(&ts) };
        assert_eq!(result, 2 * NSEC_PER_SEC + 500_000_000);
    }

    #[test]
    fn test_timespec_load_nsec_negative() {
        let ts = LibcTimespec {
            tv_sec: -1,
            tv_nsec: 0,
        };
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        let result = unsafe { rs_timespec_load_nsec(&ts) };
        assert_eq!(result, NSEC_INFINITY);
    }

    // ── rs_timespec_store ───────────────────────────────────────────────────

    #[test]
    fn test_timespec_store_null() {
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        let result = unsafe { rs_timespec_store(std::ptr::null_mut(), 1000) };
        assert!(result.is_null());
    }

    #[test]
    fn test_timespec_store_valid() {
        let mut ts = LibcTimespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        let usec = 5_500_000u64;
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        let result = unsafe { rs_timespec_store(&mut ts, usec) };
        assert_eq!(result as *const _, &ts as *const _);
        assert_eq!(ts.tv_sec, 5);
        assert_eq!(ts.tv_nsec, 500_000_000);
    }

    #[test]
    fn test_timespec_store_infinity() {
        let mut ts = LibcTimespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        unsafe { rs_timespec_store(&mut ts, USEC_INFINITY) };
        assert_eq!(ts.tv_sec, -1);
        assert_eq!(ts.tv_nsec, -1);
    }

    #[test]
    fn test_timespec_store_zero() {
        let mut ts = LibcTimespec {
            tv_sec: 99,
            tv_nsec: 999,
        };
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        unsafe { rs_timespec_store(&mut ts, 0) };
        assert_eq!(ts.tv_sec, 0);
        assert_eq!(ts.tv_nsec, 0);
    }

    // ── rs_timespec_store_nsec ──────────────────────────────────────────────

    #[test]
    fn test_timespec_store_nsec_null() {
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        let result = unsafe { rs_timespec_store_nsec(std::ptr::null_mut(), 1000) };
        assert!(result.is_null());
    }

    #[test]
    fn test_timespec_store_nsec_valid() {
        let mut ts = LibcTimespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        let nsec = 2_500_000_000u64;
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        unsafe { rs_timespec_store_nsec(&mut ts, nsec) };
        assert_eq!(ts.tv_sec, 2);
        assert_eq!(ts.tv_nsec, 500_000_000);
    }

    #[test]
    fn test_timespec_store_nsec_infinity() {
        let mut ts = LibcTimespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        unsafe { rs_timespec_store_nsec(&mut ts, NSEC_INFINITY) };
        assert_eq!(ts.tv_sec, -1);
        assert_eq!(ts.tv_nsec, -1);
    }

    // ── rs_timeval_load ─────────────────────────────────────────────────────

    #[test]
    fn test_timeval_load_null() {
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        let result = unsafe { rs_timeval_load(std::ptr::null()) };
        assert_eq!(result, 0);
    }

    #[test]
    fn test_timeval_load_valid() {
        let tv = LibcTimeval {
            tv_sec: 3,
            tv_usec: 250_000,
        };
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        let result = unsafe { rs_timeval_load(&tv) };
        assert_eq!(result, 3 * USEC_PER_SEC + 250_000);
    }

    #[test]
    fn test_timeval_load_negative() {
        let tv = LibcTimeval {
            tv_sec: -1,
            tv_usec: 0,
        };
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        let result = unsafe { rs_timeval_load(&tv) };
        assert_eq!(result, USEC_INFINITY);
    }

    // ── rs_timeval_store ────────────────────────────────────────────────────

    #[test]
    fn test_timeval_store_null() {
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        let result = unsafe { rs_timeval_store(std::ptr::null_mut(), 1000) };
        assert!(result.is_null());
    }

    #[test]
    fn test_timeval_store_valid() {
        let mut tv = LibcTimeval {
            tv_sec: 0,
            tv_usec: 0,
        };
        let usec = 7_123_456u64;
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        unsafe { rs_timeval_store(&mut tv, usec) };
        assert_eq!(tv.tv_sec, 7);
        assert_eq!(tv.tv_usec, 123_456);
    }

    #[test]
    fn test_timeval_store_infinity() {
        let mut tv = LibcTimeval {
            tv_sec: 0,
            tv_usec: 0,
        };
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        unsafe { rs_timeval_store(&mut tv, USEC_INFINITY) };
        assert_eq!(tv.tv_sec, -1);
        assert_eq!(tv.tv_usec, -1);
    }

    // ── rs_triple_timestamp_by_clock ────────────────────────────────────────

    #[test]
    fn test_triple_timestamp_by_clock_null() {
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        let result = unsafe { rs_triple_timestamp_by_clock(std::ptr::null(), CLOCK_REALTIME) };
        assert_eq!(result, 0);
    }

    #[test]
    fn test_triple_timestamp_by_clock_realtime() {
        let ts = TripleTimestamp {
            realtime: 1000,
            monotonic: 2000,
            boottime: 3000,
        };
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        let result = unsafe { rs_triple_timestamp_by_clock(&ts, CLOCK_REALTIME) };
        assert_eq!(result, 1000);
    }

    #[test]
    fn test_triple_timestamp_by_clock_monotonic() {
        let ts = TripleTimestamp {
            realtime: 1000,
            monotonic: 2000,
            boottime: 3000,
        };
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        let result = unsafe { rs_triple_timestamp_by_clock(&ts, CLOCK_MONOTONIC) };
        assert_eq!(result, 2000);
    }

    #[test]
    fn test_triple_timestamp_by_clock_boottime() {
        let ts = TripleTimestamp {
            realtime: 1000,
            monotonic: 2000,
            boottime: 3000,
        };
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        let result = unsafe { rs_triple_timestamp_by_clock(&ts, CLOCK_BOOTTIME) };
        assert_eq!(result, 3000);
    }

    #[test]
    fn test_triple_timestamp_by_clock_realtime_alarm() {
        let ts = TripleTimestamp {
            realtime: 1000,
            monotonic: 2000,
            boottime: 3000,
        };
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        let result = unsafe { rs_triple_timestamp_by_clock(&ts, CLOCK_REALTIME_ALARM) };
        assert_eq!(result, 1000);
    }

    #[test]
    fn test_triple_timestamp_by_clock_boottime_alarm() {
        let ts = TripleTimestamp {
            realtime: 1000,
            monotonic: 2000,
            boottime: 3000,
        };
        // SAFETY: the raw pointer is derived from a live stack value.
        let result = unsafe { rs_triple_timestamp_by_clock(&ts, CLOCK_BOOTTIME_ALARM) };
        assert_eq!(result, 3000);
    }

    #[test]
    fn test_triple_timestamp_by_clock_invalid() {
        let ts = TripleTimestamp {
            realtime: 1000,
            monotonic: 2000,
            boottime: 3000,
        };
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        let result = unsafe { rs_triple_timestamp_by_clock(&ts, 999) };
        assert_eq!(result, USEC_INFINITY);
    }

    // ── rs_timestamp_style_to_string ────────────────────────────────────────

    #[test]
    fn test_timestamp_style_to_string_pretty() {
        // SAFETY: returns either null or a pointer to a static NUL-terminated entry in TIMESTAMP_STYLE_NAMES.
        let result = unsafe { rs_timestamp_style_to_string(0) };
        assert!(!result.is_null());
        // SAFETY: `result` was checked for null and points to a static NUL-terminated string.
        let s = unsafe { CStr::from_ptr(result) };
        assert_eq!(s.to_bytes(), b"pretty");
    }

    #[test]
    fn test_timestamp_style_to_string_us() {
        // SAFETY: returns either null or a pointer to a static NUL-terminated entry in TIMESTAMP_STYLE_NAMES.
        let result = unsafe { rs_timestamp_style_to_string(1) };
        assert!(!result.is_null());
        // SAFETY: `result` was checked for null and points to a static NUL-terminated string.
        let s = unsafe { CStr::from_ptr(result) };
        assert_eq!(s.to_bytes(), b"us");
    }

    #[test]
    fn test_timestamp_style_to_string_utc() {
        // SAFETY: returns either null or a pointer to a static NUL-terminated entry in TIMESTAMP_STYLE_NAMES.
        let result = unsafe { rs_timestamp_style_to_string(2) };
        assert!(!result.is_null());
        // SAFETY: `result` was checked for null and points to a static NUL-terminated string.
        let s = unsafe { CStr::from_ptr(result) };
        assert_eq!(s.to_bytes(), b"utc");
    }

    #[test]
    fn test_timestamp_style_to_string_us_utc() {
        // SAFETY: returns either null or a pointer to a static NUL-terminated entry in TIMESTAMP_STYLE_NAMES.
        let result = unsafe { rs_timestamp_style_to_string(3) };
        assert!(!result.is_null());
        // SAFETY: `result` was checked for null and points to a static NUL-terminated string.
        let s = unsafe { CStr::from_ptr(result) };
        assert_eq!(s.to_bytes(), b"us+utc");
    }

    #[test]
    fn test_timestamp_style_to_string_unix() {
        // SAFETY: returns either null or a pointer to a static NUL-terminated entry in TIMESTAMP_STYLE_NAMES.
        let result = unsafe { rs_timestamp_style_to_string(4) };
        assert!(!result.is_null());
        // SAFETY: `result` was checked for null and points to a static NUL-terminated string.
        let s = unsafe { CStr::from_ptr(result) };
        assert_eq!(s.to_bytes(), b"unix");
    }

    #[test]
    fn test_timestamp_style_to_string_invalid() {
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        let result = unsafe { rs_timestamp_style_to_string(99) };
        assert!(result.is_null());
    }

    #[test]
    fn test_timestamp_style_to_string_negative() {
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        let result = unsafe { rs_timestamp_style_to_string(-1) };
        assert!(result.is_null());
    }

    // ── rs_timestamp_style_from_string ──────────────────────────────────────

    #[test]
    fn test_timestamp_style_from_string_null() {
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        let result = unsafe { rs_timestamp_style_from_string(std::ptr::null()) };
        assert_eq!(result, Errno::EINVAL.to_neg_errno());
    }

    #[test]
    fn test_timestamp_style_from_string_pretty() {
        let s = CString::new("pretty").unwrap();
        // SAFETY: the raw pointer is derived from a live allocation and is used only for the duration of this operation.
        let result = unsafe { rs_timestamp_style_from_string(s.as_ptr()) };
        assert_eq!(result, 0);
    }

    #[test]
    fn test_timestamp_style_from_string_us() {
        let s = CString::new("us").unwrap();
        // SAFETY: the raw pointer is derived from a live allocation and is used only for the duration of this operation.
        let result = unsafe { rs_timestamp_style_from_string(s.as_ptr()) };
        assert_eq!(result, 1);
    }

    #[test]
    fn test_timestamp_style_from_string_utc() {
        let s = CString::new("utc").unwrap();
        // SAFETY: the raw pointer is derived from a live allocation and is used only for the duration of this operation.
        let result = unsafe { rs_timestamp_style_from_string(s.as_ptr()) };
        assert_eq!(result, 2);
    }

    #[test]
    fn test_timestamp_style_from_string_us_utc() {
        let s = CString::new("us+utc").unwrap();
        // SAFETY: the raw pointer is derived from a live allocation and is used only for the duration of this operation.
        let result = unsafe { rs_timestamp_style_from_string(s.as_ptr()) };
        assert_eq!(result, 3);
    }

    #[test]
    fn test_timestamp_style_from_string_unix() {
        let s = CString::new("unix").unwrap();
        // SAFETY: the raw pointer is derived from a live allocation and is used only for the duration of this operation.
        let result = unsafe { rs_timestamp_style_from_string(s.as_ptr()) };
        assert_eq!(result, 4);
    }

    #[test]
    fn test_timestamp_style_from_string_micro_sign() {
        let s = [0xC2u8, 0xB5, b's', 0];
        // SAFETY: the raw pointer is derived from a live allocation and is used only for the duration of this operation.
        let result = unsafe { rs_timestamp_style_from_string(s.as_ptr() as *const c_char) };
        assert_eq!(result, 1);
    }

    #[test]
    fn test_timestamp_style_from_string_greek_mu() {
        let s = [0xCEu8, 0xBC, b's', 0];
        // SAFETY: the raw pointer is derived from a live allocation and is used only for the duration of this operation.
        let result = unsafe { rs_timestamp_style_from_string(s.as_ptr() as *const c_char) };
        assert_eq!(result, 1);
    }

    #[test]
    fn test_timestamp_style_from_string_micro_sign_utc() {
        let s = [0xC2u8, 0xB5, b's', b'+', b'u', b't', b'c', 0];
        // SAFETY: the raw pointer is derived from a live allocation and is used only for the duration of this operation.
        let result = unsafe { rs_timestamp_style_from_string(s.as_ptr() as *const c_char) };
        assert_eq!(result, 3);
    }

    #[test]
    fn test_timestamp_style_from_string_invalid() {
        let s = CString::new("invalid").unwrap();
        // SAFETY: the raw pointer is derived from a live allocation and is used only for the duration of this operation.
        let result = unsafe { rs_timestamp_style_from_string(s.as_ptr()) };
        assert_eq!(result, Errno::EINVAL.to_neg_errno());
    }

    #[test]
    fn test_timestamp_style_from_string_empty() {
        let s = CString::new("").unwrap();
        // SAFETY: the raw pointer is derived from a live allocation and is used only for the duration of this operation.
        let result = unsafe { rs_timestamp_style_from_string(s.as_ptr()) };
        assert_eq!(result, Errno::EINVAL.to_neg_errno());
    }

    // ── rs_parse_gmtoff ─────────────────────────────────────────────────────

    #[test]
    fn test_parse_gmtoff_null() {
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        let result = unsafe { rs_parse_gmtoff(std::ptr::null(), std::ptr::null_mut()) };
        assert_eq!(result, Errno::EINVAL.to_neg_errno());
    }

    #[test]
    fn test_parse_gmtoff_plus0900() {
        let s = CString::new("+0900").unwrap();
        let mut ret: c_long = 0;
        // SAFETY: the raw pointer is derived from a live allocation and is used only for the duration of this operation.
        let result = unsafe { rs_parse_gmtoff(s.as_ptr(), &mut ret) };
        assert_eq!(result, 0);
        assert_eq!(ret, 9 * 3600);
    }

    #[test]
    fn test_parse_gmtoff_minus0500() {
        let s = CString::new("-0500").unwrap();
        let mut ret: c_long = 0;
        // SAFETY: the raw pointer is derived from a live allocation and is used only for the duration of this operation.
        let result = unsafe { rs_parse_gmtoff(s.as_ptr(), &mut ret) };
        assert_eq!(result, 0);
        assert_eq!(ret, -5 * 3600);
    }

    #[test]
    fn test_parse_gmtoff_plus09() {
        let s = CString::new("+09").unwrap();
        let mut ret: c_long = 0;
        // SAFETY: the raw pointer is derived from a live allocation and is used only for the duration of this operation.
        let result = unsafe { rs_parse_gmtoff(s.as_ptr(), &mut ret) };
        assert_eq!(result, 0);
        assert_eq!(ret, 9 * 3600);
    }

    #[test]
    fn test_parse_gmtoff_plus09_colon_30() {
        let s = CString::new("+09:30").unwrap();
        let mut ret: c_long = 0;
        // SAFETY: the raw pointer is derived from a live allocation and is used only for the duration of this operation.
        let result = unsafe { rs_parse_gmtoff(s.as_ptr(), &mut ret) };
        assert_eq!(result, 0);
        assert_eq!(ret, 9 * 3600 + 30 * 60);
    }

    #[test]
    fn test_parse_gmtoff_zero() {
        let s = CString::new("+0000").unwrap();
        let mut ret: c_long = 0;
        // SAFETY: the raw pointer is derived from a live allocation and is used only for the duration of this operation.
        let result = unsafe { rs_parse_gmtoff(s.as_ptr(), &mut ret) };
        assert_eq!(result, 0);
        assert_eq!(ret, 0);
    }

    #[test]
    fn test_parse_gmtoff_invalid_no_sign() {
        let s = CString::new("0900").unwrap();
        // SAFETY: the raw pointer is derived from a live allocation and is used only for the duration of this operation.
        let result = unsafe { rs_parse_gmtoff(s.as_ptr(), std::ptr::null_mut()) };
        assert_eq!(result, Errno::EINVAL.to_neg_errno());
    }

    #[test]
    fn test_parse_gmtoff_invalid_minutes_60() {
        let s = CString::new("+0960").unwrap();
        // SAFETY: the raw pointer is derived from a live allocation and is used only for the duration of this operation.
        let result = unsafe { rs_parse_gmtoff(s.as_ptr(), std::ptr::null_mut()) };
        assert_eq!(result, Errno::EINVAL.to_neg_errno());
    }

    #[test]
    fn test_parse_gmtoff_null_ret() {
        let s = CString::new("+0500").unwrap();
        // SAFETY: the raw pointer is derived from a live allocation and is used only for the duration of this operation.
        let result = unsafe { rs_parse_gmtoff(s.as_ptr(), std::ptr::null_mut()) };
        assert_eq!(result, 0);
    }

    // ── rs_format_timespan ──────────────────────────────────────────────────

    #[test]
    fn test_format_timespan_null_buf() {
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        let result = unsafe { rs_format_timespan(std::ptr::null_mut(), 64, 1000, 1) };
        assert!(result.is_null());
    }

    #[test]
    fn test_format_timespan_zero_length() {
        let mut buf = [0 as c_char; 64];
        // SAFETY: the raw pointer is derived from a live allocation and is used only for the duration of this operation.
        let result = unsafe { rs_format_timespan(buf.as_mut_ptr(), 0, 1000, 1) };
        assert!(result.is_null());
    }

    #[test]
    fn test_format_timespan_infinity() {
        let mut buf = [0 as c_char; 64];
        // SAFETY: `buf` points to writable stack storage of length `buf.len()`.
        unsafe { rs_format_timespan(buf.as_mut_ptr(), buf.len(), USEC_INFINITY, 1) };
        // SAFETY: `rs_format_timespan` wrote a NUL-terminated string into `buf`.
        let s = unsafe { CStr::from_ptr(buf.as_ptr()) };
        assert_eq!(s.to_bytes(), b"infinity");
    }

    #[test]
    fn test_format_timespan_zero() {
        let mut buf = [0 as c_char; 64];
        // SAFETY: `buf` points to writable stack storage of length `buf.len()`.
        unsafe { rs_format_timespan(buf.as_mut_ptr(), buf.len(), 0, 1) };
        // SAFETY: `rs_format_timespan` wrote a NUL-terminated string into `buf`.
        let s = unsafe { CStr::from_ptr(buf.as_ptr()) };
        assert_eq!(s.to_bytes(), b"0");
    }

    #[test]
    fn test_format_timespan_seconds() {
        let mut buf = [0 as c_char; 64];
        // SAFETY: `buf` points to writable stack storage of length `buf.len()`.
        unsafe { rs_format_timespan(buf.as_mut_ptr(), buf.len(), 5 * USEC_PER_SEC, 1) };
        // SAFETY: `rs_format_timespan` wrote a NUL-terminated string into `buf`.
        let s = unsafe { CStr::from_ptr(buf.as_ptr()) };
        assert_eq!(s.to_bytes(), b"5s");
    }

    #[test]
    fn test_format_timespan_minutes_seconds() {
        let mut buf = [0 as c_char; 64];
        let usec = 2 * USEC_PER_MINUTE + 30 * USEC_PER_SEC;
        // SAFETY: `buf` points to writable stack storage of length `buf.len()`.
        unsafe { rs_format_timespan(buf.as_mut_ptr(), buf.len(), usec, 1) };
        // SAFETY: `rs_format_timespan` wrote a NUL-terminated string into `buf`.
        let s = unsafe { CStr::from_ptr(buf.as_ptr()) };
        assert_eq!(s.to_bytes(), b"2min 30s");
    }

    #[test]
    fn test_format_timespan_days() {
        let mut buf = [0 as c_char; 64];
        let usec = 3 * USEC_PER_DAY;
        // SAFETY: `buf` points to writable stack storage of length `buf.len()`.
        unsafe { rs_format_timespan(buf.as_mut_ptr(), buf.len(), usec, 1) };
        // SAFETY: `rs_format_timespan` wrote a NUL-terminated string into `buf`.
        let s = unsafe { CStr::from_ptr(buf.as_ptr()) };
        assert_eq!(s.to_bytes(), b"3d");
    }

    #[test]
    fn test_format_timespan_milliseconds() {
        let mut buf = [0 as c_char; 64];
        // SAFETY: `buf` points to writable stack storage of length `buf.len()`.
        unsafe { rs_format_timespan(buf.as_mut_ptr(), buf.len(), 500_000, 1) };
        // SAFETY: `rs_format_timespan` wrote a NUL-terminated string into `buf`.
        let s = unsafe { CStr::from_ptr(buf.as_ptr()) };
        assert_eq!(s.to_bytes(), b"500ms");
    }

    #[test]
    fn test_format_timespan_microseconds() {
        let mut buf = [0 as c_char; 64];
        // SAFETY: `buf` points to writable stack storage of length `buf.len()`.
        unsafe { rs_format_timespan(buf.as_mut_ptr(), buf.len(), 1234, 1) };
        // SAFETY: `rs_format_timespan` wrote a NUL-terminated string into `buf`.
        let s = unsafe { CStr::from_ptr(buf.as_ptr()) };
        assert_eq!(s.to_bytes(), b"1.234ms");
    }

    #[test]
    fn test_format_timespan_small_buffer() {
        let mut buf = [0 as c_char; 4];
        // SAFETY: `buf` points to writable stack storage of length `buf.len()`.
        unsafe { rs_format_timespan(buf.as_mut_ptr(), buf.len(), 5 * USEC_PER_SEC, 1) };
        // SAFETY: `rs_format_timespan` wrote a NUL-terminated string into `buf`.
        let s = unsafe { CStr::from_ptr(buf.as_ptr()) };
        assert!(s.to_bytes().len() < 4);
    }

    #[test]
    fn test_format_timespan_small_buffer_matches_c_incremental_truncation() {
        let mut buf = [0 as c_char; 4];
        let usec = USEC_PER_YEAR + 2 * USEC_PER_MONTH;
        // SAFETY: buf points to writable stack storage of length buf.len().
        unsafe { rs_format_timespan(buf.as_mut_ptr(), buf.len(), usec, 1) };
        // C appends each segment with the remaining buffer size, leaving only
        // the separator from the second segment in this constrained buffer.
        // SAFETY: rs_format_timespan above received all four writable bytes and
        // always NUL-terminates a non-null buffer with nonzero length.
        let s = unsafe { CStr::from_ptr(buf.as_ptr()) };
        assert_eq!(s.to_bytes(), b"1y ");
    }

    #[test]
    fn test_format_timespan_single_byte_buffer_is_nul_terminated() {
        let mut buf = [127 as c_char];
        // SAFETY: buf points to writable stack storage of length buf.len().
        unsafe { rs_format_timespan(buf.as_mut_ptr(), buf.len(), USEC_PER_SEC, 1) };
        assert_eq!(buf, [0]);
    }

    #[test]
    fn test_format_timespan_with_accuracy() {
        let mut buf = [0 as c_char; 64];
        let usec = 2 * USEC_PER_DAY + 3 * USEC_PER_HOUR + 500_000;
        // SAFETY: `buf` points to writable stack storage of length `buf.len()`.
        unsafe { rs_format_timespan(buf.as_mut_ptr(), buf.len(), usec, USEC_PER_SEC) };
        // SAFETY: `rs_format_timespan` wrote a NUL-terminated string into `buf`.
        let s = unsafe { CStr::from_ptr(buf.as_ptr()) };
        assert_eq!(s.to_bytes(), b"2d 3h");
    }

    // ── rs_timestamp_is_set ─────────────────────────────────────────────────

    #[test]
    fn test_timestamp_is_set_zero() {
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        let result = unsafe { rs_timestamp_is_set(0) };
        assert!(!result);
    }

    #[test]
    fn test_timestamp_is_set_infinity() {
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        let result = unsafe { rs_timestamp_is_set(USEC_INFINITY) };
        assert!(!result);
    }

    #[test]
    fn test_timestamp_is_set_valid() {
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        let result = unsafe { rs_timestamp_is_set(12345) };
        assert!(result);
    }

    #[test]
    fn test_timestamp_is_set_one() {
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        let result = unsafe { rs_timestamp_is_set(1) };
        assert!(result);
    }

    // ── rs_dual_timestamp_is_set ────────────────────────────────────────────

    #[test]
    fn test_dual_timestamp_is_set_null() {
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        let result = unsafe { rs_dual_timestamp_is_set(std::ptr::null()) };
        assert!(!result);
    }

    #[test]
    fn test_dual_timestamp_is_set_both_unset() {
        let ts = DualTimestamp {
            realtime: 0,
            monotonic: 0,
        };
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        let result = unsafe { rs_dual_timestamp_is_set(&ts) };
        assert!(!result);
    }

    #[test]
    fn test_dual_timestamp_is_set_realtime_set() {
        let ts = DualTimestamp {
            realtime: 1000,
            monotonic: 0,
        };
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        let result = unsafe { rs_dual_timestamp_is_set(&ts) };
        assert!(result);
    }

    #[test]
    fn test_dual_timestamp_is_set_monotonic_set() {
        let ts = DualTimestamp {
            realtime: 0,
            monotonic: 1000,
        };
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        let result = unsafe { rs_dual_timestamp_is_set(&ts) };
        assert!(result);
    }

    #[test]
    fn test_dual_timestamp_is_set_both_set() {
        let ts = DualTimestamp {
            realtime: 1000,
            monotonic: 2000,
        };
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        let result = unsafe { rs_dual_timestamp_is_set(&ts) };
        assert!(result);
    }

    #[test]
    fn test_dual_timestamp_is_set_both_infinity() {
        let ts = DualTimestamp {
            realtime: USEC_INFINITY,
            monotonic: USEC_INFINITY,
        };
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        let result = unsafe { rs_dual_timestamp_is_set(&ts) };
        assert!(!result);
    }

    // ── rs_triple_timestamp_is_set ──────────────────────────────────────────

    #[test]
    fn test_triple_timestamp_is_set_null() {
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        let result = unsafe { rs_triple_timestamp_is_set(std::ptr::null()) };
        assert!(!result);
    }

    #[test]
    fn test_triple_timestamp_is_set_all_unset() {
        let ts = TripleTimestamp {
            realtime: 0,
            monotonic: 0,
            boottime: 0,
        };
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        let result = unsafe { rs_triple_timestamp_is_set(&ts) };
        assert!(!result);
    }

    #[test]
    fn test_triple_timestamp_is_set_boottime_set() {
        let ts = TripleTimestamp {
            realtime: 0,
            monotonic: 0,
            boottime: 1000,
        };
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        let result = unsafe { rs_triple_timestamp_is_set(&ts) };
        assert!(result);
    }

    // ── rs_usec_add ─────────────────────────────────────────────────────────

    #[test]
    fn test_usec_add_normal() {
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        let result = unsafe { rs_usec_add(1000, 2000) };
        assert_eq!(result, 3000);
    }

    #[test]
    fn test_usec_add_zero() {
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        let result = unsafe { rs_usec_add(0, 0) };
        assert_eq!(result, 0);
    }

    #[test]
    fn test_usec_add_overflow() {
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        let result = unsafe { rs_usec_add(USEC_INFINITY, 1) };
        assert_eq!(result, USEC_INFINITY);
    }

    #[test]
    fn test_usec_add_near_max() {
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        let result = unsafe { rs_usec_add(u64::MAX - 1, 1) };
        assert_eq!(result, USEC_INFINITY);
    }

    // ── rs_usec_sub_unsigned ────────────────────────────────────────────────

    #[test]
    fn test_usec_sub_unsigned_normal() {
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        let result = unsafe { rs_usec_sub_unsigned(5000, 2000) };
        assert_eq!(result, 3000);
    }

    #[test]
    fn test_usec_sub_unsigned_zero() {
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        let result = unsafe { rs_usec_sub_unsigned(0, 0) };
        assert_eq!(result, 0);
    }

    #[test]
    fn test_usec_sub_unsigned_infinity() {
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        let result = unsafe { rs_usec_sub_unsigned(USEC_INFINITY, 1000) };
        assert_eq!(result, USEC_INFINITY);
    }

    #[test]
    fn test_usec_sub_unsigned_underflow() {
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        let result = unsafe { rs_usec_sub_unsigned(1000, 5000) };
        assert_eq!(result, 0);
    }

    #[test]
    fn test_usec_sub_unsigned_equal() {
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        let result = unsafe { rs_usec_sub_unsigned(5000, 5000) };
        assert_eq!(result, 0);
    }

    // ── rs_usec_sub_signed ──────────────────────────────────────────────────

    #[test]
    fn test_usec_sub_signed_positive_delta() {
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        let result = unsafe { rs_usec_sub_signed(5000, 2000) };
        assert_eq!(result, 3000);
    }

    #[test]
    fn test_usec_sub_signed_negative_delta() {
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        let result = unsafe { rs_usec_sub_signed(5000, -2000) };
        assert_eq!(result, 7000);
    }

    #[test]
    fn test_usec_sub_signed_zero_delta() {
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        let result = unsafe { rs_usec_sub_signed(5000, 0) };
        assert_eq!(result, 5000);
    }

    #[test]
    fn test_usec_sub_signed_int64_min() {
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        let result = unsafe { rs_usec_sub_signed(0, i64::MIN) };
        assert_eq!(result, (i64::MAX as u64) + 1);
    }

    #[test]
    fn test_usec_sub_signed_negative_underflow() {
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        let result = unsafe { rs_usec_sub_signed(1000, -5000) };
        assert_eq!(result, 6000);
    }

    // ── rs_parse_time ───────────────────────────────────────────────────────

    #[test]
    fn test_parse_time_null() {
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        let result = unsafe { rs_parse_time(std::ptr::null(), std::ptr::null_mut(), USEC_PER_SEC) };
        assert_eq!(result, Errno::EINVAL.to_neg_errno());
    }

    #[test]
    fn test_parse_time_default_unit_zero() {
        let s = CString::new("5").unwrap();
        // SAFETY: the raw pointer is derived from a live allocation and is used only for the duration of this operation.
        let result = unsafe { rs_parse_time(s.as_ptr(), std::ptr::null_mut(), 0) };
        assert_eq!(result, Errno::EINVAL.to_neg_errno());
    }

    #[test]
    fn test_parse_time_infinity() {
        let s = CString::new("infinity").unwrap();
        let mut ret: u64 = 0;
        // SAFETY: the raw pointer is derived from a live allocation and is used only for the duration of this operation.
        let result = unsafe { rs_parse_time(s.as_ptr(), &mut ret, USEC_PER_SEC) };
        assert_eq!(result, 0);
        assert_eq!(ret, USEC_INFINITY);
    }

    #[test]
    fn test_parse_time_plain_seconds() {
        let s = CString::new("5").unwrap();
        let mut ret: u64 = 0;
        // SAFETY: the raw pointer is derived from a live allocation and is used only for the duration of this operation.
        let result = unsafe { rs_parse_time(s.as_ptr(), &mut ret, USEC_PER_SEC) };
        assert_eq!(result, 0);
        assert_eq!(ret, 5 * USEC_PER_SEC);
    }

    #[test]
    fn test_parse_time_with_suffix_s() {
        let s = CString::new("5s").unwrap();
        let mut ret: u64 = 0;
        // SAFETY: the raw pointer is derived from a live allocation and is used only for the duration of this operation.
        let result = unsafe { rs_parse_time(s.as_ptr(), &mut ret, USEC_PER_SEC) };
        assert_eq!(result, 0);
        assert_eq!(ret, 5 * USEC_PER_SEC);
    }

    #[test]
    fn test_parse_time_with_suffix_ms() {
        let s = CString::new("500ms").unwrap();
        let mut ret: u64 = 0;
        // SAFETY: the raw pointer is derived from a live allocation and is used only for the duration of this operation.
        let result = unsafe { rs_parse_time(s.as_ptr(), &mut ret, USEC_PER_SEC) };
        assert_eq!(result, 0);
        assert_eq!(ret, 500 * USEC_PER_MSEC);
    }

    #[test]
    fn test_parse_time_with_suffix_min() {
        let s = CString::new("2min").unwrap();
        let mut ret: u64 = 0;
        // SAFETY: the raw pointer is derived from a live allocation and is used only for the duration of this operation.
        let result = unsafe { rs_parse_time(s.as_ptr(), &mut ret, USEC_PER_SEC) };
        assert_eq!(result, 0);
        assert_eq!(ret, 2 * USEC_PER_MINUTE);
    }

    #[test]
    fn test_parse_time_with_suffix_h() {
        let s = CString::new("1h").unwrap();
        let mut ret: u64 = 0;
        // SAFETY: the raw pointer is derived from a live allocation and is used only for the duration of this operation.
        let result = unsafe { rs_parse_time(s.as_ptr(), &mut ret, USEC_PER_SEC) };
        assert_eq!(result, 0);
        assert_eq!(ret, USEC_PER_HOUR);
    }

    #[test]
    fn test_parse_time_with_suffix_d() {
        let s = CString::new("3d").unwrap();
        let mut ret: u64 = 0;
        // SAFETY: the raw pointer is derived from a live allocation and is used only for the duration of this operation.
        let result = unsafe { rs_parse_time(s.as_ptr(), &mut ret, USEC_PER_SEC) };
        assert_eq!(result, 0);
        assert_eq!(ret, 3 * USEC_PER_DAY);
    }

    #[test]
    fn test_parse_time_with_suffix_w() {
        let s = CString::new("2w").unwrap();
        let mut ret: u64 = 0;
        // SAFETY: the raw pointer is derived from a live allocation and is used only for the duration of this operation.
        let result = unsafe { rs_parse_time(s.as_ptr(), &mut ret, USEC_PER_SEC) };
        assert_eq!(result, 0);
        assert_eq!(ret, 2 * USEC_PER_WEEK);
    }

    #[test]
    fn test_parse_time_with_suffix_y() {
        let s = CString::new("1y").unwrap();
        let mut ret: u64 = 0;
        // SAFETY: the raw pointer is derived from a live allocation and is used only for the duration of this operation.
        let result = unsafe { rs_parse_time(s.as_ptr(), &mut ret, USEC_PER_SEC) };
        assert_eq!(result, 0);
        assert_eq!(ret, USEC_PER_YEAR);
    }

    #[test]
    fn test_parse_time_with_suffix_month() {
        let s = CString::new("6month").unwrap();
        let mut ret: u64 = 0;
        // SAFETY: the raw pointer is derived from a live allocation and is used only for the duration of this operation.
        let result = unsafe { rs_parse_time(s.as_ptr(), &mut ret, USEC_PER_SEC) };
        assert_eq!(result, 0);
        assert_eq!(ret, 6 * USEC_PER_MONTH);
    }

    #[test]
    fn test_parse_time_with_suffix_us() {
        let s = CString::new("100us").unwrap();
        let mut ret: u64 = 0;
        // SAFETY: the raw pointer is derived from a live allocation and is used only for the duration of this operation.
        let result = unsafe { rs_parse_time(s.as_ptr(), &mut ret, USEC_PER_SEC) };
        assert_eq!(result, 0);
        assert_eq!(ret, 100);
    }

    #[test]
    fn test_parse_time_with_suffix_usec() {
        let s = CString::new("100usec").unwrap();
        let mut ret: u64 = 0;
        // SAFETY: the raw pointer is derived from a live allocation and is used only for the duration of this operation.
        let result = unsafe { rs_parse_time(s.as_ptr(), &mut ret, USEC_PER_SEC) };
        assert_eq!(result, 0);
        assert_eq!(ret, 100);
    }

    #[test]
    fn test_parse_time_with_suffix_seconds() {
        let s = CString::new("10seconds").unwrap();
        let mut ret: u64 = 0;
        // SAFETY: the raw pointer is derived from a live allocation and is used only for the duration of this operation.
        let result = unsafe { rs_parse_time(s.as_ptr(), &mut ret, USEC_PER_SEC) };
        assert_eq!(result, 0);
        assert_eq!(ret, 10 * USEC_PER_SEC);
    }

    #[test]
    fn test_parse_time_with_suffix_days() {
        let s = CString::new("2days").unwrap();
        let mut ret: u64 = 0;
        // SAFETY: the raw pointer is derived from a live allocation and is used only for the duration of this operation.
        let result = unsafe { rs_parse_time(s.as_ptr(), &mut ret, USEC_PER_SEC) };
        assert_eq!(result, 0);
        assert_eq!(ret, 2 * USEC_PER_DAY);
    }

    #[test]
    fn test_parse_time_with_suffix_years() {
        let s = CString::new("1year").unwrap();
        let mut ret: u64 = 0;
        // SAFETY: the raw pointer is derived from a live allocation and is used only for the duration of this operation.
        let result = unsafe { rs_parse_time(s.as_ptr(), &mut ret, USEC_PER_SEC) };
        assert_eq!(result, 0);
        assert_eq!(ret, USEC_PER_YEAR);
    }

    #[test]
    fn test_parse_time_with_suffix_hr() {
        let s = CString::new("3hr").unwrap();
        let mut ret: u64 = 0;
        // SAFETY: the raw pointer is derived from a live allocation and is used only for the duration of this operation.
        let result = unsafe { rs_parse_time(s.as_ptr(), &mut ret, USEC_PER_SEC) };
        assert_eq!(result, 0);
        assert_eq!(ret, 3 * USEC_PER_HOUR);
    }

    #[test]
    fn test_parse_time_with_suffix_hour() {
        let s = CString::new("2hour").unwrap();
        let mut ret: u64 = 0;
        // SAFETY: the raw pointer is derived from a live allocation and is used only for the duration of this operation.
        let result = unsafe { rs_parse_time(s.as_ptr(), &mut ret, USEC_PER_SEC) };
        assert_eq!(result, 0);
        assert_eq!(ret, 2 * USEC_PER_HOUR);
    }

    #[test]
    fn test_parse_time_with_suffix_hours() {
        let s = CString::new("5hours").unwrap();
        let mut ret: u64 = 0;
        // SAFETY: the raw pointer is derived from a live allocation and is used only for the duration of this operation.
        let result = unsafe { rs_parse_time(s.as_ptr(), &mut ret, USEC_PER_SEC) };
        assert_eq!(result, 0);
        assert_eq!(ret, 5 * USEC_PER_HOUR);
    }

    #[test]
    fn test_parse_time_with_suffix_weeks() {
        let s = CString::new("3weeks").unwrap();
        let mut ret: u64 = 0;
        // SAFETY: the raw pointer is derived from a live allocation and is used only for the duration of this operation.
        let result = unsafe { rs_parse_time(s.as_ptr(), &mut ret, USEC_PER_SEC) };
        assert_eq!(result, 0);
        assert_eq!(ret, 3 * USEC_PER_WEEK);
    }

    #[test]
    fn test_parse_time_with_suffix_week() {
        let s = CString::new("1week").unwrap();
        let mut ret: u64 = 0;
        // SAFETY: the raw pointer is derived from a live allocation and is used only for the duration of this operation.
        let result = unsafe { rs_parse_time(s.as_ptr(), &mut ret, USEC_PER_SEC) };
        assert_eq!(result, 0);
        assert_eq!(ret, USEC_PER_WEEK);
    }

    #[test]
    fn test_parse_time_with_suffix_minutes() {
        let s = CString::new("10minutes").unwrap();
        let mut ret: u64 = 0;
        // SAFETY: the raw pointer is derived from a live allocation and is used only for the duration of this operation.
        let result = unsafe { rs_parse_time(s.as_ptr(), &mut ret, USEC_PER_SEC) };
        assert_eq!(result, 0);
        assert_eq!(ret, 10 * USEC_PER_MINUTE);
    }

    #[test]
    fn test_parse_time_with_suffix_minute() {
        let s = CString::new("5minute").unwrap();
        let mut ret: u64 = 0;
        // SAFETY: the raw pointer is derived from a live allocation and is used only for the duration of this operation.
        let result = unsafe { rs_parse_time(s.as_ptr(), &mut ret, USEC_PER_SEC) };
        assert_eq!(result, 0);
        assert_eq!(ret, 5 * USEC_PER_MINUTE);
    }

    #[test]
    fn test_parse_time_with_suffix_months() {
        let s = CString::new("2months").unwrap();
        let mut ret: u64 = 0;
        // SAFETY: the raw pointer is derived from a live allocation and is used only for the duration of this operation.
        let result = unsafe { rs_parse_time(s.as_ptr(), &mut ret, USEC_PER_SEC) };
        assert_eq!(result, 0);
        assert_eq!(ret, 2 * USEC_PER_MONTH);
    }

    #[test]
    fn test_parse_time_with_suffix_M() {
        let s = CString::new("3M").unwrap();
        let mut ret: u64 = 0;
        // SAFETY: the raw pointer is derived from a live allocation and is used only for the duration of this operation.
        let result = unsafe { rs_parse_time(s.as_ptr(), &mut ret, USEC_PER_SEC) };
        assert_eq!(result, 0);
        assert_eq!(ret, 3 * USEC_PER_MONTH);
    }

    #[test]
    fn test_parse_time_with_suffix_sec() {
        let s = CString::new("10sec").unwrap();
        let mut ret: u64 = 0;
        // SAFETY: the raw pointer is derived from a live allocation and is used only for the duration of this operation.
        let result = unsafe { rs_parse_time(s.as_ptr(), &mut ret, USEC_PER_SEC) };
        assert_eq!(result, 0);
        assert_eq!(ret, 10 * USEC_PER_SEC);
    }

    #[test]
    fn test_parse_time_with_suffix_second() {
        let s = CString::new("7second").unwrap();
        let mut ret: u64 = 0;
        // SAFETY: the raw pointer is derived from a live allocation and is used only for the duration of this operation.
        let result = unsafe { rs_parse_time(s.as_ptr(), &mut ret, USEC_PER_SEC) };
        assert_eq!(result, 0);
        assert_eq!(ret, 7 * USEC_PER_SEC);
    }

    #[test]
    fn test_parse_time_with_suffix_day() {
        let s = CString::new("1day").unwrap();
        let mut ret: u64 = 0;
        // SAFETY: the raw pointer is derived from a live allocation and is used only for the duration of this operation.
        let result = unsafe { rs_parse_time(s.as_ptr(), &mut ret, USEC_PER_SEC) };
        assert_eq!(result, 0);
        assert_eq!(ret, USEC_PER_DAY);
    }

    #[test]
    fn test_parse_time_composite() {
        let s = CString::new("2min 500ms").unwrap();
        let mut ret: u64 = 0;
        // SAFETY: the raw pointer is derived from a live allocation and is used only for the duration of this operation.
        let result = unsafe { rs_parse_time(s.as_ptr(), &mut ret, USEC_PER_SEC) };
        assert_eq!(result, 0);
        assert_eq!(ret, 2 * USEC_PER_MINUTE + 500 * USEC_PER_MSEC);
    }

    #[test]
    fn test_parse_time_with_leading_whitespace() {
        let s = CString::new("  5s").unwrap();
        let mut ret: u64 = 0;
        // SAFETY: the raw pointer is derived from a live allocation and is used only for the duration of this operation.
        let result = unsafe { rs_parse_time(s.as_ptr(), &mut ret, USEC_PER_SEC) };
        assert_eq!(result, 0);
        assert_eq!(ret, 5 * USEC_PER_SEC);
    }

    #[test]
    fn test_parse_time_empty() {
        let s = CString::new("").unwrap();
        // SAFETY: the raw pointer is derived from a live allocation and is used only for the duration of this operation.
        let result = unsafe { rs_parse_time(s.as_ptr(), std::ptr::null_mut(), USEC_PER_SEC) };
        assert_eq!(result, Errno::EINVAL.to_neg_errno());
    }

    #[test]
    fn test_parse_time_invalid_suffix() {
        let s = CString::new("5x").unwrap();
        // SAFETY: the raw pointer is derived from a live allocation and is used only for the duration of this operation.
        let result = unsafe { rs_parse_time(s.as_ptr(), std::ptr::null_mut(), USEC_PER_SEC) };
        assert_eq!(result, Errno::EINVAL.to_neg_errno());
    }

    #[test]
    fn test_parse_time_negative() {
        let s = CString::new("-5").unwrap();
        // SAFETY: the raw pointer is derived from a live allocation and is used only for the duration of this operation.
        let result = unsafe { rs_parse_time(s.as_ptr(), std::ptr::null_mut(), USEC_PER_SEC) };
        assert_eq!(result, Errno::ERANGE.to_neg_errno());
    }

    #[test]
    fn test_parse_time_rejects_values_past_c_long_long_max() {
        let s = CString::new("9223372036854775808").unwrap();
        let mut ret = 0;
        // SAFETY: the raw pointer is derived from a live allocation.
        let result = unsafe { rs_parse_time(s.as_ptr(), &mut ret, 1) };
        assert_eq!(result, Errno::ERANGE.to_neg_errno());
    }

    #[test]
    fn test_parse_time_decimal() {
        let s = CString::new("1.5s").unwrap();
        let mut ret: u64 = 0;
        // SAFETY: the raw pointer is derived from a live allocation and is used only for the duration of this operation.
        let result = unsafe { rs_parse_time(s.as_ptr(), &mut ret, USEC_PER_SEC) };
        assert_eq!(result, 0);
        assert_eq!(ret, USEC_PER_SEC + USEC_PER_SEC / 2);
    }

    #[test]
    fn test_parse_time_null_ret() {
        let s = CString::new("5s").unwrap();
        // SAFETY: the raw pointer is derived from a live allocation and is used only for the duration of this operation.
        let result = unsafe { rs_parse_time(s.as_ptr(), std::ptr::null_mut(), USEC_PER_SEC) };
        assert_eq!(result, 0);
    }

    // ── rs_parse_sec ────────────────────────────────────────────────────────

    #[test]
    fn test_parse_sec_null() {
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        let result = unsafe { rs_parse_sec(std::ptr::null(), std::ptr::null_mut()) };
        assert_eq!(result, Errno::EINVAL.to_neg_errno());
    }

    #[test]
    fn test_parse_sec_basic() {
        let s = CString::new("10").unwrap();
        let mut ret: u64 = 0;
        // SAFETY: the raw pointer is derived from a live allocation and is used only for the duration of this operation.
        let result = unsafe { rs_parse_sec(s.as_ptr(), &mut ret) };
        assert_eq!(result, 0);
        assert_eq!(ret, 10 * USEC_PER_SEC);
    }

    #[test]
    fn test_parse_sec_with_suffix() {
        let s = CString::new("5min").unwrap();
        let mut ret: u64 = 0;
        // SAFETY: the raw pointer is derived from a live allocation and is used only for the duration of this operation.
        let result = unsafe { rs_parse_sec(s.as_ptr(), &mut ret) };
        assert_eq!(result, 0);
        assert_eq!(ret, 5 * USEC_PER_MINUTE);
    }

    #[test]
    fn test_parse_sec_infinity() {
        let s = CString::new("infinity").unwrap();
        let mut ret: u64 = 0;
        // SAFETY: the raw pointer is derived from a live allocation and is used only for the duration of this operation.
        let result = unsafe { rs_parse_sec(s.as_ptr(), &mut ret) };
        assert_eq!(result, 0);
        assert_eq!(ret, USEC_INFINITY);
    }

    #[test]
    fn test_parse_sec_zero() {
        let s = CString::new("0").unwrap();
        let mut ret: u64 = 0;
        // SAFETY: the raw pointer is derived from a live allocation and is used only for the duration of this operation.
        let result = unsafe { rs_parse_sec(s.as_ptr(), &mut ret) };
        assert_eq!(result, 0);
        assert_eq!(ret, 0);
    }

    // ── rs_parse_sec_fix_0 ──────────────────────────────────────────────────

    #[test]
    fn test_parse_sec_fix_0_null_input() {
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        let result = unsafe { rs_parse_sec_fix_0(std::ptr::null(), std::ptr::null_mut()) };
        assert_eq!(result, Errno::EINVAL.to_neg_errno());
    }

    #[test]
    fn test_parse_sec_fix_0_null_ret() {
        let s = CString::new("5").unwrap();
        // SAFETY: the raw pointer is derived from a live allocation and is used only for the duration of this operation.
        let result = unsafe { rs_parse_sec_fix_0(s.as_ptr(), std::ptr::null_mut()) };
        assert_eq!(result, Errno::EINVAL.to_neg_errno());
    }

    #[test]
    fn test_parse_sec_fix_0_zero_becomes_infinity() {
        let s = CString::new("0").unwrap();
        let mut ret: u64 = 0;
        // SAFETY: the raw pointer is derived from a live allocation and is used only for the duration of this operation.
        let result = unsafe { rs_parse_sec_fix_0(s.as_ptr(), &mut ret) };
        assert_eq!(result, 0);
        assert_eq!(ret, USEC_INFINITY);
    }

    #[test]
    fn test_parse_sec_fix_0_nonzero_unchanged() {
        let s = CString::new("5").unwrap();
        let mut ret: u64 = 0;
        // SAFETY: the raw pointer is derived from a live allocation and is used only for the duration of this operation.
        let result = unsafe { rs_parse_sec_fix_0(s.as_ptr(), &mut ret) };
        assert_eq!(result, 0);
        assert_eq!(ret, 5 * USEC_PER_SEC);
    }

    #[test]
    fn test_parse_sec_fix_0_error_propagation() {
        let s = CString::new("invalid").unwrap();
        let mut ret: u64 = 0;
        // SAFETY: the raw pointer is derived from a live allocation and is used only for the duration of this operation.
        let result = unsafe { rs_parse_sec_fix_0(s.as_ptr(), &mut ret) };
        assert!(result < 0);
    }

    // ── rs_parse_sec_def_infinity ───────────────────────────────────────────

    #[test]
    fn test_parse_sec_def_infinity_null_input() {
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        let result = unsafe { rs_parse_sec_def_infinity(std::ptr::null(), std::ptr::null_mut()) };
        assert_eq!(result, Errno::EINVAL.to_neg_errno());
    }

    #[test]
    fn test_parse_sec_def_infinity_null_ret() {
        let s = CString::new("5").unwrap();
        // SAFETY: the raw pointer is derived from a live allocation and is used only for the duration of this operation.
        let result = unsafe { rs_parse_sec_def_infinity(s.as_ptr(), std::ptr::null_mut()) };
        assert_eq!(result, Errno::EINVAL.to_neg_errno());
    }

    #[test]
    fn test_parse_sec_def_infinity_empty_string() {
        let s = CString::new("").unwrap();
        let mut ret: u64 = 0;
        // SAFETY: the raw pointer is derived from a live allocation and is used only for the duration of this operation.
        let result = unsafe { rs_parse_sec_def_infinity(s.as_ptr(), &mut ret) };
        assert_eq!(result, 0);
        assert_eq!(ret, USEC_INFINITY);
    }

    #[test]
    fn test_parse_sec_def_infinity_whitespace_only() {
        let s = CString::new("   ").unwrap();
        let mut ret: u64 = 0;
        // SAFETY: the raw pointer is derived from a live allocation and is used only for the duration of this operation.
        let result = unsafe { rs_parse_sec_def_infinity(s.as_ptr(), &mut ret) };
        assert_eq!(result, 0);
        assert_eq!(ret, USEC_INFINITY);
    }

    #[test]
    fn test_parse_sec_def_infinity_normal_value() {
        let s = CString::new("10").unwrap();
        let mut ret: u64 = 0;
        // SAFETY: the raw pointer is derived from a live allocation and is used only for the duration of this operation.
        let result = unsafe { rs_parse_sec_def_infinity(s.as_ptr(), &mut ret) };
        assert_eq!(result, 0);
        assert_eq!(ret, 10 * USEC_PER_SEC);
    }

    #[test]
    fn test_parse_sec_def_infinity_zero() {
        let s = CString::new("0").unwrap();
        let mut ret: u64 = 0;
        // SAFETY: the raw pointer is derived from a live allocation and is used only for the duration of this operation.
        let result = unsafe { rs_parse_sec_def_infinity(s.as_ptr(), &mut ret) };
        assert_eq!(result, 0);
        assert_eq!(ret, 0);
    }
}
