// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: scope=basic.time-util; authority=src/basic/time-util.c,src/basic/time-util.h
//
// Timestamp predicates and saturating microsecond arithmetic.

use super::types::{DualTimestamp, TripleTimestamp, USEC_INFINITY};

/// Shadow of C timestamp_is_set() (inline in time-util.h)
#[unsafe(no_mangle)]
pub extern "C" fn rs_timestamp_is_set(timestamp: u64) -> bool {
    timestamp > 0 && timestamp != USEC_INFINITY
}

/// Shadow of C dual_timestamp_is_set() (inline in time-util.h)
/// dual_timestamp: { realtime: u64, monotonic: u64 }
///
/// # Safety
///
/// A non-null `ts` must be aligned, initialized, and readable as a
/// `DualTimestamp` for this call. Null is explicitly accepted.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_dual_timestamp_is_set(ts: *const DualTimestamp) -> bool {
    if ts.is_null() {
        return false;
    }
    // SAFETY: required by this function's contract and checked for NULL above.
    let ts = unsafe_ffi!(&*ts);
    rs_timestamp_is_set(ts.realtime) || rs_timestamp_is_set(ts.monotonic)
}

/// Shadow of C triple_timestamp_is_set() (inline in time-util.h)
/// triple_timestamp: { realtime: u64, monotonic: u64, boottime: u64 }
///
/// # Safety
///
/// A non-null `ts` must be aligned, initialized, and readable as a
/// `TripleTimestamp` for this call. Null is explicitly accepted.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_triple_timestamp_is_set(ts: *const TripleTimestamp) -> bool {
    if ts.is_null() {
        return false;
    }
    // SAFETY: required by this function's contract and checked for NULL above.
    let ts = unsafe_ffi!(&*ts);
    rs_timestamp_is_set(ts.realtime)
        || rs_timestamp_is_set(ts.monotonic)
        || rs_timestamp_is_set(ts.boottime)
}

// ── usec arithmetic helpers ───────────────────────────────────────────────

/// Saturating addition for usec_t values (internal).
fn saturate_add_u64(a: u64, b: u64, limit: u64) -> u64 {
    a.checked_add(b).unwrap_or(limit).min(limit)
}

/// Shadow of C usec_add() (inline in time-util.h)
#[unsafe(no_mangle)]
pub extern "C" fn rs_usec_add(a: u64, b: u64) -> u64 {
    saturate_add_u64(a, b, USEC_INFINITY)
}

/// Shadow of C usec_sub_unsigned() (inline in time-util.h)
#[unsafe(no_mangle)]
pub extern "C" fn rs_usec_sub_unsigned(timestamp: u64, delta: u64) -> u64 {
    if timestamp == USEC_INFINITY {
        return USEC_INFINITY;
    }
    if timestamp < delta {
        return 0;
    }
    timestamp - delta
}

/// Shadow of C usec_sub_signed() (inline in time-util.h)
#[unsafe(no_mangle)]
pub extern "C" fn rs_usec_sub_signed(timestamp: u64, delta: i64) -> u64 {
    if delta == i64::MIN {
        // -(INT64_MIN + 1) == INT64_MAX
        // USEC_INFINITY > INT64_MAX
        return rs_usec_add(timestamp, (i64::MAX as u64) + 1);
    }
    if delta < 0 {
        return rs_usec_add(timestamp, (-delta) as u64);
    }
    rs_usec_sub_unsigned(timestamp, delta as u64)
}
