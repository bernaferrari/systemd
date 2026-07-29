// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: scope=basic.time-util; authority=src/basic/time-util.c,src/basic/time-util.h
//
// Clock-domain conversion and libc timestamp conversion primitives.

use super::types::{
    CLOCK_BOOTTIME, CLOCK_BOOTTIME_ALARM, CLOCK_MONOTONIC, CLOCK_REALTIME, CLOCK_REALTIME_ALARM,
    LibcTimespec, LibcTimeval, NSEC_INFINITY, NSEC_PER_SEC, NSEC_PER_USEC, TIME_T_MAX,
    TripleTimestamp, USEC_INFINITY, USEC_PER_SEC,
};

// ── map_clock_usec_raw ────────────────────────────────────────────────────

#[unsafe(no_mangle)]
pub extern "C" fn rs_map_clock_usec_raw(from: u64, from_base: u64, to_base: u64) -> u64 {
    if from >= from_base {
        // Future: to_base + (from - from_base)
        let delta = from - from_base;
        if to_base >= USEC_INFINITY - delta {
            return USEC_INFINITY;
        }
        to_base + delta
    } else {
        // Past: to_base - (from_base - from)
        let delta = from_base - from;
        if to_base <= delta {
            return 0;
        }
        to_base - delta
    }
}

// ── timespec_load ─────────────────────────────────────────────────────────

// SAFETY: A non-null ts must be aligned, initialized, and readable as a
// LibcTimespec for the duration of this call; null is explicitly accepted.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_timespec_load(ts: *const LibcTimespec) -> u64 {
    if ts.is_null() {
        return 0;
    }
    // SAFETY: the null check and function contract establish a readable,
    // aligned LibcTimespec; the shared reference does not mutate it.
    let ts = unsafe { &*ts };
    if ts.tv_sec < 0 || ts.tv_nsec < 0 {
        return USEC_INFINITY;
    }
    let sec = ts.tv_sec as u64;
    let nsec = ts.tv_nsec as u64;
    if sec > (u64::MAX - nsec / NSEC_PER_USEC) / USEC_PER_SEC {
        return USEC_INFINITY;
    }
    sec * USEC_PER_SEC + nsec / NSEC_PER_USEC
}

// ── timespec_load_nsec ────────────────────────────────────────────────────

// SAFETY: A non-null ts must be aligned, initialized, and readable as a
// LibcTimespec for the duration of this call; null is explicitly accepted.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_timespec_load_nsec(ts: *const LibcTimespec) -> u64 {
    if ts.is_null() {
        return 0;
    }
    // SAFETY: the null check and function contract establish a readable,
    // aligned LibcTimespec; the shared reference does not mutate it.
    let ts = unsafe { &*ts };
    if ts.tv_sec < 0 || ts.tv_nsec < 0 {
        return NSEC_INFINITY;
    }
    let sec = ts.tv_sec as u64;
    let nsec = ts.tv_nsec as u64;
    if sec >= (u64::MAX - nsec) / NSEC_PER_SEC {
        return NSEC_INFINITY;
    }
    sec * NSEC_PER_SEC + nsec
}

// ── timespec_store ────────────────────────────────────────────────────────

// SAFETY: A non-null ts must be aligned, initialized, uniquely writable as a
// LibcTimespec, and not aliased for the mutable borrow; null is accepted.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_timespec_store(ts: *mut LibcTimespec, u: u64) -> *mut LibcTimespec {
    if ts.is_null() {
        return std::ptr::null_mut();
    }
    // SAFETY: the null check and function contract establish exclusive,
    // initialized writable storage for the returned mutable reference.
    let ts = unsafe { &mut *ts };
    if u == USEC_INFINITY || u / USEC_PER_SEC >= TIME_T_MAX {
        ts.tv_sec = -1;
        ts.tv_nsec = -1;
    } else {
        ts.tv_sec = (u / USEC_PER_SEC) as i64;
        ts.tv_nsec = ((u % USEC_PER_SEC) * NSEC_PER_USEC) as i64;
    }
    ts
}

// ── timespec_store_nsec ──────────────────────────────────────────────────

// SAFETY: A non-null ts must be aligned, initialized, uniquely writable as a
// LibcTimespec, and not aliased for the mutable borrow; null is accepted.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_timespec_store_nsec(
    ts: *mut LibcTimespec,
    n: u64,
) -> *mut LibcTimespec {
    if ts.is_null() {
        return std::ptr::null_mut();
    }
    // SAFETY: the null check and function contract establish exclusive,
    // initialized writable storage for the returned mutable reference.
    let ts = unsafe { &mut *ts };
    if n == NSEC_INFINITY || n / NSEC_PER_SEC >= TIME_T_MAX {
        ts.tv_sec = -1;
        ts.tv_nsec = -1;
    } else {
        ts.tv_sec = (n / NSEC_PER_SEC) as i64;
        ts.tv_nsec = (n % NSEC_PER_SEC) as i64;
    }
    ts
}

// ── timeval_load ──────────────────────────────────────────────────────────

// SAFETY: A non-null tv must be aligned, initialized, and readable as a
// LibcTimeval for the duration of this call; null is explicitly accepted.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_timeval_load(tv: *const LibcTimeval) -> u64 {
    if tv.is_null() {
        return 0;
    }
    // SAFETY: the null check and function contract establish a readable,
    // aligned LibcTimeval; the shared reference does not mutate it.
    let tv = unsafe { &*tv };
    if tv.tv_sec < 0 || tv.tv_usec < 0 {
        return USEC_INFINITY;
    }
    let sec = tv.tv_sec as u64;
    let usec = tv.tv_usec as u64;
    if sec > (u64::MAX - usec) / USEC_PER_SEC {
        return USEC_INFINITY;
    }
    sec * USEC_PER_SEC + usec
}

// ── timeval_store ─────────────────────────────────────────────────────────

// SAFETY: A non-null tv must be aligned, initialized, uniquely writable as a
// LibcTimeval, and not aliased for the mutable borrow; null is accepted.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_timeval_store(tv: *mut LibcTimeval, u: u64) -> *mut LibcTimeval {
    if tv.is_null() {
        return std::ptr::null_mut();
    }
    // SAFETY: the null check and function contract establish exclusive,
    // initialized writable storage for the returned mutable reference.
    let tv = unsafe { &mut *tv };
    if u == USEC_INFINITY || u / USEC_PER_SEC > TIME_T_MAX {
        tv.tv_sec = -1;
        tv.tv_usec = -1;
    } else {
        tv.tv_sec = (u / USEC_PER_SEC) as i64;
        tv.tv_usec = (u % USEC_PER_SEC) as i64;
    }
    tv
}

// ── triple_timestamp_by_clock ─────────────────────────────────────────────

// SAFETY: A non-null ts must be aligned, initialized, and readable as a
// TripleTimestamp for this call; null is explicitly accepted.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_triple_timestamp_by_clock(ts: *mut TripleTimestamp, clock: i32) -> u64 {
    if ts.is_null() {
        return 0;
    }
    // SAFETY: the null check and function contract establish a readable,
    // aligned TripleTimestamp; the shared reference does not mutate it.
    let ts = unsafe { &*ts };
    match clock {
        CLOCK_REALTIME | CLOCK_REALTIME_ALARM => ts.realtime,
        CLOCK_MONOTONIC => ts.monotonic,
        CLOCK_BOOTTIME | CLOCK_BOOTTIME_ALARM => ts.boottime,
        _ => USEC_INFINITY,
    }
}
