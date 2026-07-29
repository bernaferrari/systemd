// SPDX-License-Identifier: LGPL-2.1-or-later
//
// Shared ABI types and units from src/basic/time-util.h.
// PORT-SYNC: scope=basic.time-util-conversion; authority=src/basic/time-util.c,src/basic/time-util.h

pub const USEC_PER_SEC: u64 = 1_000_000;
pub(crate) const USEC_PER_MSEC: u64 = 1_000;
pub(crate) const NSEC_PER_USEC: u64 = 1_000;
pub(crate) const NSEC_PER_SEC: u64 = 1_000_000_000;
pub(crate) const USEC_PER_MINUTE: u64 = 60 * USEC_PER_SEC;
pub(crate) const USEC_PER_HOUR: u64 = 60 * USEC_PER_MINUTE;
pub(crate) const USEC_PER_DAY: u64 = 24 * USEC_PER_HOUR;
pub(crate) const USEC_PER_WEEK: u64 = 7 * USEC_PER_DAY;
pub(crate) const USEC_PER_MONTH: u64 = 2_629_800 * USEC_PER_SEC;
pub(crate) const USEC_PER_YEAR: u64 = 31_557_600 * USEC_PER_SEC;
pub(crate) const USEC_INFINITY: u64 = u64::MAX;
pub(crate) const NSEC_INFINITY: u64 = u64::MAX;
pub(crate) const TIME_T_MAX: u64 = i64::MAX as u64;

/// Target C `struct timespec` layout supplied by the `libc` crate.
///
/// Keeping this as a target-specific alias, rather than hard-coding two
/// 64-bit fields, preserves the ABI on supported 32-bit targets too.
pub type LibcTimespec = libc::timespec;

/// Target C `struct timeval` layout supplied by the `libc` crate.
///
/// Keeping this as a target-specific alias, rather than hard-coding two
/// 64-bit fields, preserves the ABI on supported 32-bit targets too.
pub type LibcTimeval = libc::timeval;

#[repr(C)]
pub struct DualTimestamp {
    pub realtime: u64,
    pub monotonic: u64,
}

#[repr(C)]
pub struct TripleTimestamp {
    pub realtime: u64,
    pub monotonic: u64,
    pub boottime: u64,
}

pub(crate) const CLOCK_REALTIME: i32 = 0;
pub(crate) const CLOCK_MONOTONIC: i32 = 1;
pub(crate) const CLOCK_BOOTTIME: i32 = 7;
pub(crate) const CLOCK_REALTIME_ALARM: i32 = 8;
pub(crate) const CLOCK_BOOTTIME_ALARM: i32 = 9;
