// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: scope=basic.ratelimit; authority=src/basic/ratelimit.c,src/basic/ratelimit.h
//
// Rate limiting utilities, modelled after Linux' lib/ratelimit.c.

// ── Constants ──────────────────────────────────────────────────────────────

const USEC_INFINITY: u64 = u64::MAX;

// ── Internal helpers ──────────────────────────────────────────────────────

fn saturate_add(x: u64, y: u64, limit: u64) -> u64 {
    if x > limit || y >= limit - x {
        limit
    } else {
        x + y
    }
}

fn usec_add(a: u64, b: u64) -> u64 {
    saturate_add(a, b, USEC_INFINITY)
}

fn usec_sub_unsigned(timestamp: u64, delta: u64) -> u64 {
    if timestamp == USEC_INFINITY {
        return USEC_INFINITY;
    }
    timestamp.saturating_sub(delta)
}

fn now_boottime_usec() -> u64 {
    let mut timestamp = std::mem::MaybeUninit::<libc::timespec>::uninit();
    // SAFETY: timestamp points to sufficient initialized output storage and
    // CLOCK_BOOTTIME is the exact clock used by the C authority.
    if unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, timestamp.as_mut_ptr()) } < 0 {
        return 0;
    }
    // SAFETY: clock_gettime succeeded and initialized timestamp.
    let timestamp = unsafe { timestamp.assume_init() };
    let seconds = u64::try_from(timestamp.tv_sec).unwrap_or(0);
    let nanoseconds = u64::try_from(timestamp.tv_nsec).unwrap_or(0);
    seconds
        .saturating_mul(1_000_000)
        .saturating_add(nanoseconds / 1_000)
}

// ── Types ──────────────────────────────────────────────────────────────────

#[repr(C)]
#[derive(Debug, Clone)]
pub struct RateLimit {
    pub interval: u64,
    pub burst: u32,
    pub num: u32,
    pub begin: u64,
}

impl RateLimit {
    pub const fn new(interval: u64, burst: u32) -> Self {
        Self {
            interval,
            burst,
            num: 0,
            begin: 0,
        }
    }

    pub fn configured(&self) -> bool {
        self.interval > 0 && self.burst > 0
    }

    pub fn reset(&mut self) {
        self.num = 0;
        self.begin = 0;
    }

    pub fn below(&mut self) -> bool {
        if !self.configured() {
            return true;
        }

        let ts = now_boottime_usec();

        if self.begin == 0 || usec_sub_unsigned(ts, self.begin) > self.interval {
            self.begin = ts;
            self.num = 1;
            return true;
        }

        if self.num == u32::MAX {
            return false;
        }

        self.num += 1;
        self.num <= self.burst
    }

    pub fn num_dropped(&self) -> u32 {
        if self.num == u32::MAX {
            return u32::MAX;
        }
        self.num.saturating_sub(self.burst)
    }

    pub fn end(&self) -> u64 {
        if self.begin == 0 {
            return 0;
        }
        usec_add(self.begin, self.interval)
    }

    pub fn left(&self) -> u64 {
        if self.begin == 0 {
            return 0;
        }
        let end = usec_add(self.begin, self.interval);
        usec_sub_unsigned(end, now_boottime_usec())
    }
}

/// C ABI facade for `ratelimit_below()`.
///
/// # Safety
/// `rl` must point to a writable C-compatible `RateLimit` for the duration of
/// the call. A NULL pointer is rejected instead of following C's assertion.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_ratelimit_below(rl: *mut RateLimit) -> bool {
    if rl.is_null() {
        return false;
    }
    // SAFETY: the FFI contract requires a valid writable RateLimit.
    unsafe { (&mut *rl).below() }
}

/// C ABI facade for `ratelimit_num_dropped()`.
///
/// # Safety
/// `rl` must point to a readable C-compatible `RateLimit`; NULL fails closed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_ratelimit_num_dropped(rl: *const RateLimit) -> u32 {
    // SAFETY: null is explicitly rejected; the remaining pointer is readable
    // under this facade's C ABI contract.
    unsafe { rl.as_ref().map_or(0, RateLimit::num_dropped) }
}

/// C ABI facade for `ratelimit_end()`.
///
/// # Safety
/// `rl` must point to a readable C-compatible `RateLimit`; NULL fails closed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_ratelimit_end(rl: *const RateLimit) -> u64 {
    // SAFETY: null is explicitly rejected; the remaining pointer is readable
    // under this facade's C ABI contract.
    unsafe { rl.as_ref().map_or(0, RateLimit::end) }
}

/// C ABI facade for `ratelimit_left()`.
///
/// # Safety
/// `rl` must point to a readable C-compatible `RateLimit`; NULL fails closed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_ratelimit_left(rl: *const RateLimit) -> u64 {
    // SAFETY: null is explicitly rejected; the remaining pointer is readable
    // under this facade's C ABI contract.
    unsafe { rl.as_ref().map_or(0, RateLimit::left) }
}

/// C ABI facade for the header-inline `ratelimit_reset()`.
///
/// # Safety
/// `rl` must point to writable C-compatible `RateLimit` storage; NULL is a
/// no-op instead of following C's invalid-pointer behavior.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_ratelimit_reset(rl: *mut RateLimit) {
    // SAFETY: a non-NULL FFI pointer is writable RateLimit storage.
    if let Some(rl) = unsafe { rl.as_mut() } {
        rl.reset();
    }
}

/// C ABI facade for the header-inline `ratelimit_configured()`.
///
/// # Safety
/// `rl` must point to readable C-compatible `RateLimit` storage; NULL fails closed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_ratelimit_configured(rl: *const RateLimit) -> bool {
    // SAFETY: null is explicitly rejected; the remaining pointer is readable
    // under this facade's C ABI contract.
    unsafe { rl.as_ref().is_some_and(RateLimit::configured) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ratelimit_below_zero_interval() {
        let mut rl = RateLimit::new(0, 5);
        assert!(rl.below());
    }

    #[test]
    fn test_ratelimit_below_zero_burst() {
        let mut rl = RateLimit::new(1_000_000, 0);
        assert!(rl.below());
    }

    #[test]
    fn test_ratelimit_below_first_call() {
        let mut rl = RateLimit::new(1_000_000, 5);
        assert!(rl.below());
        assert_eq!(rl.num, 1);
        assert!(rl.begin > 0);
    }

    #[test]
    fn test_ratelimit_below_within_burst() {
        let mut rl = RateLimit::new(1_000_000, 3);
        assert!(rl.below());
        assert!(rl.below());
        assert!(rl.below());
        assert!(!rl.below());
    }

    #[test]
    fn test_ratelimit_below_exhausted() {
        let mut rl = RateLimit::new(1_000_000, 1);
        assert!(rl.below());
        assert!(!rl.below());
        assert!(!rl.below());
    }

    #[test]
    fn test_ratelimit_num_dropped_zero() {
        let rl = RateLimit::new(1_000_000, 5);
        assert_eq!(rl.num_dropped(), 0);
    }

    #[test]
    fn test_ratelimit_num_dropped_within_burst() {
        let rl = RateLimit {
            interval: 1_000_000,
            burst: 5,
            num: 3,
            begin: 100,
        };
        assert_eq!(rl.num_dropped(), 0);
    }

    #[test]
    fn test_ratelimit_num_dropped_over_burst() {
        let rl = RateLimit {
            interval: 1_000_000,
            burst: 5,
            num: 10,
            begin: 100,
        };
        assert_eq!(rl.num_dropped(), 5);
    }

    #[test]
    fn test_ratelimit_num_dropped_max() {
        let rl = RateLimit {
            interval: 1_000_000,
            burst: 5,
            num: u32::MAX,
            begin: 100,
        };
        assert_eq!(rl.num_dropped(), u32::MAX);
    }

    #[test]
    fn test_ratelimit_end_zero_begin() {
        let rl = RateLimit::new(1_000_000, 5);
        assert_eq!(rl.end(), 0);
    }

    #[test]
    fn test_ratelimit_end_basic() {
        let rl = RateLimit {
            interval: 1_000_000,
            burst: 5,
            num: 0,
            begin: 500_000,
        };
        assert_eq!(rl.end(), 1_500_000);
    }

    #[test]
    fn test_ratelimit_end_infinity_interval() {
        let rl = RateLimit {
            interval: USEC_INFINITY,
            burst: 5,
            num: 0,
            begin: 500_000,
        };
        assert_eq!(rl.end(), USEC_INFINITY);
    }

    #[test]
    fn test_ratelimit_left_zero_begin() {
        let rl = RateLimit::new(1_000_000, 5);
        assert_eq!(rl.left(), 0);
    }

    #[test]
    fn test_ratelimit_reset() {
        let mut rl = RateLimit {
            interval: 1_000_000,
            burst: 5,
            num: 10,
            begin: 500,
        };
        rl.reset();
        assert_eq!(rl.num, 0);
        assert_eq!(rl.begin, 0);
    }

    #[test]
    fn test_ratelimit_configured() {
        let rl = RateLimit::new(1_000_000, 5);
        assert!(rl.configured());
        let rl = RateLimit::new(0, 5);
        assert!(!rl.configured());
        let rl = RateLimit::new(1_000_000, 0);
        assert!(!rl.configured());
    }

    #[test]
    fn test_saturate_add_overflow() {
        assert_eq!(saturate_add(u64::MAX, 1, u64::MAX), u64::MAX);
    }

    #[test]
    fn test_usec_add_infinity() {
        assert_eq!(usec_add(USEC_INFINITY, 1000), USEC_INFINITY);
        assert_eq!(usec_add(1000, USEC_INFINITY), USEC_INFINITY);
    }

    #[test]
    fn test_usec_sub_unsigned_infinity() {
        assert_eq!(usec_sub_unsigned(USEC_INFINITY, 1000), USEC_INFINITY);
    }

    #[test]
    fn test_usec_sub_unsigned_underflow() {
        assert_eq!(usec_sub_unsigned(100, 200), 0);
    }

    #[test]
    fn test_usec_sub_unsigned_normal() {
        assert_eq!(usec_sub_unsigned(500, 200), 300);
    }
}
