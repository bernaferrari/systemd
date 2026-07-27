// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/basic/ratelimit.c
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

fn now_monotonic_usec() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_micros() as u64)
        .unwrap_or(0)
}

// ── Types ──────────────────────────────────────────────────────────────────

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

        let ts = now_monotonic_usec();

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
        usec_sub_unsigned(end, now_monotonic_usec())
    }
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
