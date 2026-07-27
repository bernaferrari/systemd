// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/fundamental/logarithm.h
//
// Logarithm and bit-counting utilities.

/// log2 for u64. Returns 0 for x <= 1.
/// PORT-SYNC: mirrors log2u64() / LOG2ULL()
#[inline]
pub fn log2u64(x: u64) -> u32 {
    if x <= 1 {
        0
    } else {
        63 - x.leading_zeros()
    }
}

/// log2 for u32. Returns 0 for x <= 1.
/// PORT-SYNC: mirrors log2u() / LOG2U()
#[inline]
pub fn log2u(x: u32) -> u32 {
    if x <= 1 {
        0
    } else {
        31 - x.leading_zeros()
    }
}

/// log2 rounded up. Returns ceil(log2(x)).
/// PORT-SYNC: mirrors log2u_round_up()
#[inline]
pub fn log2u_round_up(x: u32) -> u32 {
    if x <= 1 {
        0
    } else {
        log2u(x - 1) + 1
    }
}

/// Count trailing zeros for u32. Returns 32 for x == 0.
/// PORT-SYNC: mirrors u32ctz()
#[inline]
pub fn u32ctz(n: u32) -> u32 {
    if n == 0 {
        32
    } else {
        n.trailing_zeros()
    }
}

/// Population count (number of set bits).
/// PORT-SYNC: mirrors popcount()
#[inline]
pub fn popcount_u8(n: u8) -> u32 {
    n.count_ones()
}

#[inline]
pub fn popcount_u16(n: u16) -> u32 {
    n.count_ones()
}

#[inline]
pub fn popcount_u32(n: u32) -> u32 {
    n.count_ones()
}

#[inline]
pub fn popcount_u64(n: u64) -> u32 {
    n.count_ones()
}

/// Check if a value is a power of two.
#[inline]
pub const fn is_power_of_2(x: u64) -> bool {
    x > 0 && (x & (x - 1)) == 0
}

/// Round up to the next power of two.
#[inline]
pub fn next_power_of_2(x: u32) -> u32 {
    if x <= 1 {
        return 1;
    }
    1u32 << log2u_round_up(x)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log2u64() {
        assert_eq!(log2u64(0), 0);
        assert_eq!(log2u64(1), 0);
        assert_eq!(log2u64(2), 1);
        assert_eq!(log2u64(4), 2);
        assert_eq!(log2u64(8), 3);
        assert_eq!(log2u64(1024), 10);
        assert_eq!(log2u64(1 << 63), 63);
    }

    #[test]
    fn test_log2u() {
        assert_eq!(log2u(0), 0);
        assert_eq!(log2u(1), 0);
        assert_eq!(log2u(3), 1);
        assert_eq!(log2u(7), 2);
        assert_eq!(log2u(8), 3);
        assert_eq!(log2u(15), 3);
        assert_eq!(log2u(16), 4);
    }

    #[test]
    fn test_log2u_round_up() {
        assert_eq!(log2u_round_up(0), 0);
        assert_eq!(log2u_round_up(1), 0);
        assert_eq!(log2u_round_up(2), 1);
        assert_eq!(log2u_round_up(3), 2);
        assert_eq!(log2u_round_up(4), 2);
        assert_eq!(log2u_round_up(5), 3);
        assert_eq!(log2u_round_up(8), 3);
        assert_eq!(log2u_round_up(9), 4);
    }

    #[test]
    fn test_u32ctz() {
        assert_eq!(u32ctz(0), 32);
        assert_eq!(u32ctz(1), 0);
        assert_eq!(u32ctz(2), 1);
        assert_eq!(u32ctz(4), 2);
        assert_eq!(u32ctz(8), 3);
        assert_eq!(u32ctz(1 << 31), 31);
    }

    #[test]
    fn test_popcount() {
        assert_eq!(popcount_u8(0), 0);
        assert_eq!(popcount_u8(0xFF), 8);
        assert_eq!(popcount_u8(0b10101010), 4);
        assert_eq!(popcount_u32(0), 0);
        assert_eq!(popcount_u32(0xFFFFFFFF), 32);
        assert_eq!(popcount_u64(0), 0);
        assert_eq!(popcount_u64(0xFFFFFFFFFFFFFFFF), 64);
    }

    #[test]
    fn test_next_power_of_2() {
        assert_eq!(next_power_of_2(0), 1);
        assert_eq!(next_power_of_2(1), 1);
        assert_eq!(next_power_of_2(2), 2);
        assert_eq!(next_power_of_2(3), 4);
        assert_eq!(next_power_of_2(4), 4);
        assert_eq!(next_power_of_2(5), 8);
        assert_eq!(next_power_of_2(7), 8);
        assert_eq!(next_power_of_2(8), 8);
        assert_eq!(next_power_of_2(9), 16);
    }

    #[test]
    fn test_is_power_of_2() {
        assert!(!is_power_of_2(0));
        assert!(is_power_of_2(1));
        assert!(is_power_of_2(2));
        assert!(!is_power_of_2(3));
        assert!(is_power_of_2(4));
        assert!(is_power_of_2(1 << 31));
    }
}
