// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/basic/macro.h (u64_multiply_safe, ALIGN_POWER2, size_add)
//
// Safe arithmetic operations that return sentinel values on overflow, plus a
// narrow exact C ABI for the registered macro.h comparison.

// ── u64_multiply_safe ────────────────────────────────────────────────────

/// Returns 0 on overflow, otherwise a * b.
///
/// Faithful to `static inline uint64_t u64_multiply_safe(uint64_t a, uint64_t b)` in macro.h:
/// returns 0 when `a != 0 && b > (UINT64_MAX / a)`.
pub fn u64_multiply_safe(a: u64, b: u64) -> u64 {
    if a != 0 && b > (u64::MAX / a) {
        return 0;
    }
    a * b
}

/// Exact C ABI facade for `u64_multiply_safe()`.
#[unsafe(no_mangle)]
pub extern "C" fn rs_u64_multiply_safe(a: u64, b: u64) -> u64 {
    u64_multiply_safe(a, b)
}

// ── ALIGN_POWER2 ─────────────────────────────────────────────────────────

/// Align to next higher power-of-2. Returns 0 for input 0 or on overflow.
///
/// Faithful to `static inline unsigned long ALIGN_POWER2(unsigned long u)` in macro.h.
/// `c_ulong` keeps the safe core and the C boundary correct on every supported
/// target instead of assuming LP64.
pub fn align_power2(u: libc::c_ulong) -> libc::c_ulong {
    if u == 0 {
        return 0;
    }
    if u == 1 {
        return 1;
    }
    let leading_zeros = (u - 1).leading_zeros();
    if leading_zeros < 1 {
        return 0;
    }
    1 << (libc::c_ulong::BITS - leading_zeros)
}

/// Exact C ABI facade for `ALIGN_POWER2()`.
#[allow(non_snake_case)]
#[unsafe(no_mangle)]
pub extern "C" fn rs_ALIGN_POWER2(u: libc::c_ulong) -> libc::c_ulong {
    align_power2(u)
}

// ── size_add ─────────────────────────────────────────────────────────────

/// Saturating addition for size_t.
///
/// Faithful to `static inline size_t size_add(size_t x, size_t y)` in macro.h,
/// which delegates to `saturate_add(x, y, SIZE_MAX)`.
pub fn size_add(x: usize, y: usize) -> usize {
    x.saturating_add(y)
}

/// Exact C ABI facade for `size_add()`.
#[unsafe(no_mangle)]
pub extern "C" fn rs_size_add(x: usize, y: usize) -> usize {
    size_add(x, y)
}

// ── size_multiply ────────────────────────────────────────────────────────

/// Safe multiplication for size_t. Returns `None` on overflow.
///
/// Mirrors the overflow-safety pattern of `u64_multiply_safe` but for `usize`,
/// returning a `Result` instead of a sentinel value for idiomatic Rust usage.
pub fn size_multiply_safe(x: usize, y: usize) -> Option<usize> {
    if y != 0 && x > (usize::MAX / y) {
        return None;
    }
    Some(x * y)
}

// ── size_round_up ────────────────────────────────────────────────────────

/// Round `x` up to the next multiple of `alignment`. Returns `None` on overflow.
///
/// Common pattern in systemd for computing buffer sizes with alignment.
pub fn size_round_up(x: usize, alignment: usize) -> Option<usize> {
    if alignment == 0 {
        return None;
    }
    let remainder = x % alignment;
    if remainder == 0 {
        return Some(x);
    }
    x.checked_add(alignment - remainder)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_u64_multiply_safe_normal() {
        assert_eq!(u64_multiply_safe(2, 3), 6);
        assert_eq!(u64_multiply_safe(0, 100), 0);
        assert_eq!(u64_multiply_safe(100, 0), 0);
        assert_eq!(u64_multiply_safe(1, 1), 1);
        assert_eq!(u64_multiply_safe(1_000_000, 1_000_000), 1_000_000_000_000);
    }

    #[test]
    fn test_u64_multiply_safe_overflow() {
        assert_eq!(u64_multiply_safe(u64::MAX, 2), 0);
        assert_eq!(u64_multiply_safe(u64::MAX, u64::MAX), 0);
        assert_eq!(u64_multiply_safe(u64::MAX / 2 + 1, 2), 0);
        assert_eq!(u64_multiply_safe(u64::MAX / 3 + 1, 3), 0);
    }

    #[test]
    fn test_u64_multiply_safe_boundary() {
        assert_eq!(u64_multiply_safe(u64::MAX / 2, 2), u64::MAX - 1);
        assert_eq!(u64_multiply_safe(u64::MAX, 1), u64::MAX);
        assert_eq!(u64_multiply_safe(1, u64::MAX), u64::MAX);
    }

    #[test]
    fn test_u64_multiply_safe_identity() {
        assert_eq!(u64_multiply_safe(1, u64::MAX), u64::MAX);
        assert_eq!(u64_multiply_safe(u64::MAX, 1), u64::MAX);
        assert_eq!(u64_multiply_safe(1, 0), 0);
        assert_eq!(u64_multiply_safe(0, 1), 0);
    }

    #[test]
    fn test_align_power2_normal() {
        assert_eq!(align_power2(1), 1);
        assert_eq!(align_power2(2), 2);
        assert_eq!(align_power2(3), 4);
        assert_eq!(align_power2(4), 4);
        assert_eq!(align_power2(5), 8);
        assert_eq!(align_power2(7), 8);
        assert_eq!(align_power2(8), 8);
        assert_eq!(align_power2(9), 16);
        assert_eq!(align_power2(15), 16);
        assert_eq!(align_power2(16), 16);
    }

    #[test]
    fn test_align_power2_zero() {
        assert_eq!(align_power2(0), 0);
    }

    #[test]
    fn test_align_power2_powers_of_two() {
        for i in 0..libc::c_ulong::BITS {
            let p: libc::c_ulong = 1 << i;
            assert_eq!(align_power2(p), p, "align_power2(2^{}) should be {}", i, p);
        }
    }

    #[test]
    fn test_align_power2_large() {
        let half: libc::c_ulong = 1 << (libc::c_ulong::BITS - 1);
        assert_eq!(align_power2(half), half);
        assert_eq!(align_power2(half + 1), 0);
    }

    #[test]
    fn test_size_add_normal() {
        assert_eq!(size_add(0, 0), 0);
        assert_eq!(size_add(0, 5), 5);
        assert_eq!(size_add(5, 0), 5);
        assert_eq!(size_add(2, 3), 5);
        assert_eq!(size_add(usize::MAX / 2, usize::MAX / 2), usize::MAX - 1);
    }

    #[test]
    fn test_size_add_saturating() {
        assert_eq!(size_add(usize::MAX, 1), usize::MAX);
        assert_eq!(size_add(usize::MAX, usize::MAX), usize::MAX);
        assert_eq!(size_add(usize::MAX - 1, 2), usize::MAX);
    }

    #[test]
    fn test_size_multiply_safe_normal() {
        assert_eq!(size_multiply_safe(2, 3), Some(6));
        assert_eq!(size_multiply_safe(0, 100), Some(0));
        assert_eq!(size_multiply_safe(100, 0), Some(0));
        assert_eq!(size_multiply_safe(1, 1), Some(1));
    }

    #[test]
    fn test_size_multiply_safe_overflow() {
        assert_eq!(size_multiply_safe(usize::MAX, 2), None);
        assert_eq!(size_multiply_safe(usize::MAX, usize::MAX), None);
    }

    #[test]
    fn test_size_round_up_normal() {
        assert_eq!(size_round_up(0, 8), Some(0));
        assert_eq!(size_round_up(1, 8), Some(8));
        assert_eq!(size_round_up(7, 8), Some(8));
        assert_eq!(size_round_up(8, 8), Some(8));
        assert_eq!(size_round_up(9, 8), Some(16));
        assert_eq!(size_round_up(100, 1), Some(100));
    }

    #[test]
    fn test_size_round_up_zero_alignment() {
        assert_eq!(size_round_up(10, 0), None);
    }
}
