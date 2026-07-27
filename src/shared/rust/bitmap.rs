// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/bitmap.c, src/shared/bitmap.h
//
// Bitmap operations - efficient bit set for tracking enum values.
// Faithful safe Rust port of the C implementation using BTreeSet.

use std::collections::BTreeSet;

/// Maximum entry value. Bitmaps are only meant to store relatively small
/// numbers (corresponding to, say, an enum), so 64k should be plenty.
///
/// Equivalent to C `BITMAPS_MAX_ENTRY`.
pub const BITMAPS_MAX_ENTRY: u64 = 0xffff;

/// Error type for bitmap operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BitmapError {
    /// The bit number exceeds BITMAPS_MAX_ENTRY.
    OutOfRange,
}

impl std::fmt::Display for BitmapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BitmapError::OutOfRange => write!(
                f,
                "bitmap entry {} exceeds maximum ({})",
                BITMAPS_MAX_ENTRY + 1,
                BITMAPS_MAX_ENTRY
            ),
        }
    }
}

impl std::error::Error for BitmapError {}

/// A bitmap for tracking set bits (typically small enum values).
///
/// Faithful safe Rust port of the C `Bitmap` from `bitmap.h`.
/// Uses `BTreeSet<u64>` internally for ordered iteration and O(log n) operations.
///
/// Corresponds to C `bitmap_new()` / `bitmap_free()` lifecycle — managed via RAII.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Bitmap {
    set: BTreeSet<u64>,
}

impl Bitmap {
    /// Create a new empty bitmap.
    ///
    /// Equivalent to C `bitmap_new()`.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a deep copy of this bitmap.
    ///
    /// Equivalent to C `bitmap_copy()`.
    #[must_use]
    pub fn copy(&self) -> Self {
        self.clone()
    }

    /// Set bit `n`. Returns `Ok(true)` if the bit was newly set,
    /// `Ok(false)` if it was already set.
    ///
    /// Returns `Err(BitmapError::OutOfRange)` if `n > BITMAPS_MAX_ENTRY`.
    ///
    /// Equivalent to C `bitmap_set()` which returns 0 on success,
    /// `-ERANGE` if `n > BITMAPS_MAX_ENTRY`, or `-ENOMEM` on allocation failure.
    /// In safe Rust, allocation failure is not possible with `BTreeSet`.
    pub fn set(&mut self, n: u64) -> Result<bool, BitmapError> {
        if n > BITMAPS_MAX_ENTRY {
            return Err(BitmapError::OutOfRange);
        }
        Ok(self.set.insert(n))
    }

    /// Unset bit `n`. Returns `true` if the bit was previously set,
    /// `false` if it was not set (or out of range).
    ///
    /// Equivalent to C `bitmap_unset()` which silently ignores null/out-of-range.
    pub fn unset(&mut self, n: u64) -> bool {
        // Silently ignore out-of-range values, matching C behavior
        if n > BITMAPS_MAX_ENTRY {
            return false;
        }
        self.set.remove(&n)
    }

    /// Check if bit `n` is set.
    ///
    /// Equivalent to C `bitmap_isset()`.
    pub fn contains(&self, n: u64) -> bool {
        self.set.contains(&n)
    }

    /// Check if all bits are clear (bitmap is empty).
    ///
    /// Equivalent to C `bitmap_isclear()`.
    pub fn is_clear(&self) -> bool {
        self.set.is_empty()
    }

    /// Clear all bits, resetting the bitmap to empty.
    ///
    /// Equivalent to C `bitmap_clear()` which frees the internal array
    /// and resets `n_bitmaps` to 0.
    pub fn clear(&mut self) {
        self.set.clear();
    }

    /// Iterate over all set bits in ascending order.
    ///
    /// Equivalent to C `bitmap_iterate()` / `BITMAP_FOREACH` macro.
    /// Returns bits in increasing order, matching the C scan order.
    pub fn iterate(&self) -> impl Iterator<Item = u64> + '_ {
        self.set.iter().copied()
    }

    /// Check if two bitmaps are equal (contain the same set bits).
    ///
    /// Equivalent to C `bitmap_equal()`. Also available via `PartialEq` (`==`).
    pub fn equal(&self, other: &Self) -> bool {
        self == other
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_is_empty() {
        let b = Bitmap::new();
        assert!(b.is_clear());
        assert_eq!(b.iterate().count(), 0);
    }

    #[test]
    fn test_default_is_empty() {
        let b = Bitmap::default();
        assert!(b.is_clear());
    }

    #[test]
    fn test_set_and_contains() {
        let mut b = Bitmap::new();
        assert!(!b.contains(5));
        assert!(b.set(5).is_ok());
        assert!(b.contains(5));
        assert_eq!(b.set(5).unwrap(), false);
    }

    #[test]
    fn test_set_returns_newly_inserted() {
        let mut b = Bitmap::new();
        assert_eq!(b.set(10).unwrap(), true);
        assert_eq!(b.set(10).unwrap(), false);
        assert_eq!(b.set(20).unwrap(), true);
    }

    #[test]
    fn test_unset_removes_bit() {
        let mut b = Bitmap::new();
        b.set(7).unwrap();
        assert!(b.contains(7));
        assert!(b.unset(7));
        assert!(!b.contains(7));
    }

    #[test]
    fn test_unset_nonexistent_returns_false() {
        let mut b = Bitmap::new();
        assert!(!b.unset(99));
    }

    #[test]
    fn test_set_unset_roundtrip() {
        let mut b = Bitmap::new();
        for i in [0, 1, 63, 64, 65, 100, 1000, 0xffff] {
            assert!(b.set(i).unwrap());
            assert!(b.contains(i));
            assert!(b.unset(i));
            assert!(!b.contains(i));
            assert!(!b.unset(i));
        }
    }

    #[test]
    fn test_set_max_entry() {
        let mut b = Bitmap::new();
        assert!(b.set(BITMAPS_MAX_ENTRY).is_ok());
        assert!(b.contains(BITMAPS_MAX_ENTRY));
    }

    #[test]
    fn test_set_exceeds_max_entry() {
        let mut b = Bitmap::new();
        assert_eq!(b.set(BITMAPS_MAX_ENTRY + 1), Err(BitmapError::OutOfRange));
        assert!(!b.contains(BITMAPS_MAX_ENTRY + 1));
    }

    #[test]
    fn test_unset_exceeds_max_entry() {
        let mut b = Bitmap::new();
        assert!(!b.unset(BITMAPS_MAX_ENTRY + 1));
    }

    #[test]
    fn test_contains_exceeds_max_entry() {
        let b = Bitmap::new();
        assert!(!b.contains(BITMAPS_MAX_ENTRY + 1));
    }

    #[test]
    fn test_is_clear_after_operations() {
        let mut b = Bitmap::new();
        assert!(b.is_clear());
        b.set(1).unwrap();
        assert!(!b.is_clear());
        b.unset(1);
        assert!(b.is_clear());
    }

    #[test]
    fn test_clear_resets_all() {
        let mut b = Bitmap::new();
        b.set(1).unwrap();
        b.set(10).unwrap();
        b.set(100).unwrap();
        b.set(0xffff).unwrap();
        assert!(!b.is_clear());
        b.clear();
        assert!(b.is_clear());
        assert_eq!(b.iterate().count(), 0);
    }

    #[test]
    fn test_clear_idempotent() {
        let mut b = Bitmap::new();
        b.clear();
        assert!(b.is_clear());
        b.set(5).unwrap();
        b.clear();
        b.clear();
        assert!(b.is_clear());
    }

    #[test]
    fn test_copy_independence() {
        let mut b = Bitmap::new();
        b.set(3).unwrap();
        b.set(42).unwrap();

        let mut c = b.copy();
        assert!(c.contains(3));
        assert!(c.contains(42));
        assert!(b.equal(&c));

        c.set(99).unwrap();
        assert!(c.contains(99));
        assert!(!b.contains(99));
        assert!(!b.equal(&c));

        b.unset(3);
        assert!(!b.contains(3));
        assert!(c.contains(3));
    }

    #[test]
    fn test_copy_empty() {
        let b = Bitmap::new();
        let c = b.copy();
        assert!(c.is_clear());
        assert!(b.equal(&c));
    }

    #[test]
    fn test_equal_empty_bitmaps() {
        let a = Bitmap::new();
        let b = Bitmap::new();
        assert!(a.equal(&b));
    }

    #[test]
    fn test_equal_same_bits() {
        let mut a = Bitmap::new();
        let mut b = Bitmap::new();
        a.set(5).unwrap();
        b.set(5).unwrap();
        assert!(a.equal(&b));
    }

    #[test]
    fn test_equal_different_bits() {
        let mut a = Bitmap::new();
        let mut b = Bitmap::new();
        a.set(5).unwrap();
        b.set(6).unwrap();
        assert!(!a.equal(&b));
    }

    #[test]
    fn test_equal_subset() {
        let mut a = Bitmap::new();
        let mut b = Bitmap::new();
        a.set(5).unwrap();
        a.set(10).unwrap();
        b.set(5).unwrap();
        assert!(!a.equal(&b));
    }

    #[test]
    fn test_equal_self() {
        let mut b = Bitmap::new();
        b.set(1).unwrap();
        b.set(1000).unwrap();
        assert!(b.equal(&b));
    }

    #[test]
    fn test_equal_via_partial_eq() {
        let mut a = Bitmap::new();
        let mut b = Bitmap::new();
        a.set(7).unwrap();
        b.set(7).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn test_iterate_empty() {
        let b = Bitmap::new();
        assert_eq!(b.iterate().collect::<Vec<_>>(), Vec::<u64>::new());
    }

    #[test]
    fn test_iterate_single() {
        let mut b = Bitmap::new();
        b.set(42).unwrap();
        assert_eq!(b.iterate().collect::<Vec<_>>(), vec![42]);
    }

    #[test]
    fn test_iterate_ascending_order() {
        let mut b = Bitmap::new();
        for i in [50, 10, 30, 1, 0xffff] {
            b.set(i).unwrap();
        }
        let collected: Vec<u64> = b.iterate().collect();
        assert_eq!(collected, vec![1, 10, 30, 50, 0xffff]);
    }

    #[test]
    fn test_iterate_dense() {
        let mut b = Bitmap::new();
        for i in 0..=20 {
            b.set(i).unwrap();
        }
        let collected: Vec<u64> = b.iterate().collect();
        assert_eq!(collected, (0..=20).collect::<Vec<_>>());
    }

    #[test]
    fn test_iterate_word_boundaries() {
        let mut b = Bitmap::new();
        // Set bits at u64 word boundaries: 63, 64, 65, 127, 128, 129
        for i in [63, 64, 65, 127, 128, 129, 191, 192, 193] {
            b.set(i).unwrap();
        }
        let collected: Vec<u64> = b.iterate().collect();
        assert_eq!(collected, vec![63, 64, 65, 127, 128, 129, 191, 192, 193]);
    }

    #[test]
    fn test_iterate_after_unset() {
        let mut b = Bitmap::new();
        b.set(1).unwrap();
        b.set(2).unwrap();
        b.set(3).unwrap();
        b.unset(2);
        assert_eq!(b.iterate().collect::<Vec<_>>(), vec![1, 3]);
    }

    #[test]
    fn test_iterate_after_clear() {
        let mut b = Bitmap::new();
        b.set(1).unwrap();
        b.set(2).unwrap();
        b.clear();
        assert!(b.iterate().collect::<Vec<_>>().is_empty());
    }

    #[test]
    fn test_zero_bit() {
        let mut b = Bitmap::new();
        assert!(b.set(0).is_ok());
        assert!(b.contains(0));
        assert!(b.unset(0));
        assert!(!b.contains(0));
    }

    #[test]
    fn test_many_bits() {
        let mut b = Bitmap::new();
        let expected: Vec<u64> = (0..=BITMAPS_MAX_ENTRY)
            .step_by(7)
            .filter_map(|i| if b.set(i).unwrap() { Some(i) } else { None })
            .collect();
        assert_eq!(b.iterate().collect::<Vec<_>>(), expected);
    }

    #[test]
    fn test_clone_produces_equal() {
        let mut b = Bitmap::new();
        b.set(1).unwrap();
        b.set(0xffff).unwrap();
        let c = b.clone();
        assert_eq!(b, c);
    }

    #[test]
    fn test_debug_format() {
        let mut b = Bitmap::new();
        b.set(3).unwrap();
        b.set(7).unwrap();
        let debug = format!("{:?}", b);
        assert!(debug.contains("Bitmap"));
    }
}
