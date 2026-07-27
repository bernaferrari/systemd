// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/bitmap.c
//
// Bitmap functions.

// ── Constants ─────────────────────────────────────────────────────────────

pub const BITMAPS_MAX_ENTRY: u32 = 0xffff;
pub const BITMAP_END: u32 = u32::MAX;
const BITS_PER_WORD: usize = u64::BITS as usize;

// ── Errors ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BitmapError {
    OutOfRange,
}

impl std::fmt::Display for BitmapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::OutOfRange => write!(f, "bitmap entry out of range"),
        }
    }
}

impl std::error::Error for BitmapError {}

// ── Types ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Bitmap {
    bitmaps: Vec<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BitmapIterator {
    idx: u32,
}

impl Default for BitmapIterator {
    fn default() -> Self {
        Self { idx: 0 }
    }
}

impl Bitmap {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn copy(&self) -> Self {
        self.clone()
    }

    pub fn is_set(&self, n: u32) -> bool {
        let offset = n as usize / BITS_PER_WORD;
        let rem = n as usize % BITS_PER_WORD;
        self.bitmaps
            .get(offset)
            .is_some_and(|word| word & (1u64 << rem) != 0)
    }

    pub fn is_clear(&self) -> bool {
        self.bitmaps.iter().all(|w| *w == 0)
    }

    pub fn set(&mut self, n: u32) -> Result<(), BitmapError> {
        if n > BITMAPS_MAX_ENTRY {
            return Err(BitmapError::OutOfRange);
        }

        let offset = n as usize / BITS_PER_WORD;
        if offset >= self.bitmaps.len() {
            self.bitmaps.resize(offset + 1, 0);
        }

        self.bitmaps[offset] |= 1u64 << (n as usize % BITS_PER_WORD);
        Ok(())
    }

    pub fn unset(&mut self, n: u32) {
        let offset = n as usize / BITS_PER_WORD;
        if let Some(word) = self.bitmaps.get_mut(offset) {
            *word &= !(1u64 << (n as usize % BITS_PER_WORD));
        }
    }

    pub fn clear(&mut self) {
        self.bitmaps.clear();
    }

    pub fn equal(&self, other: &Self) -> bool {
        let common = self.bitmaps.len().min(other.bitmaps.len());
        if self.bitmaps[..common] != other.bitmaps[..common] {
            return false;
        }

        let tail = if self.bitmaps.len() > other.bitmaps.len() {
            &self.bitmaps[common..]
        } else {
            &other.bitmaps[common..]
        };

        tail.iter().all(|w| *w == 0)
    }

    pub fn iterate(&self, iter: &mut BitmapIterator) -> Option<u32> {
        if iter.idx == BITMAP_END {
            return None;
        }

        let mut offset = iter.idx as usize / BITS_PER_WORD;
        let mut rem = iter.idx as usize % BITS_PER_WORD;
        let mut bitmask = 1u64 << rem;

        while offset < self.bitmaps.len() {
            let word = self.bitmaps[offset];
            if word != 0 {
                while bitmask != 0 {
                    if word & bitmask != 0 {
                        let n = (offset * BITS_PER_WORD + rem) as u32;
                        iter.idx = n.saturating_add(1);
                        return Some(n);
                    }
                    bitmask <<= 1;
                    rem += 1;
                }
            }

            offset += 1;
            rem = 0;
            bitmask = 1;
        }

        iter.idx = BITMAP_END;
        None
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_bitmap_is_clear() {
        let b = Bitmap::new();
        assert!(b.is_clear());
        assert!(!b.is_set(0));
    }

    #[test]
    fn set_and_unset_single_bit() {
        let mut b = Bitmap::new();
        b.set(5).unwrap();
        assert!(b.is_set(5));
        b.unset(5);
        assert!(!b.is_set(5));
        assert!(b.is_clear());
    }

    #[test]
    fn set_across_word_boundary() {
        let mut b = Bitmap::new();
        b.set(63).unwrap();
        b.set(64).unwrap();
        assert!(b.is_set(63));
        assert!(b.is_set(64));
        assert!(!b.is_set(62));
    }

    #[test]
    fn set_rejects_out_of_range() {
        let mut b = Bitmap::new();
        assert_eq!(b.set(BITMAPS_MAX_ENTRY + 1), Err(BitmapError::OutOfRange));
    }

    #[test]
    fn clear_drops_all_bits() {
        let mut b = Bitmap::new();
        b.set(1).unwrap();
        b.set(100).unwrap();
        b.clear();
        assert!(b.is_clear());
        assert!(!b.is_set(1));
        assert!(!b.is_set(100));
    }

    #[test]
    fn copy_is_independent() {
        let mut a = Bitmap::new();
        a.set(1).unwrap();
        let mut b = a.copy();
        b.set(2).unwrap();
        assert!(a.is_set(1));
        assert!(!a.is_set(2));
        assert!(b.is_set(2));
    }

    #[test]
    fn equal_ignores_zero_tail_words() {
        let mut a = Bitmap::new();
        let mut b = Bitmap::new();
        a.set(0).unwrap();
        b.set(0).unwrap();
        b.set(128).unwrap();
        b.unset(128);
        assert!(a.equal(&b));
    }

    #[test]
    fn iterate_returns_bits_in_ascending_order() {
        let mut b = Bitmap::new();
        for bit in [0, 10, 63, 64, 129] {
            b.set(bit).unwrap();
        }

        let mut iter = BitmapIterator::default();
        let mut seen = Vec::new();
        while let Some(bit) = b.iterate(&mut iter) {
            seen.push(bit);
        }

        assert_eq!(seen, vec![0, 10, 63, 64, 129]);
        assert_eq!(iter.idx, BITMAP_END);
    }

    #[test]
    fn iterate_empty_bitmap_ends_immediately() {
        let b = Bitmap::new();
        let mut iter = BitmapIterator::default();
        assert_eq!(b.iterate(&mut iter), None);
        assert_eq!(iter.idx, BITMAP_END);
    }
}
