// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: scope=basic.bitmap; authority=src/shared/bitmap.c,src/shared/bitmap.h,src/basic/iterator.h
//
// Bitmap functions.

use libc::c_void;

// ── Constants ─────────────────────────────────────────────────────────────

pub const BITMAPS_MAX_ENTRY: u32 = 0xffff;
pub const BITMAP_END: u32 = u32::MAX;
const BITS_PER_WORD: usize = u64::BITS as usize;

#[repr(C)]
pub struct CBitmap {
    bitmaps: *mut u64,
    n_bitmaps: usize,
}

#[repr(C)]
pub struct CIterator {
    next_key: *const c_void,
    idx: u32,
}

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

fn bitmap_offset(n: u32) -> usize {
    n as usize / BITS_PER_WORD
}

fn bitmap_mask(n: u32) -> u64 {
    1_u64 << (n as usize % BITS_PER_WORD)
}

/// Read a bitmap word from a valid C bitmap allocation.
///
/// # Safety
/// `bitmap` must be a valid C `Bitmap`, and its `bitmaps` field must reference
/// at least `n_bitmaps` aligned `u64` words when `n_bitmaps` is non-zero.
unsafe fn bitmap_words(bitmap: *const CBitmap) -> *const u64 {
    // SAFETY: guaranteed by this helper's documented C bitmap representation contract.
    unsafe { (*bitmap).bitmaps.cast_const() }
}

/// Allocate a zeroed C-compatible bitmap object.
fn c_bitmap_new() -> *mut CBitmap {
    // SAFETY: libc allocates suitably aligned storage for a C Bitmap object.
    unsafe { libc::calloc(1, std::mem::size_of::<CBitmap>()) }.cast::<CBitmap>()
}

/// Exact C ABI shadow of `bitmap_isset()`.
///
/// # Safety
/// A non-null `b` must point to a valid C `Bitmap` whose word array is readable
/// for its recorded `n_bitmaps` length. The function borrows all input memory.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_bitmap_isset(b: *const CBitmap, n: u32) -> bool {
    if b.is_null() {
        return false;
    }
    let offset = bitmap_offset(n);
    // SAFETY: required by this FFI boundary's C bitmap representation contract.
    if offset >= unsafe { (*b).n_bitmaps } {
        return false;
    }
    // SAFETY: the representation contract guarantees this indexed word is readable.
    unsafe { *bitmap_words(b).add(offset) & bitmap_mask(n) != 0 }
}

/// Exact C ABI shadow of `bitmap_isclear()`.
///
/// # Safety
/// A non-null `b` must point to a valid C `Bitmap` whose word array is readable
/// for its recorded `n_bitmaps` length. The function borrows all input memory.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_bitmap_isclear(b: *const CBitmap) -> bool {
    if b.is_null() {
        return true;
    }
    // SAFETY: required by this FFI boundary's C bitmap representation contract.
    let n_bitmaps = unsafe { (*b).n_bitmaps };
    // SAFETY: the representation contract guarantees each indexed word is readable.
    (0..n_bitmaps).all(|index| unsafe { *bitmap_words(b).add(index) == 0 })
}

/// Exact C ABI shadow of `bitmap_equal()`.
///
/// # Safety
/// Each non-null input must point to a valid C `Bitmap` whose word array is
/// readable for its recorded length. The function borrows all input memory.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_bitmap_equal(a: *const CBitmap, b: *const CBitmap) -> bool {
    if a == b {
        return true;
    }
    if a.is_null() || b.is_null() {
        return false;
    }
    // SAFETY: required by this FFI boundary's C bitmap representation contract.
    let (a_len, b_len) = unsafe { ((*a).n_bitmaps, (*b).n_bitmaps) };
    let common = a_len.min(b_len);
    for index in 0..common {
        // SAFETY: the representation contract guarantees both indexed words are readable.
        if unsafe { *bitmap_words(a).add(index) != *bitmap_words(b).add(index) } {
            return false;
        }
    }
    let (longer, longer_len) = if a_len > b_len {
        (a, a_len)
    } else {
        (b, b_len)
    };
    // SAFETY: the representation contract guarantees each indexed word is readable.
    (common..longer_len).all(|index| unsafe { *bitmap_words(longer).add(index) == 0 })
}

/// Exact C ABI shadow of `bitmap_new()`.
///
/// The result has libc allocator ownership and must be passed to
/// `rs_bitmap_free()` or C `bitmap_free()`.
#[unsafe(no_mangle)]
pub extern "C" fn rs_bitmap_new() -> *mut CBitmap {
    c_bitmap_new()
}

/// Exact C ABI shadow of `bitmap_copy()`.
///
/// # Safety
/// `b` must point to a valid C `Bitmap` whose word array is readable for its
/// recorded length. The returned independent copy has libc allocator ownership.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_bitmap_copy(b: *mut CBitmap) -> *mut CBitmap {
    if b.is_null() {
        return std::ptr::null_mut();
    }
    let copy = c_bitmap_new();
    if copy.is_null() {
        return std::ptr::null_mut();
    }
    // SAFETY: required by this FFI boundary's C bitmap representation contract.
    let n_bitmaps = unsafe { (*b).n_bitmaps };
    if n_bitmaps == 0 {
        return copy;
    }
    let Some(bytes) = n_bitmaps.checked_mul(std::mem::size_of::<u64>()) else {
        // SAFETY: the local object has not escaped this function.
        unsafe { libc::free(copy.cast::<c_void>()) };
        return std::ptr::null_mut();
    };
    // SAFETY: libc allocates a word array of the checked byte length.
    let words = unsafe { libc::malloc(bytes) }.cast::<u64>();
    if words.is_null() {
        // SAFETY: the local object has not escaped this function.
        unsafe { libc::free(copy.cast::<c_void>()) };
        return std::ptr::null_mut();
    }
    // SAFETY: both word arrays are valid for `n_bitmaps` words by their contracts.
    unsafe {
        std::ptr::copy_nonoverlapping(bitmap_words(b), words, n_bitmaps);
        (*copy).bitmaps = words;
        (*copy).n_bitmaps = n_bitmaps;
    }
    copy
}

/// Exact C ABI shadow of `bitmap_free()`.
///
/// # Safety
/// A non-null `b` must be a libc-owned valid C `Bitmap` and its `bitmaps` field
/// must be either null or a libc-owned allocation. It must not be used again.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_bitmap_free(b: *mut CBitmap) -> *mut CBitmap {
    if b.is_null() {
        return std::ptr::null_mut();
    }
    // SAFETY: required by this FFI boundary's libc ownership contract.
    unsafe {
        libc::free((*b).bitmaps.cast::<c_void>());
        libc::free(b.cast::<c_void>());
    }
    std::ptr::null_mut()
}

/// Exact C ABI shadow of `bitmap_ensure_allocated()`.
///
/// # Safety
/// `b` must point to writable `Bitmap *` storage. If `*b` is non-null, it must
/// be a valid C `Bitmap` with libc allocation ownership.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_bitmap_ensure_allocated(b: *mut *mut CBitmap) -> i32 {
    if b.is_null() {
        return -libc::EINVAL;
    }
    // SAFETY: required by this FFI boundary's writable-output contract.
    if !unsafe { (*b).is_null() } {
        return 0;
    }
    let bitmap = c_bitmap_new();
    if bitmap.is_null() {
        return -libc::ENOMEM;
    }
    // SAFETY: required by this FFI boundary's writable-output contract.
    unsafe { *b = bitmap };
    0
}

/// Exact C ABI shadow of `bitmap_set()`.
///
/// # Safety
/// `b` must point to a valid libc-owned C `Bitmap`; its existing word array
/// must be a libc allocation (or null when empty). It may be reallocated.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_bitmap_set(b: *mut CBitmap, n: u32) -> i32 {
    if b.is_null() {
        return -libc::EINVAL;
    }
    if n > BITMAPS_MAX_ENTRY {
        return -libc::ERANGE;
    }
    let offset = bitmap_offset(n);
    // SAFETY: required by this FFI boundary's C bitmap representation contract.
    let old_len = unsafe { (*b).n_bitmaps };
    if offset >= old_len {
        let Some(new_len) = offset.checked_add(1) else {
            return -libc::ENOMEM;
        };
        let Some(bytes) = new_len.checked_mul(std::mem::size_of::<u64>()) else {
            return -libc::ENOMEM;
        };
        // SAFETY: `bitmaps` is libc-owned by this FFI boundary's contract.
        let words = unsafe { libc::realloc((*b).bitmaps.cast::<c_void>(), bytes) }.cast::<u64>();
        if words.is_null() {
            return -libc::ENOMEM;
        }
        // SAFETY: realloc preserved the old prefix and made the requested suffix live.
        unsafe {
            for index in old_len..new_len {
                *words.add(index) = 0;
            }
            (*b).bitmaps = words;
            (*b).n_bitmaps = new_len;
        }
    }
    // SAFETY: the representation contract guarantees the selected word is writable.
    unsafe { *(*b).bitmaps.add(offset) |= bitmap_mask(n) };
    0
}

/// Exact C ABI shadow of `bitmap_unset()`.
///
/// # Safety
/// A non-null `b` must point to a valid C `Bitmap` with a writable word array.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_bitmap_unset(b: *mut CBitmap, n: u32) {
    if b.is_null() {
        return;
    }
    let offset = bitmap_offset(n);
    // SAFETY: required by this FFI boundary's C bitmap representation contract.
    if offset >= unsafe { (*b).n_bitmaps } {
        return;
    }
    // SAFETY: the representation contract guarantees the selected word is writable.
    unsafe { *(*b).bitmaps.add(offset) &= !bitmap_mask(n) };
}

/// Exact C ABI shadow of `bitmap_clear()`.
///
/// # Safety
/// A non-null `b` must point to a valid libc-owned C `Bitmap`; its word array
/// must be either null or a libc-owned allocation.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_bitmap_clear(b: *mut CBitmap) {
    if b.is_null() {
        return;
    }
    // SAFETY: required by this FFI boundary's libc ownership contract.
    unsafe {
        libc::free((*b).bitmaps.cast::<c_void>());
        (*b).bitmaps = std::ptr::null_mut();
        (*b).n_bitmaps = 0;
    }
}

/// Exact C ABI shadow of `bitmap_iterate()`.
///
/// # Safety
/// A non-null `b` must be a valid readable C `Bitmap`. `i` and `n` must point
/// to writable C `Iterator` and `unsigned` storage, respectively.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_bitmap_iterate(
    b: *const CBitmap,
    i: *mut CIterator,
    n: *mut u32,
) -> bool {
    if i.is_null() || n.is_null() || b.is_null() {
        return false;
    }
    // SAFETY: required by this FFI boundary's C Iterator contract.
    if unsafe { (*i).idx } == BITMAP_END {
        return false;
    }
    // SAFETY: required by this FFI boundary's C bitmap representation contract.
    let n_bitmaps = unsafe { (*b).n_bitmaps };
    // SAFETY: required by this FFI boundary's C Iterator contract.
    let mut offset = bitmap_offset(unsafe { (*i).idx });
    // SAFETY: required by this FFI boundary's C Iterator contract.
    let mut rem = unsafe { (*i).idx as usize % BITS_PER_WORD };
    let mut bitmask = 1_u64 << rem;
    while offset < n_bitmaps {
        // SAFETY: the representation contract guarantees this indexed word is readable.
        if unsafe { *bitmap_words(b).add(offset) } != 0 {
            while bitmask != 0 {
                // SAFETY: the representation contract guarantees this indexed word is readable.
                if unsafe { *bitmap_words(b).add(offset) & bitmask != 0 } {
                    let value = (offset * BITS_PER_WORD + rem) as u32;
                    // SAFETY: required by this FFI boundary's writable Iterator/output contract.
                    unsafe {
                        *n = value;
                        (*i).idx = value.wrapping_add(1);
                    }
                    return true;
                }
                bitmask <<= 1;
                rem += 1;
            }
        }
        offset += 1;
        rem = 0;
        bitmask = 1;
    }
    // SAFETY: required by this FFI boundary's writable Iterator contract.
    unsafe { (*i).idx = BITMAP_END };
    false
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
