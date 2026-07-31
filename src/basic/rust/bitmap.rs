// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: scope=basic.bitmap; authority=src/shared/bitmap.c,src/shared/bitmap.h,src/basic/iterator.h
//
// Bitmap functions.

use libc::c_void;
use std::slice;

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

impl CBitmap {
    // C ABI adapters ensure that non-empty bitmaps carry a live aligned word
    // allocation. The safe bitmap core works exclusively with this slice.
    fn words(&self) -> &[u64] {
        if self.n_bitmaps == 0 {
            return &[];
        }
        // SAFETY: the C ABI adapter established the C Bitmap representation
        // invariant for its non-empty word allocation.
        unsafe { slice::from_raw_parts(self.bitmaps, self.n_bitmaps) }
    }

    fn words_mut(&mut self) -> &mut [u64] {
        if self.n_bitmaps == 0 {
            return &mut [];
        }
        // SAFETY: the C ABI adapter established exclusive access to the live
        // C Bitmap word allocation.
        unsafe { slice::from_raw_parts_mut(self.bitmaps, self.n_bitmaps) }
    }

    fn is_set(&self, n: u32) -> bool {
        self.words()
            .get(bitmap_offset(n))
            .is_some_and(|word| word & bitmap_mask(n) != 0)
    }

    fn is_clear(&self) -> bool {
        self.words().iter().all(|word| *word == 0)
    }

    fn equal(&self, other: &Self) -> bool {
        equal_words(self.words(), other.words())
    }

    fn unset(&mut self, n: u32) {
        if let Some(word) = self.words_mut().get_mut(bitmap_offset(n)) {
            *word &= !bitmap_mask(n);
        }
    }

    fn grow_to(&mut self, new_len: usize) -> bool {
        debug_assert!(new_len > self.n_bitmaps);
        let Some(bytes) = new_len.checked_mul(std::mem::size_of::<u64>()) else {
            return false;
        };
        // SAFETY: the C ABI adapter guarantees the existing pointer is a
        // libc allocation (or null when empty), so realloc retains ownership.
        let words = unsafe { libc::realloc(self.bitmaps.cast::<c_void>(), bytes) }.cast::<u64>();
        if words.is_null() {
            return false;
        }

        let old_len = self.n_bitmaps;
        // SAFETY: realloc returned a live allocation for exactly `new_len`
        // words; only the newly allocated suffix is initialized here.
        let initialized = unsafe { slice::from_raw_parts_mut(words, new_len) };
        initialized[old_len..].fill(0);
        self.bitmaps = words;
        self.n_bitmaps = new_len;
        true
    }

    fn set(&mut self, n: u32) -> bool {
        let offset = bitmap_offset(n);
        if offset >= self.n_bitmaps && !self.grow_to(offset + 1) {
            return false;
        }
        self.words_mut()[offset] |= bitmap_mask(n);
        true
    }

    fn clear(&mut self) {
        // SAFETY: the C ABI adapter guarantees this pointer has libc
        // allocation ownership or is null.
        unsafe { libc::free(self.bitmaps.cast::<c_void>()) };
        self.bitmaps = std::ptr::null_mut();
        self.n_bitmaps = 0;
    }
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

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BitmapIterator {
    idx: u32,
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
        iterate_words(&self.bitmaps, &mut iter.idx)
    }
}

fn bitmap_offset(n: u32) -> usize {
    n as usize / BITS_PER_WORD
}

fn bitmap_mask(n: u32) -> u64 {
    1_u64 << (n as usize % BITS_PER_WORD)
}

fn equal_words(left: &[u64], right: &[u64]) -> bool {
    let common = left.len().min(right.len());
    left[..common] == right[..common]
        && left[common..]
            .iter()
            .chain(&right[common..])
            .all(|word| *word == 0)
}

fn iterate_words(words: &[u64], idx: &mut u32) -> Option<u32> {
    if *idx == BITMAP_END {
        return None;
    }

    let mut offset = bitmap_offset(*idx);
    let mut rem = *idx as usize % BITS_PER_WORD;
    let mut bitmask = 1_u64 << rem;

    while let Some(&word) = words.get(offset) {
        if word != 0 {
            while bitmask != 0 {
                if word & bitmask != 0 {
                    let value = (offset * BITS_PER_WORD + rem) as u32;
                    *idx = value.wrapping_add(1);
                    return Some(value);
                }
                bitmask <<= 1;
                rem += 1;
            }
        }
        offset += 1;
        rem = 0;
        bitmask = 1;
    }

    *idx = BITMAP_END;
    None
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
    // SAFETY: required by this FFI boundary's C bitmap representation contract.
    unsafe { (&*b).is_set(n) }
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
    unsafe { (&*b).is_clear() }
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
    unsafe { (&*a).equal(&*b) }
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
    let source = unsafe { (&*b).words() };
    if source.is_empty() {
        return copy;
    }
    let Some(bytes) = source.len().checked_mul(std::mem::size_of::<u64>()) else {
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
    // SAFETY: `words` names a fresh allocation for exactly `source.len()`
    // words and the borrowed source slice is live by the C Bitmap contract.
    unsafe {
        slice::from_raw_parts_mut(words, source.len()).copy_from_slice(source);
        (*copy).bitmaps = words;
        (*copy).n_bitmaps = source.len();
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
    // SAFETY: required by this FFI boundary's C bitmap representation contract.
    if unsafe { (&mut *b).set(n) } {
        0
    } else {
        -libc::ENOMEM
    }
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
    // SAFETY: required by this FFI boundary's C bitmap representation contract.
    unsafe { (&mut *b).unset(n) };
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
    unsafe { (&mut *b).clear() };
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
    // SAFETY: required by this FFI boundary's bitmap, iterator, and output
    // pointer contracts.
    let (bitmap, iter, output) = unsafe { (&*b, &mut *i, &mut *n) };
    let Some(value) = iterate_words(bitmap.words(), &mut iter.idx) else {
        return false;
    };
    *output = value;
    true
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
