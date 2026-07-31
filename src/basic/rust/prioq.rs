// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: scope=basic.prioq; authority=src/basic/prioq.c,src/basic/prioq.h
//
// Priority queue (min-heap) with custom comparator support.

use libc::{c_int, c_void};
use std::cmp::Ordering;

// ── Constants ─────────────────────────────────────────────────────────────

/// Sentinel value for an invalid priority queue index.
pub const PRIOQ_IDX_NULL: u32 = u32::MAX;

// ── Types ─────────────────────────────────────────────────────────────────

/// Comparator function type for priority queue ordering.
pub type CompareFn<T> = fn(&T, &T) -> Ordering;

/// A priority queue implemented as a min-heap.
///
/// Items are ordered by the comparator provided at construction time.
/// The item for which the comparator returns `Ordering::Less` relative to
/// all others is at the front (peek/pop return it first).
pub struct Prioq<T> {
    items: Vec<T>,
    compare: CompareFn<T>,
}

// ── Internal helpers ──────────────────────────────────────────────────────

impl<T> Prioq<T> {
    /// Compare items at indices `a` and `b`.
    fn cmp(&self, a: usize, b: usize) -> Ordering {
        (self.compare)(&self.items[a], &self.items[b])
    }

    /// Bubble the item at `idx` up towards the root until the heap
    /// property is restored.  Returns the final index.
    fn shuffle_up(&mut self, mut idx: usize) -> usize {
        while idx > 0 {
            let parent = (idx - 1) / 2;
            if self.cmp(parent, idx) != Ordering::Greater {
                break;
            }
            self.items.swap(idx, parent);
            idx = parent;
        }
        idx
    }

    /// Push the item at `idx` down towards the leaves until the heap
    /// property is restored.  Returns the final index.
    fn shuffle_down(&mut self, mut idx: usize) -> usize {
        loop {
            let left = 2 * idx + 1;
            if left >= self.items.len() {
                break;
            }
            let right = left + 1;

            // Pick the smallest of idx, left-child, right-child
            let mut smallest = if self.cmp(left, idx) == Ordering::Less {
                left
            } else {
                idx
            };

            if right < self.items.len() && self.cmp(right, smallest) == Ordering::Less {
                smallest = right;
            }

            if smallest == idx {
                break;
            }

            self.items.swap(idx, smallest);
            idx = smallest;
        }
        idx
    }
}

// ── Public API ────────────────────────────────────────────────────────────

impl<T> Prioq<T> {
    /// Create a new empty priority queue ordered by `compare`.
    pub fn new(compare: CompareFn<T>) -> Self {
        Self {
            items: Vec::new(),
            compare,
        }
    }

    /// Insert `data` into the queue.  Returns the index where the item
    /// was placed.  Note that this index may change as subsequent
    /// insertions or removals rebalance the heap.
    pub fn put(&mut self, data: T) -> u32 {
        let idx = self.items.len();
        self.items.push(data);
        self.shuffle_up(idx) as u32
    }

    /// Remove and return the smallest item (according to the comparator).
    pub fn pop(&mut self) -> Option<T> {
        if self.items.is_empty() {
            return None;
        }
        let last = self.items.len() - 1;
        self.items.swap(0, last);
        let data = self.items.pop().unwrap();
        if !self.items.is_empty() {
            let k = self.shuffle_down(0);
            self.shuffle_up(k);
        }
        Some(data)
    }

    /// Remove the item at the given heap index.
    pub fn remove_at(&mut self, idx: u32) -> Option<T> {
        let idx = idx as usize;
        if idx >= self.items.len() {
            return None;
        }
        let last = self.items.len() - 1;
        if idx == last {
            return self.items.pop();
        }
        self.items.swap(idx, last);
        let data = self.items.pop().unwrap();
        let k = self.shuffle_down(idx);
        self.shuffle_up(k);
        Some(data)
    }

    /// Remove the first item for which `predicate` returns true.
    pub fn remove_where(&mut self, mut predicate: impl FnMut(&T) -> bool) -> Option<T> {
        let idx = self.items.iter().position(|x| predicate(x))?;
        self.remove_at(idx as u32)
    }

    /// Rebalance the heap after the item at `idx` may have changed its
    /// ordering relative to its neighbours.
    pub fn reshuffle_at(&mut self, idx: u32) {
        let idx = idx as usize;
        if idx >= self.items.len() {
            return;
        }
        let k = self.shuffle_down(idx);
        self.shuffle_up(k);
    }

    /// Rebalance the heap after the first item matching `predicate` may
    /// have changed its ordering relative to its neighbours.
    pub fn reshuffle_where(&mut self, mut predicate: impl FnMut(&T) -> bool) {
        if let Some(idx) = self.items.iter().position(|x| predicate(x)) {
            let k = self.shuffle_down(idx);
            self.shuffle_up(k);
        }
    }

    /// Peek at the smallest item without removing it.
    pub fn peek(&self) -> Option<&T> {
        self.items.first()
    }

    /// Peek at the item stored at heap index `idx`.
    pub fn peek_at(&self, idx: u32) -> Option<&T> {
        self.items.get(idx as usize)
    }

    /// Get a mutable reference to the item at heap index `idx`.
    pub fn get_mut(&mut self, idx: u32) -> Option<&mut T> {
        self.items.get_mut(idx as usize)
    }

    /// Number of items in the queue.
    pub fn len(&self) -> u32 {
        self.items.len() as u32
    }

    /// True when the queue contains no items.
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
}

// ── C ABI facade ──────────────────────────────────────────────────────────

const EINVAL: c_int = 22;
const ENOMEM: c_int = 12;

/// C callback ABI used by the opaque priority-queue facade.
///
/// # Safety
/// The callback borrows its two data pointers for the duration of a comparison
/// and must return a negative, zero, or positive value as `compare_func_t`
/// does in `prioq.h`; it must neither unwind nor re-enter the queue.
pub type PrioqCompareFn = Option<unsafe extern "C" fn(*const c_void, *const c_void) -> c_int>;

#[derive(Clone, Copy)]
struct PrioqItem {
    data: *mut c_void,
    index: *mut u32,
}

/// Opaque C handle. C callers may retain and exchange this pointer, but only
/// the exported Rust facade owns its allocation and vector bookkeeping.
#[repr(C)]
pub struct RsPrioq {
    // SAFETY: a present callback is invoked only under `compare_items`'s
    // documented data-pointer and non-reentrancy contract.
    compare: PrioqCompareFn,
    items: Vec<PrioqItem>,
}

impl RsPrioq {
    // SAFETY: `compare` is retained as an opaque C callback and is invoked
    // only by the documented `compare_items` boundary.
    fn new(compare: PrioqCompareFn) -> Self {
        Self {
            compare,
            items: Vec::new(),
        }
    }

    // The C ABI adapters establish the callback, data-pointer, and
    // index-pointer contracts once per operation. The private heap core below
    // then works solely with live vector positions, keeping reordering safe.

    /// Call the C comparator for two entries currently owned by this queue.
    fn compare_items(&self, left: usize, right: usize) -> c_int {
        // SAFETY: the documented queue contract makes both data pointers and
        // the C callback valid for this synchronous comparison.
        let Some(compare) = self.compare else {
            // A null comparator is accepted by `prioq_new()` but cannot order
            // a queue containing multiple entries. `rs_prioq_put()` prevents
            // that state; treat corrupted state as an inert comparison instead
            // of panicking across the FFI boundary.
            return 0;
        };
        // SAFETY: the documented queue contract makes both data pointers and
        // the C callback valid for this synchronous comparison.
        unsafe { compare(self.items[left].data, self.items[right].data) }
    }

    /// Publish an entry's current heap index to its optional C-owned storage.
    fn publish_index(item: PrioqItem, index: usize) {
        if !item.index.is_null() {
            // SAFETY: guaranteed by the C priority-queue index-pointer contract.
            unsafe { *item.index = index as u32 };
        }
    }

    /// Mark an entry's optional C-owned heap-index storage invalid.
    fn invalidate_index(item: PrioqItem) {
        if !item.index.is_null() {
            // SAFETY: guaranteed by the C priority-queue index-pointer contract.
            unsafe { *item.index = PRIOQ_IDX_NULL };
        }
    }

    /// Swap two live heap entries and keep their externally supplied indices
    /// synchronized with the moved data pointers.
    fn swap_items(&mut self, left: usize, right: usize) {
        self.items.swap(left, right);
        Self::publish_index(self.items[left], left);
        Self::publish_index(self.items[right], right);
    }

    /// Restore the heap property towards the root and return the final index.
    fn shuffle_up(&mut self, mut index: usize) -> usize {
        while index > 0 {
            let parent = (index - 1) / 2;
            if self.compare_items(parent, index) <= 0 {
                break;
            }
            self.swap_items(index, parent);
            index = parent;
        }
        index
    }

    /// Restore the heap property towards the leaves and return the final index.
    fn shuffle_down(&mut self, mut index: usize) -> usize {
        loop {
            let left = index.saturating_mul(2).saturating_add(1);
            if left >= self.items.len() {
                break;
            }
            let right = left.saturating_add(1);
            let mut smallest = if self.compare_items(left, index) < 0 {
                left
            } else {
                index
            };
            if right < self.items.len() && self.compare_items(right, smallest) < 0 {
                smallest = right;
            }
            if smallest == index {
                break;
            }
            self.swap_items(index, smallest);
            index = smallest;
        }
        index
    }

    /// Locate C data by its optional tracked heap index.
    fn find_index(&self, data: *mut c_void, index: *mut u32) -> Option<usize> {
        if index.is_null() {
            return self.items.iter().position(|item| item.data == data);
        }
        // SAFETY: guaranteed by this helper's C index-pointer contract.
        let current = unsafe { *index };
        if current == PRIOQ_IDX_NULL {
            return None;
        }
        let position = current as usize;
        self.items
            .get(position)
            .filter(|item| item.data == data)
            .map(|_| position)
    }

    /// Remove a live entry, invalidate its external index, and repair the heap.
    fn remove_index(&mut self, index: usize) -> PrioqItem {
        let removed = self.items[index];
        Self::invalidate_index(removed);

        let last = self.items.len() - 1;
        if index == last {
            return self.items.pop().expect("live priority-queue entry");
        }

        let replacement = self.items.pop().expect("live priority-queue entry");
        self.items[index] = replacement;
        Self::publish_index(replacement, index);
        let index = self.shuffle_down(index);
        self.shuffle_up(index);
        removed
    }
}

/// C ABI facade for `prioq_new()`.
///
/// # Safety
/// If non-null, `compare` must be a valid C `compare_func_t` callback for all
/// subsequently inserted data pointers, must not unwind, and must not re-enter
/// or free the queue while it is being invoked.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_prioq_new(compare: PrioqCompareFn) -> *mut RsPrioq {
    // SAFETY: libc returns suitably aligned storage for this opaque C handle.
    // The allocation remains wholly owned by `rs_prioq_free` below.
    let queue = unsafe { libc::malloc(std::mem::size_of::<RsPrioq>()) }.cast::<RsPrioq>();
    if queue.is_null() {
        return std::ptr::null_mut();
    }
    // SAFETY: `queue` is a fresh, suitably aligned allocation large enough
    // for exactly one initialized RsPrioq.
    unsafe { std::ptr::write(queue, RsPrioq::new(compare)) };
    queue
}

/// C ABI facade for `prioq_free()`.
///
/// # Safety
/// `q` must be NULL or a unique pointer previously returned by
/// `rs_prioq_new()`. Every non-null tracked index pointer must remain writable
/// until this function invalidates it.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_prioq_free(q: *mut RsPrioq) -> *mut RsPrioq {
    if q.is_null() {
        return std::ptr::null_mut();
    }
    // SAFETY: the function contract establishes unique access to the live
    // allocation and writable external index storage for all entries.
    let queue = unsafe { &mut *q };
    for item in &queue.items {
        RsPrioq::invalidate_index(*item);
    }
    // SAFETY: q was initialized exactly once by rs_prioq_new and is no longer
    // observable through this exclusive C API call. Its Vec drops before the
    // enclosing libc allocation is released.
    unsafe {
        std::ptr::drop_in_place(q);
        libc::free(q.cast::<c_void>());
    }
    std::ptr::null_mut()
}

/// C ABI facade for `prioq_put()`.
///
/// # Safety
/// `q` must be a unique live queue from `rs_prioq_new()`. `data` remains
/// borrowed until removed, and non-null `index` must be writable `u32` storage
/// that remains live and is not aliased for this queue entry's lifetime.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_prioq_put(
    q: *mut RsPrioq,
    data: *mut c_void,
    index: *mut u32,
) -> c_int {
    if q.is_null() {
        return -EINVAL;
    }
    // SAFETY: `q` is a unique live queue for mutation by the public contract.
    let queue = unsafe { &mut *q };
    if queue.compare.is_none() && !queue.items.is_empty() {
        // C has no defined ordering behavior after using a null comparator for
        // multiple entries. Keep the successfully allocated empty/singleton
        // queue observable, but reject that undefined extension without
        // panicking or calling through a null function pointer.
        return -EINVAL;
    }
    if queue.items.len() >= u32::MAX as usize || queue.items.try_reserve(1).is_err() {
        return -ENOMEM;
    }
    let inserted = queue.items.len();
    queue.items.push(PrioqItem { data, index });
    RsPrioq::publish_index(queue.items[inserted], inserted);
    queue.shuffle_up(inserted);
    0
}

/// C ABI facade for `prioq_remove()`.
///
/// # Safety
/// `q` must be NULL or a live queue. A non-null `index` must be readable and,
/// if it identifies a live entry, writable `u32` storage associated with
/// `data` for that queue entry.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_prioq_remove(
    q: *mut RsPrioq,
    data: *mut c_void,
    index: *mut u32,
) -> c_int {
    if q.is_null() {
        return 0;
    }
    // SAFETY: the public contract establishes a live queue and valid index
    // storage whenever `index` is non-null.
    let queue = unsafe { &mut *q };
    let Some(position) = queue.find_index(data, index) else {
        return 0;
    };
    queue.remove_index(position);
    1
}

/// C ABI facade for `prioq_reshuffle()`.
///
/// # Safety
/// `q` must be a unique live queue. A non-null `index` must be readable and,
/// if it identifies a live entry, writable `u32` storage associated with
/// `data` for that queue entry.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_prioq_reshuffle(q: *mut RsPrioq, data: *mut c_void, index: *mut u32) {
    if q.is_null() {
        return;
    }
    // SAFETY: the public contract establishes a unique live queue and valid
    // index storage whenever `index` is non-null.
    let queue = unsafe { &mut *q };
    let Some(position) = queue.find_index(data, index) else {
        return;
    };
    let position = queue.shuffle_down(position);
    queue.shuffle_up(position);
}

/// C ABI facade for `prioq_peek_by_index()`.
///
/// # Safety
/// `q` must be NULL or a live queue pointer. Returned data is borrowed and
/// remains owned by its original C caller.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_prioq_peek_by_index(q: *mut RsPrioq, index: u32) -> *mut c_void {
    if q.is_null() {
        return std::ptr::null_mut();
    }
    // SAFETY: the public contract establishes a readable live queue. The
    // resulting borrow is used only to inspect its item slice.
    let items = unsafe { &(*q).items };
    items
        .get(index as usize)
        .map_or(std::ptr::null_mut(), |item| item.data)
}

/// C ABI facade for `prioq_pop()`.
///
/// # Safety
/// `q` must be NULL or a unique live queue. Any non-null tracked index pointer
/// for the removed item must remain writable while it is invalidated.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_prioq_pop(q: *mut RsPrioq) -> *mut c_void {
    if q.is_null() {
        return std::ptr::null_mut();
    }
    // SAFETY: the public contract establishes a unique live queue.
    let queue = unsafe { &mut *q };
    if queue.items.is_empty() {
        return std::ptr::null_mut();
    }
    queue.remove_index(0).data
}

/// C ABI facade for `prioq_size()`.
///
/// # Safety
/// `q` must be NULL or a readable live queue pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_prioq_size(q: *mut RsPrioq) -> u32 {
    if q.is_null() {
        return 0;
    }
    // SAFETY: the public contract establishes a readable live queue.
    unsafe { (*q).items.len() as u32 }
}

/// C ABI facade for `prioq_isempty()`.
///
/// # Safety
/// `q` must be NULL or a readable live queue pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_prioq_isempty(q: *mut RsPrioq) -> bool {
    if q.is_null() {
        return true;
    }
    // SAFETY: the public contract establishes a readable live queue.
    unsafe { (*q).items.is_empty() }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Comparators ────────────────────────────────────────────────────

    fn compare_u32(a: &u32, b: &u32) -> Ordering {
        a.cmp(b)
    }

    fn compare_reverse_u32(a: &u32, b: &u32) -> Ordering {
        b.cmp(a)
    }

    // ── Construction ───────────────────────────────────────────────────

    #[test]
    fn test_new_is_empty() {
        let q: Prioq<u32> = Prioq::new(compare_u32);
        assert_eq!(q.len(), 0);
        assert!(q.is_empty());
        assert!(q.peek().is_none());
    }

    #[test]
    fn test_new_with_different_comparator() {
        let q: Prioq<u32> = Prioq::new(compare_reverse_u32);
        assert_eq!(q.len(), 0);
        assert!(q.is_empty());
    }

    // ── Put / Pop ──────────────────────────────────────────────────────

    #[test]
    fn test_put_pop_single() {
        let mut q = Prioq::new(compare_u32);
        let idx = q.put(42u32);
        assert_eq!(idx, 0);
        assert_eq!(q.len(), 1);
        assert!(!q.is_empty());

        let val = q.pop().unwrap();
        assert_eq!(val, 42);
        assert!(q.is_empty());
    }

    #[test]
    fn test_put_pop_multiple_ordered() {
        let mut q = Prioq::new(compare_u32);
        for &v in &[5u32, 3, 1, 4, 2] {
            q.put(v);
        }
        assert_eq!(q.len(), 5);

        // Items should emerge in ascending order (min-heap)
        let mut prev = 0u32;
        for _ in 0..5 {
            let val = q.pop().unwrap();
            assert!(val >= prev, "got {} but expected >= {}", val, prev);
            prev = val;
        }
        assert!(q.is_empty());
    }

    #[test]
    fn test_put_pop_reverse_comparator() {
        let mut q = Prioq::new(compare_reverse_u32);
        for &v in &[5u32, 3, 1, 4, 2] {
            q.put(v);
        }

        // Reverse comparator → max-heap, items emerge in descending order
        let mut prev = u32::MAX;
        while let Some(val) = q.pop() {
            assert!(val <= prev, "got {} but expected <= {}", val, prev);
            prev = val;
        }
    }

    #[test]
    fn test_pop_empty_returns_none() {
        let mut q: Prioq<u32> = Prioq::new(compare_u32);
        assert!(q.pop().is_none());
    }

    // ── Full roundtrip ─────────────────────────────────────────────────

    #[test]
    fn test_full_roundtrip_0_to_9() {
        let mut q = Prioq::new(compare_u32);
        for &v in &[9u32, 7, 5, 3, 1, 0, 2, 4, 6, 8] {
            q.put(v);
        }
        assert_eq!(q.len(), 10);

        for expected in 0..10u32 {
            let val = q.pop().unwrap();
            assert_eq!(val, expected);
        }
        assert!(q.is_empty());
    }

    // ── Duplicates ─────────────────────────────────────────────────────

    #[test]
    fn test_duplicates() {
        let mut q = Prioq::new(compare_u32);
        q.put(5u32);
        q.put(5u32);
        q.put(5u32);
        assert_eq!(q.len(), 3);

        let mut count = 0;
        while let Some(val) = q.pop() {
            assert_eq!(val, 5);
            count += 1;
        }
        assert_eq!(count, 3);
    }

    // ── Peek ───────────────────────────────────────────────────────────

    #[test]
    fn test_peek_returns_min() {
        let mut q = Prioq::new(compare_u32);
        for &v in &[30u32, 10, 20] {
            q.put(v);
        }
        assert_eq!(*q.peek().unwrap(), 10);
    }

    #[test]
    fn test_peek_at() {
        let mut q = Prioq::new(compare_u32);
        for &v in &[30u32, 10, 20] {
            q.put(v);
        }
        // After heapification, index 0 is the minimum (10)
        assert_eq!(*q.peek_at(0).unwrap(), 10);
        // Out of range
        assert!(q.peek_at(99).is_none());
    }

    // ── Remove ─────────────────────────────────────────────────────────

    #[test]
    fn test_remove_at_valid() {
        let mut q = Prioq::new(compare_u32);
        for &v in &[40u32, 20, 30, 10] {
            q.put(v);
        }
        assert_eq!(q.len(), 4);

        let removed = q.remove_at(1);
        assert!(removed.is_some());
        assert_eq!(q.len(), 3);
    }

    #[test]
    fn test_remove_at_out_of_range() {
        let mut q = Prioq::new(compare_u32);
        q.put(42u32);
        assert!(q.remove_at(5).is_none());
        assert_eq!(q.len(), 1);
    }

    #[test]
    fn test_remove_where_found() {
        let mut q = Prioq::new(compare_u32);
        for &v in &[40u32, 20, 30, 10] {
            q.put(v);
        }

        let removed = q.remove_where(|v| *v == 20);
        assert_eq!(removed, Some(20));
        assert_eq!(q.len(), 3);
    }

    #[test]
    fn test_remove_where_not_found() {
        let mut q = Prioq::new(compare_u32);
        q.put(42u32);

        let removed = q.remove_where(|v| *v == 99);
        assert!(removed.is_none());
        assert_eq!(q.len(), 1);
    }

    // ── Reshuffle ──────────────────────────────────────────────────────

    #[test]
    fn test_reshuffle_at_after_mutation() {
        let mut q = Prioq::new(compare_u32);
        for &v in &[30u32, 10, 20] {
            q.put(v);
        }

        // Mutate the item at index 0 (currently the minimum) to a large value
        if let Some(item) = q.get_mut(0) {
            *item = 100;
        }
        q.reshuffle_at(0);

        // After reshuffle, the new minimum should be different from 100
        let min = q.peek().unwrap();
        assert_ne!(*min, 100);
        assert!(q.pop().unwrap() < 100);
    }

    #[test]
    fn test_reshuffle_at_out_of_range() {
        let mut q = Prioq::new(compare_u32);
        q.put(42u32);
        // Should not panic
        q.reshuffle_at(99);
        assert_eq!(q.len(), 1);
    }

    // ── Single element edge case ───────────────────────────────────────

    #[test]
    fn test_single_element() {
        let mut q = Prioq::new(compare_u32);
        q.put(100u32);
        assert_eq!(q.len(), 1);
        assert!(!q.is_empty());
        assert_eq!(*q.peek_at(0).unwrap(), 100);

        let popped = q.pop().unwrap();
        assert_eq!(popped, 100);
        assert!(q.is_empty());
    }

    // ── Remove the only element ────────────────────────────────────────

    #[test]
    fn test_remove_only_element() {
        let mut q = Prioq::new(compare_u32);
        q.put(77u32);
        let removed = q.remove_at(0);
        assert_eq!(removed, Some(77));
        assert!(q.is_empty());
    }
}
