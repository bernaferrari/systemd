// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/basic/prioq.c, src/basic/prioq.h
//
// Priority queue (min-heap) with custom comparator support.

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
        self.shuffle_up(idx);
        idx as u32
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
