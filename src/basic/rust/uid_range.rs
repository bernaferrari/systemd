// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/basic/uid-range.c

use crate::ffi::Errno;

pub const UID_INVALID: u32 = u32::MAX;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UIDRangeEntry {
    pub start: u32,
    pub nr: u32,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UIDRange {
    entries: Vec<UIDRangeEntry>,
}

fn parse_u32_component(text: &str) -> Result<u32, i32> {
    text.parse::<u32>()
        .map_err(|_| Errno::EINVAL.to_neg_errno())
}

fn parse_uid_range(s: &str) -> Result<(u32, u32), i32> {
    let s = s.trim();
    if s.is_empty() {
        return Err(Errno::EINVAL.to_neg_errno());
    }

    if let Some((a, b)) = s.split_once('-') {
        let start = parse_u32_component(a.trim())?;
        let end = parse_u32_component(b.trim())?;
        if end < start {
            return Err(Errno::EINVAL.to_neg_errno());
        }
        Ok((start, end))
    } else {
        let uid = parse_u32_component(s)?;
        Ok((uid, uid))
    }
}

fn entry_intersects(a: UIDRangeEntry, b: UIDRangeEntry) -> bool {
    a.start <= b.start.saturating_add(b.nr) && a.start.saturating_add(a.nr) >= b.start
}

impl UIDRange {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn entries(&self) -> &[UIDRangeEntry] {
        &self.entries
    }

    pub fn n_entries(&self) -> usize {
        self.entries.len()
    }

    pub fn get_entry(&self, index: usize) -> Option<UIDRangeEntry> {
        self.entries.get(index).copied()
    }

    pub fn add_internal(&mut self, start: u32, nr: u32, coalesce: bool) -> Result<(), i32> {
        if nr == 0 {
            return Ok(());
        }

        if start > u32::MAX - nr {
            return Err(Errno::ERANGE.to_neg_errno());
        }

        self.entries.push(UIDRangeEntry { start, nr });

        if coalesce {
            self.coalesce();
        }

        Ok(())
    }

    pub fn add_str_full(&mut self, s: &str, coalesce: bool) -> Result<(), i32> {
        let (start, end) = parse_uid_range(s)?;
        self.add_internal(start, end - start + 1, coalesce)
    }

    pub fn next_lower(&self, uid: u32) -> Result<u32, i32> {
        if uid == 0 {
            return Err(-libc::EBUSY);
        }

        let candidate = uid - 1;
        let mut closest = UID_INVALID;

        for entry in &self.entries {
            if entry.nr == 0 {
                continue;
            }

            let begin = entry.start;
            let end = entry.start + entry.nr - 1;

            if candidate >= begin && candidate <= end {
                return Ok(candidate);
            }

            if end < candidate {
                closest = end;
            }
        }

        if closest == UID_INVALID {
            Err(-libc::EBUSY)
        } else {
            Ok(closest)
        }
    }

    pub fn covers(&self, start: u32, nr: u32) -> bool {
        if nr == 0 {
            return true;
        }

        if start > u32::MAX - nr {
            return false;
        }

        self.entries
            .iter()
            .any(|entry| start >= entry.start && start + nr <= entry.start.saturating_add(entry.nr))
    }

    pub fn contains(&self, uid: u32) -> bool {
        self.covers(uid, 1)
    }

    pub fn overlaps(&self, start: u32, nr: u32) -> bool {
        let nr = if start > u32::MAX - nr {
            u32::MAX - start
        } else {
            nr
        };

        if nr == 0 {
            return false;
        }

        let end = start + nr;
        self.entries
            .iter()
            .any(|entry| start < entry.start.saturating_add(entry.nr) && end >= entry.start)
    }

    pub fn size(&self) -> u32 {
        self.entries
            .iter()
            .fold(0u32, |acc, entry| acc.wrapping_add(entry.nr))
    }

    pub fn is_empty(&self) -> bool {
        self.entries.iter().all(|entry| entry.nr == 0)
    }

    pub fn base(&self) -> u32 {
        self.entries
            .iter()
            .find(|entry| entry.nr > 0)
            .map(|entry| entry.start)
            .unwrap_or(UID_INVALID)
    }

    fn coalesce(&mut self) {
        if self.entries.is_empty() {
            return;
        }

        self.entries.sort_by_key(|entry| (entry.start, entry.nr));

        let mut merged: Vec<UIDRangeEntry> = Vec::with_capacity(self.entries.len());
        for entry in self.entries.iter().copied() {
            match merged.last_mut() {
                Some(current) if entry_intersects(*current, entry) => {
                    let begin = current.start.min(entry.start);
                    let end = current
                        .start
                        .saturating_add(current.nr)
                        .max(entry.start.saturating_add(entry.nr));
                    current.start = begin;
                    current.nr = end - begin;
                }
                _ => merged.push(entry),
            }
        }

        self.entries = merged;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_zero_range_is_noop() {
        let mut range = UIDRange::new();
        range.add_internal(100, 0, false).unwrap();
        assert!(range.entries().is_empty());
    }

    #[test]
    fn add_rejects_overflow() {
        let mut range = UIDRange::new();
        assert_eq!(
            range.add_internal(u32::MAX, 1, false),
            Err(Errno::ERANGE.to_neg_errno())
        );
    }

    #[test]
    fn add_str_single_uid() {
        let mut range = UIDRange::new();
        range.add_str_full("42", false).unwrap();
        assert_eq!(range.get_entry(0), Some(UIDRangeEntry { start: 42, nr: 1 }));
    }

    #[test]
    fn add_str_interval() {
        let mut range = UIDRange::new();
        range.add_str_full("10-12", false).unwrap();
        assert_eq!(range.get_entry(0), Some(UIDRangeEntry { start: 10, nr: 3 }));
    }

    #[test]
    fn coalesce_merges_overlapping_and_adjacent_ranges() {
        let mut range = UIDRange::new();
        range.add_internal(20, 3, false).unwrap();
        range.add_internal(10, 5, false).unwrap();
        range.add_internal(15, 5, true).unwrap();
        assert_eq!(range.entries(), &[UIDRangeEntry { start: 10, nr: 13 }]);
    }

    #[test]
    fn covers_and_contains_match_c_logic() {
        let mut range = UIDRange::new();
        range.add_internal(100, 10, true).unwrap();
        assert!(range.covers(100, 10));
        assert!(range.covers(103, 4));
        assert!(range.contains(109));
        assert!(!range.covers(95, 20));
        assert!(!range.contains(110));
    }

    #[test]
    fn overlaps_clamps_overflowing_query() {
        let mut range = UIDRange::new();
        range.add_internal(u32::MAX - 4, 4, true).unwrap();
        assert!(range.overlaps(u32::MAX - 5, 10));
    }

    #[test]
    fn next_lower_returns_previous_uid_inside_same_entry() {
        let mut range = UIDRange::new();
        range.add_internal(100, 10, true).unwrap();
        assert_eq!(range.next_lower(105), Ok(104));
    }

    #[test]
    fn next_lower_returns_closest_lower_entry_end() {
        let mut range = UIDRange::new();
        range.add_internal(10, 3, false).unwrap();
        range.add_internal(30, 5, false).unwrap();
        assert_eq!(range.next_lower(25), Ok(12));
    }

    #[test]
    fn next_lower_fails_at_zero() {
        let range = UIDRange::new();
        assert_eq!(range.next_lower(0), Err(-libc::EBUSY));
    }

    #[test]
    fn size_is_wrapping_sum_like_c() {
        let mut range = UIDRange::new();
        range.add_internal(0, u32::MAX, false).unwrap();
        range.add_internal(0, 10, false).unwrap();
        assert_eq!(range.size(), 9);
    }

    #[test]
    fn base_returns_first_non_empty_entry() {
        let mut range = UIDRange::new();
        range.add_internal(500, 0, false).unwrap();
        range.add_internal(123, 4, false).unwrap();
        assert_eq!(range.base(), 123);
    }
}
