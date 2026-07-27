// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/libsystemd/sd-journal/test-journal-interleaving.c

use std::collections::{BTreeMap, BTreeSet};

const NEG_EINVAL: i32 = -(libc::EINVAL as i32);

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct SdId128 {
    pub bytes: [u8; 16],
}

impl SdId128 {
    pub fn from_byte(value: u8) -> Self {
        Self { bytes: [value; 16] }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JournalEntry {
    pub seqnum: u64,
    pub boot_id: SdId128,
    pub realtime: u64,
    pub monotonic: u64,
    pub number: u32,
    pub fields: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MockJournal {
    entries: Vec<JournalEntry>,
    matches: Vec<(String, String)>,
    position: Option<usize>,
}

impl MockJournal {
    pub fn new(mut entries: Vec<JournalEntry>) -> Self {
        entries.sort_by_key(|e| (e.realtime, e.monotonic, e.seqnum));
        Self {
            entries,
            matches: Vec::new(),
            position: None,
        }
    }

    pub fn add_match(&mut self, filter: &str) -> Result<(), i32> {
        let (k, v) = filter.split_once('=').ok_or(NEG_EINVAL)?;
        self.matches.push((k.to_string(), v.to_string()));
        self.position = None;
        Ok(())
    }

    pub fn flush_matches(&mut self) {
        self.matches.clear();
        self.position = None;
    }

    fn filtered_indexes(&self) -> Vec<usize> {
        self.entries
            .iter()
            .enumerate()
            .filter(|(_, entry)| {
                self.matches
                    .iter()
                    .all(|(k, v)| entry.fields.get(k) == Some(v))
            })
            .map(|(idx, _)| idx)
            .collect()
    }

    pub fn seek_head(&mut self) {
        self.position = None;
    }

    pub fn seek_tail(&mut self) {
        self.position = None;
    }

    pub fn next(&mut self) -> Result<bool, i32> {
        let indexes = self.filtered_indexes();
        let start = self.position.map(|i| i + 1).unwrap_or(0);
        for idx in indexes {
            if idx >= start {
                self.position = Some(idx);
                return Ok(true);
            }
        }
        self.position = None;
        Ok(false)
    }

    pub fn previous(&mut self) -> Result<bool, i32> {
        let indexes = self.filtered_indexes();
        let start = self.position.unwrap_or(self.entries.len());
        for idx in indexes.into_iter().rev() {
            if idx < start {
                self.position = Some(idx);
                return Ok(true);
            }
        }
        self.position = None;
        Ok(false)
    }

    pub fn next_skip(&mut self, count: usize) -> Result<usize, i32> {
        let mut moved = 0;
        for _ in 0..count {
            if !self.next()? {
                break;
            }
            moved += 1;
        }
        Ok(moved)
    }

    pub fn previous_skip(&mut self, count: usize) -> Result<usize, i32> {
        let mut moved = 0;
        for _ in 0..count {
            if !self.previous()? {
                break;
            }
            moved += 1;
        }
        Ok(moved)
    }

    pub fn current(&self) -> Result<&JournalEntry, i32> {
        self.position
            .and_then(|idx| self.entries.get(idx))
            .ok_or(NEG_EINVAL)
    }

    pub fn get_cursor(&self) -> Result<String, i32> {
        let entry = self.current()?;
        Ok(format!("s={};n={}", entry.seqnum, entry.number))
    }

    pub fn test_cursor(&self, cursor: &str) -> Result<bool, i32> {
        Ok(self.get_cursor()? == cursor)
    }

    pub fn seek_cursor(&mut self, cursor: &str) -> Result<(), i32> {
        let Some((_, seq)) = cursor.split_once("s=") else {
            return Err(NEG_EINVAL);
        };
        let Some((seq, number)) = seq.split_once(";n=") else {
            return Err(NEG_EINVAL);
        };
        let seqnum = seq.parse::<u64>().map_err(|_| NEG_EINVAL)?;
        let number = number.parse::<u32>().map_err(|_| NEG_EINVAL)?;
        self.position = self
            .entries
            .iter()
            .position(|e| e.seqnum == seqnum && e.number == number);
        self.position.ok_or(NEG_EINVAL).map(|_| ())
    }

    pub fn boots(&self) -> Result<Vec<SdId128>, i32> {
        let mut seen = BTreeSet::new();
        let mut boots = Vec::new();
        for entry in &self.entries {
            if seen.insert(entry.boot_id) {
                boots.push(entry.boot_id);
            }
        }
        Ok(boots)
    }

    pub fn seek_monotonic_usec(
        &mut self,
        boot_id: SdId128,
        usec: u64,
        next: bool,
    ) -> Result<bool, i32> {
        let indexes = self.filtered_indexes();
        let found = if next {
            indexes.into_iter().find(|&i| {
                let e = &self.entries[i];
                e.boot_id == boot_id && e.monotonic >= usec
            })
        } else {
            indexes.into_iter().rev().find(|&i| {
                let e = &self.entries[i];
                e.boot_id == boot_id && e.monotonic <= usec
            })
        };
        self.position = found;
        Ok(found.is_some())
    }

    pub fn seek_realtime_usec(&mut self, usec: u64, next: bool) -> Result<bool, i32> {
        let indexes = self.filtered_indexes();
        let found = if next {
            let mut found = None;
            for idx in indexes {
                if self.entries[idx].realtime >= usec {
                    found = Some(idx);
                    break;
                }
            }
            found
        } else {
            let mut found = None;
            for idx in indexes.into_iter().rev() {
                if self.entries[idx].realtime <= usec {
                    found = Some(idx);
                    break;
                }
            }
            found
        };
        self.position = found;
        Ok(found.is_some())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(
        seq: u64,
        boot: u8,
        realtime: u64,
        monotonic: u64,
        number: u32,
        data: &str,
    ) -> JournalEntry {
        JournalEntry {
            seqnum: seq,
            boot_id: SdId128::from_byte(boot),
            realtime,
            monotonic,
            number,
            fields: BTreeMap::from([
                ("NUMBER".into(), number.to_string()),
                ("DATA".into(), data.into()),
            ]),
        }
    }

    fn journal() -> MockJournal {
        MockJournal::new(vec![
            entry(1, 1, 10, 100, 1, "100"),
            entry(2, 1, 20, 110, 2, "100"),
            entry(3, 1, 30, 120, 3, "200"),
            entry(4, 2, 40, 10, 4, "200"),
            entry(5, 2, 50, 20, 5, "100"),
        ])
    }

    #[test]
    fn next_walks_in_realtime_order() {
        let mut j = journal();
        assert!(j.next().unwrap());
        assert_eq!(j.current().unwrap().number, 1);
    }

    #[test]
    fn previous_walks_from_tail() {
        let mut j = journal();
        assert!(j.previous().unwrap());
        assert_eq!(j.current().unwrap().number, 5);
    }

    #[test]
    fn next_skip_skips_multiple_entries() {
        let mut j = journal();
        assert_eq!(j.next_skip(3).unwrap(), 3);
        assert_eq!(j.current().unwrap().number, 3);
    }

    #[test]
    fn previous_skip_skips_multiple_entries() {
        let mut j = journal();
        assert_eq!(j.previous_skip(2).unwrap(), 2);
        assert_eq!(j.current().unwrap().number, 4);
    }

    #[test]
    fn cursor_roundtrip_works() {
        let mut j = journal();
        j.next_skip(2).unwrap();
        let cursor = j.get_cursor().unwrap();
        let mut k = journal();
        k.seek_cursor(&cursor).unwrap();
        assert!(k.test_cursor(&cursor).unwrap());
    }

    #[test]
    fn seek_monotonic_is_boot_specific() {
        let mut j = journal();
        assert!(j
            .seek_monotonic_usec(SdId128::from_byte(2), 15, true)
            .unwrap());
        assert_eq!(j.current().unwrap().number, 5);
    }

    #[test]
    fn seek_realtime_can_search_backwards() {
        let mut j = journal();
        assert!(j.seek_realtime_usec(35, false).unwrap());
        assert_eq!(j.current().unwrap().number, 3);
    }

    #[test]
    fn boots_are_listed_once_each() {
        assert_eq!(
            journal().boots().unwrap(),
            vec![SdId128::from_byte(1), SdId128::from_byte(2)]
        );
    }

    #[test]
    fn matches_filter_results() {
        let mut j = journal();
        j.add_match("DATA=200").unwrap();
        assert!(j.next().unwrap());
        assert_eq!(j.current().unwrap().number, 3);
        assert!(j.next().unwrap());
        assert_eq!(j.current().unwrap().number, 4);
    }
}
