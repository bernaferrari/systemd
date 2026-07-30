// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/libsystemd/sd-journal/test-journal-enum.c

use std::collections::BTreeMap;

const NEG_EINVAL: i32 = -libc::EINVAL;
pub const SD_JOURNAL_LOCAL_ONLY: i32 = 1;
pub const SD_JOURNAL_ASSUME_IMMUTABLE: i32 = 2;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JournalEntry {
    pub fields: BTreeMap<String, Vec<u8>>,
}

#[derive(Clone, Debug, Default)]
pub struct MockJournal {
    entries: Vec<JournalEntry>,
    matches: Vec<String>,
    cursor: Option<usize>,
}

impl MockJournal {
    pub fn open(flags: i32, entries: Vec<JournalEntry>) -> Result<Self, i32> {
        let valid = SD_JOURNAL_LOCAL_ONLY | SD_JOURNAL_ASSUME_IMMUTABLE;
        if flags & !valid != 0 {
            return Err(NEG_EINVAL);
        }
        Ok(Self {
            entries,
            matches: Vec::new(),
            cursor: None,
        })
    }

    pub fn add_match(&mut self, filter: &str) -> Result<(), i32> {
        if !filter.contains('=') {
            return Err(NEG_EINVAL);
        }
        self.matches.push(filter.to_string());
        Ok(())
    }

    fn matches_entry(&self, entry: &JournalEntry) -> bool {
        self.matches.iter().all(|filter| {
            let (key, expected) = filter.split_once('=').unwrap();
            entry.fields.get(key).map(|v| v.as_slice()) == Some(expected.as_bytes())
        })
    }

    pub fn previous(&mut self) -> Result<bool, i32> {
        let start = self.cursor.unwrap_or(self.entries.len());
        for idx in (0..start).rev() {
            if self.matches_entry(&self.entries[idx]) {
                self.cursor = Some(idx);
                return Ok(true);
            }
        }
        self.cursor = None;
        Ok(false)
    }

    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> Result<bool, i32> {
        let start = self.cursor.map(|i| i + 1).unwrap_or(0);
        for idx in start..self.entries.len() {
            if self.matches_entry(&self.entries[idx]) {
                self.cursor = Some(idx);
                return Ok(true);
            }
        }
        self.cursor = None;
        Ok(false)
    }

    pub fn get_data(&self, field: &str) -> Result<&[u8], i32> {
        let idx = self.cursor.ok_or(NEG_EINVAL)?;
        self.entries[idx]
            .fields
            .get(field)
            .map(|v| v.as_slice())
            .ok_or(NEG_EINVAL)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(transport: &str, uid: &str, message: &str) -> JournalEntry {
        JournalEntry {
            fields: BTreeMap::from([
                ("_TRANSPORT".into(), transport.as_bytes().to_vec()),
                ("_UID".into(), uid.as_bytes().to_vec()),
                ("MESSAGE".into(), message.as_bytes().to_vec()),
            ]),
        }
    }

    fn journal() -> MockJournal {
        MockJournal::open(
            SD_JOURNAL_LOCAL_ONLY | SD_JOURNAL_ASSUME_IMMUTABLE,
            vec![
                entry("kernel", "0", "kernel msg"),
                entry("syslog", "1000", "user msg"),
                entry("syslog", "0", "root msg"),
                entry("syslog", "0", "root msg 2"),
            ],
        )
        .unwrap()
    }

    #[test]
    fn invalid_open_flags_are_rejected() {
        assert!(MockJournal::open(8, vec![]).is_err());
    }

    #[test]
    fn invalid_match_is_rejected() {
        assert_eq!(journal().add_match("BROKEN"), Err(NEG_EINVAL));
    }

    #[test]
    fn backwards_iteration_finds_last_matching_entry() {
        let mut j = journal();
        j.add_match("_TRANSPORT=syslog").unwrap();
        j.add_match("_UID=0").unwrap();
        assert!(j.previous().unwrap());
        assert_eq!(j.get_data("MESSAGE").unwrap(), b"root msg 2");
    }

    #[test]
    fn backwards_iteration_then_steps_again() {
        let mut j = journal();
        j.add_match("_TRANSPORT=syslog").unwrap();
        j.add_match("_UID=0").unwrap();
        assert!(j.previous().unwrap());
        assert!(j.previous().unwrap());
        assert_eq!(j.get_data("MESSAGE").unwrap(), b"root msg");
    }

    #[test]
    fn forward_iteration_respects_matches() {
        let mut j = journal();
        j.add_match("_TRANSPORT=syslog").unwrap();
        assert!(j.next().unwrap());
        assert_eq!(j.get_data("MESSAGE").unwrap(), b"user msg");
    }

    #[test]
    fn get_data_requires_position() {
        assert_eq!(journal().get_data("MESSAGE"), Err(NEG_EINVAL));
    }

    #[test]
    fn missing_field_is_an_error() {
        let mut j = journal();
        assert!(j.next().unwrap());
        assert_eq!(j.get_data("NOPE"), Err(NEG_EINVAL));
    }

    #[test]
    fn no_matching_entries_returns_false() {
        let mut j = journal();
        j.add_match("_UID=7").unwrap();
        assert!(!j.previous().unwrap());
    }
}
