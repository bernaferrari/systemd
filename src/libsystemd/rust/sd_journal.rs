// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/libsystemd/sd-journal/sd-journal.c
//
use std::collections::{BTreeMap, BTreeSet, HashMap};

use crate::id128_util::SdId128;

pub type Result<T> = std::result::Result<T, i32>;

pub const NEG_EBADF: i32 = -(libc::EBADF as i32);
pub const NEG_EINVAL: i32 = -(libc::EINVAL as i32);
pub const NEG_ENODATA: i32 = -(libc::ENODATA as i32);
pub const NEG_ENOENT: i32 = -(libc::ENOENT as i32);

const DEFAULT_DATA_THRESHOLD: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JournalEntry {
    pub cursor: String,
    pub realtime_usec: u64,
    pub monotonic_usec: u64,
    pub boot_id: SdId128,
    pub seqnum: u64,
    pub fields: BTreeMap<String, Vec<u8>>,
    pub catalog: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JournalDirectorySource {
    pub path: String,
    pub persistent: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SdJournal {
    entries: Vec<JournalEntry>,
    current: Option<usize>,
    data_threshold: usize,
    data_enumeration: usize,
    unique_field: Option<String>,
    unique_values: Vec<Vec<u8>>,
    unique_enumeration: usize,
    match_groups: Vec<Vec<Vec<u8>>>,
    directories: Vec<JournalDirectorySource>,
    files: Vec<String>,
    flags: i32,
    fd: i32,
    catalogs: HashMap<SdId128, String>,
}

impl SdJournal {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            current: None,
            data_threshold: DEFAULT_DATA_THRESHOLD,
            data_enumeration: 0,
            unique_field: None,
            unique_values: Vec::new(),
            unique_enumeration: 0,
            match_groups: vec![Vec::new()],
            directories: Vec::new(),
            files: Vec::new(),
            flags: 0,
            fd: 3,
            catalogs: HashMap::new(),
        }
    }

    pub fn open(flags: i32) -> Result<Self> {
        if flags < 0 {
            return Err(NEG_EINVAL);
        }
        let mut journal = Self::new();
        journal.flags = flags;
        Ok(journal)
    }

    pub fn open_directory(path: &str, flags: i32) -> Result<Self> {
        if path.is_empty() || flags < 0 {
            return Err(NEG_EINVAL);
        }
        let mut journal = Self::open(flags)?;
        journal.directories.push(JournalDirectorySource {
            path: path.to_string(),
            persistent: !path.contains("/run/"),
        });
        Ok(journal)
    }

    pub fn open_files(paths: &[&str], flags: i32) -> Result<Self> {
        if paths.is_empty() || paths.iter().any(|path| path.is_empty()) || flags < 0 {
            return Err(NEG_EINVAL);
        }
        let mut journal = Self::open(flags)?;
        journal.files = paths.iter().map(|path| (*path).to_string()).collect();
        Ok(journal)
    }

    pub fn open_containers() -> Result<Self> {
        Ok(Self::new())
    }

    pub fn with_entries(mut self, entries: Vec<JournalEntry>) -> Self {
        self.entries = entries;
        self
    }

    pub fn insert_catalog(&mut self, id: SdId128, text: &str) {
        self.catalogs.insert(id, text.to_string());
    }

    pub fn close(self) {}

    pub fn ref_clone(&self) -> Self {
        self.clone()
    }

    pub fn foreach<F>(&mut self, mut callback: F) -> Result<()>
    where
        F: FnMut(&JournalEntry) -> Result<()>,
    {
        self.seek_head()?;
        while self.next()? > 0 {
            callback(self.current_entry()?)?;
        }
        Ok(())
    }

    pub fn seek_head(&mut self) -> Result<()> {
        self.current = None;
        self.data_enumeration = 0;
        Ok(())
    }

    pub fn seek_tail(&mut self) -> Result<()> {
        self.current = if self.entries.is_empty() {
            None
        } else {
            Some(self.entries.len())
        };
        self.data_enumeration = 0;
        Ok(())
    }

    pub fn seek_monotonic_usec(&mut self, boot_id: SdId128, usec: u64) -> Result<()> {
        self.current = self
            .entries
            .iter()
            .position(|entry| entry.boot_id == boot_id && entry.monotonic_usec >= usec);
        self.data_enumeration = 0;
        Ok(())
    }

    pub fn seek_realtime_usec(&mut self, usec: u64) -> Result<()> {
        self.current = self
            .entries
            .iter()
            .position(|entry| entry.realtime_usec >= usec);
        self.data_enumeration = 0;
        Ok(())
    }

    pub fn seek_cursor(&mut self, cursor: &str) -> Result<()> {
        if cursor.is_empty() {
            return Err(NEG_EINVAL);
        }
        self.current = self.entries.iter().position(|entry| entry.cursor == cursor);
        if self.current.is_none() {
            return Err(NEG_ENOENT);
        }
        self.data_enumeration = 0;
        Ok(())
    }

    pub fn next(&mut self) -> Result<i32> {
        let start = self.current.map(|index| index + 1).unwrap_or(0);
        for index in start..self.entries.len() {
            if self.entry_matches(&self.entries[index]) {
                self.current = Some(index);
                self.data_enumeration = 0;
                return Ok(1);
            }
        }
        self.current = None;
        Ok(0)
    }

    pub fn previous(&mut self) -> Result<i32> {
        let start = self.current.unwrap_or(self.entries.len());
        for index in (0..start).rev() {
            if self.entry_matches(&self.entries[index]) {
                self.current = Some(index);
                self.data_enumeration = 0;
                return Ok(1);
            }
        }
        self.current = None;
        Ok(0)
    }

    pub fn get_cursor(&self) -> Result<String> {
        Ok(self.current_entry()?.cursor.clone())
    }

    pub fn get_cursor_realtime_usec(&self) -> Result<(u64, u64)> {
        let entry = self.current_entry()?;
        Ok((entry.realtime_usec, entry.monotonic_usec))
    }

    pub fn test_cursor(&self, cursor: &str) -> Result<bool> {
        Ok(self.current_entry()?.cursor == cursor)
    }

    pub fn get_realtime_usec(&self) -> Result<u64> {
        Ok(self.current_entry()?.realtime_usec)
    }

    pub fn get_monotonic_usec(&self) -> Result<(u64, SdId128)> {
        let entry = self.current_entry()?;
        Ok((entry.monotonic_usec, entry.boot_id))
    }

    pub fn get_data(&self, field: &str) -> Result<Vec<u8>> {
        let entry = self.current_entry()?;
        let data = entry.fields.get(field).ok_or(NEG_ENODATA)?;
        Ok(data.iter().copied().take(self.data_threshold).collect())
    }

    pub fn get_data_threshold(&self) -> usize {
        self.data_threshold
    }

    pub fn set_data_threshold(&mut self, threshold: usize) -> Result<()> {
        self.data_threshold = threshold;
        Ok(())
    }

    pub fn enumerate_data(&mut self) -> Result<Option<Vec<u8>>> {
        let entry = self.current_entry()?;
        let item = entry.fields.values().nth(self.data_enumeration).cloned();
        self.data_enumeration = self.data_enumeration.saturating_add(1);
        Ok(item.map(|bytes| bytes.into_iter().take(self.data_threshold).collect()))
    }

    pub fn restart_data(&mut self) -> Result<()> {
        self.data_enumeration = 0;
        Ok(())
    }

    pub fn add_match(&mut self, field: &[u8]) -> Result<()> {
        if !match_is_valid(field) {
            return Err(NEG_EINVAL);
        }
        if self.match_groups.is_empty() {
            self.match_groups.push(Vec::new());
        }
        self.match_groups.last_mut().unwrap().push(field.to_vec());
        Ok(())
    }

    pub fn add_disjunction(&mut self) -> Result<()> {
        if self.match_groups.last().is_some_and(Vec::is_empty) {
            return Err(NEG_EINVAL);
        }
        self.match_groups.push(Vec::new());
        Ok(())
    }

    pub fn add_conjunction(&mut self) -> Result<()> {
        if self.match_groups.is_empty() {
            self.match_groups.push(Vec::new());
        }
        Ok(())
    }

    pub fn flush_matches(&mut self) {
        self.match_groups = vec![Vec::new()];
    }

    pub fn get_usage(&self) -> Result<u64> {
        Ok(self
            .entries
            .iter()
            .map(|entry| entry.fields.values().map(Vec::len).sum::<usize>() as u64)
            .sum())
    }

    pub fn get_cutoff_realtime_usec(&self) -> Result<(u64, u64)> {
        cutoff(self.entries.iter().map(|entry| entry.realtime_usec))
    }

    pub fn get_cutoff_monotonic_usec(&self) -> Result<(SdId128, u64, u64)> {
        let first = self.entries.first().ok_or(NEG_ENODATA)?;
        let boot_id = first.boot_id;
        let values = self
            .entries
            .iter()
            .filter(|entry| entry.boot_id == boot_id)
            .map(|entry| entry.monotonic_usec);
        let (from, to) = cutoff(values)?;
        Ok((boot_id, from, to))
    }

    pub fn get_fd(&self) -> Result<i32> {
        if self.fd < 0 {
            return Err(NEG_EBADF);
        }
        Ok(self.fd)
    }

    pub fn get_events(&self) -> libc::c_short {
        libc::POLLIN
    }

    pub fn get_timeout(&self) -> Result<u64> {
        Ok(u64::MAX)
    }

    pub fn process(&mut self) -> Result<i32> {
        Ok(if self.entries.is_empty() { 0 } else { 1 })
    }

    pub fn wait(&mut self, _timeout_usec: u64) -> Result<i32> {
        self.process()
    }

    pub fn get_catalog(&self) -> Result<String> {
        self.current_entry()?.catalog.clone().ok_or(NEG_ENODATA)
    }

    pub fn get_catalog_for_message_id(&self, id: SdId128) -> Result<String> {
        self.catalogs.get(&id).cloned().ok_or(NEG_ENODATA)
    }

    pub fn query_unique(&mut self, field: &str) -> Result<()> {
        if field.is_empty() {
            return Err(NEG_EINVAL);
        }
        self.unique_field = Some(field.to_string());
        self.unique_values = self
            .entries
            .iter()
            .filter_map(|entry| entry.fields.get(field).cloned())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        self.unique_enumeration = 0;
        Ok(())
    }

    pub fn enumerate_unique(&mut self) -> Result<Option<Vec<u8>>> {
        let item = self.unique_values.get(self.unique_enumeration).cloned();
        self.unique_enumeration = self.unique_enumeration.saturating_add(1);
        Ok(item)
    }

    pub fn restart_unique(&mut self) -> Result<()> {
        self.unique_enumeration = 0;
        Ok(())
    }

    pub fn get_seqnum(&self) -> Result<u64> {
        Ok(self.current_entry()?.seqnum)
    }

    pub fn seek_seqnum(&mut self, seqnum: u64) -> Result<()> {
        self.current = self.entries.iter().position(|entry| entry.seqnum >= seqnum);
        self.data_enumeration = 0;
        if self.current.is_none() {
            return Err(NEG_ENOENT);
        }
        Ok(())
    }

    pub fn get_field(&self, field: &str) -> Result<(String, usize)> {
        let data = self.get_data(field)?;
        let length = data.len();
        Ok((String::from_utf8_lossy(&data).into_owned(), length))
    }

    pub fn has_runtime_files(&self) -> bool {
        self.directories
            .iter()
            .any(|directory| !directory.persistent)
            || self.files.iter().any(|path| path.contains("/run/"))
    }

    pub fn has_persistent_files(&self) -> bool {
        self.directories
            .iter()
            .any(|directory| directory.persistent)
            || self.files.iter().any(|path| !path.contains("/run/"))
    }

    fn current_entry(&self) -> Result<&JournalEntry> {
        self.current
            .and_then(|index| self.entries.get(index))
            .ok_or(NEG_ENODATA)
    }

    fn entry_matches(&self, entry: &JournalEntry) -> bool {
        self.match_groups
            .iter()
            .filter(|group| !group.is_empty())
            .next()
            .is_none()
            || self
                .match_groups
                .iter()
                .any(|group| group.iter().all(|term| match_term(entry, term)))
    }
}

fn cutoff<I>(values: I) -> Result<(u64, u64)>
where
    I: Iterator<Item = u64>,
{
    let collected: Vec<_> = values.collect();
    let Some(first) = collected.first() else {
        return Err(NEG_ENODATA);
    };
    let last = collected.last().copied().unwrap_or(*first);
    Ok((*first, last))
}

fn match_is_valid(data: &[u8]) -> bool {
    let Some(position) = data.iter().position(|byte| *byte == b'=') else {
        return false;
    };
    position > 0
        && !data.starts_with(b"__")
        && data[..position]
            .iter()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || *byte == b'_')
}

fn match_term(entry: &JournalEntry, term: &[u8]) -> bool {
    let Some(position) = term.iter().position(|byte| *byte == b'=') else {
        return false;
    };
    let field = String::from_utf8_lossy(&term[..position]);
    entry
        .fields
        .get(field.as_ref())
        .is_some_and(|value| value == &term.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(seqnum: u64, cursor: &str, message: &str, priority: &str) -> JournalEntry {
        let mut fields = BTreeMap::new();
        fields.insert("MESSAGE".into(), format!("MESSAGE={message}").into_bytes());
        fields.insert(
            "PRIORITY".into(),
            format!("PRIORITY={priority}").into_bytes(),
        );
        JournalEntry {
            cursor: cursor.into(),
            realtime_usec: seqnum * 10,
            monotonic_usec: seqnum * 5,
            boot_id: SdId128([1; 16]),
            seqnum,
            fields,
            catalog: Some(format!("catalog-{seqnum}")),
        }
    }

    fn fixture() -> SdJournal {
        SdJournal::open_directory("/var/log/journal", 0)
            .unwrap()
            .with_entries(vec![
                entry(1, "A", "hello", "6"),
                entry(2, "B", "world", "3"),
            ])
    }

    #[test]
    fn open_helpers_capture_sources() {
        assert!(SdJournal::open(0).is_ok());
        assert!(
            SdJournal::open_directory("/run/log/journal", 0)
                .unwrap()
                .has_runtime_files()
        );
        assert!(
            SdJournal::open_files(&["/var/log/journal/a.journal"], 0)
                .unwrap()
                .has_persistent_files()
        );
    }

    #[test]
    fn seek_and_iterate_entries() {
        let mut journal = fixture();
        journal.seek_head().unwrap();
        assert_eq!(journal.next().unwrap(), 1);
        assert_eq!(journal.get_cursor().unwrap(), "A");
        assert_eq!(journal.next().unwrap(), 1);
        assert_eq!(journal.get_cursor().unwrap(), "B");
    }

    #[test]
    fn seek_cursor_and_seqnum() {
        let mut journal = fixture();
        journal.seek_cursor("B").unwrap();
        assert_eq!(journal.get_seqnum().unwrap(), 2);
        journal.seek_seqnum(1).unwrap();
        assert_eq!(journal.get_seqnum().unwrap(), 1);
    }

    #[test]
    fn data_access_obeys_threshold() {
        let mut journal = fixture();
        journal.seek_head().unwrap();
        journal.next().unwrap();
        journal.set_data_threshold(9).unwrap();
        assert_eq!(journal.get_data("MESSAGE").unwrap(), b"MESSAGE=h".to_vec());
    }

    #[test]
    fn data_enumeration_restarts() {
        let mut journal = fixture();
        journal.seek_head().unwrap();
        journal.next().unwrap();
        assert!(journal.enumerate_data().unwrap().is_some());
        journal.restart_data().unwrap();
        assert!(journal.enumerate_data().unwrap().is_some());
    }

    #[test]
    fn matches_filter_iteration() {
        let mut journal = fixture();
        journal.add_match(b"PRIORITY=3").unwrap();
        journal.seek_head().unwrap();
        assert_eq!(journal.next().unwrap(), 1);
        assert_eq!(journal.get_cursor().unwrap(), "B");
    }

    #[test]
    fn unique_query_deduplicates_values() {
        let mut journal = fixture();
        journal.query_unique("PRIORITY").unwrap();
        assert_eq!(
            journal.enumerate_unique().unwrap(),
            Some(b"PRIORITY=3".to_vec())
        );
        assert_eq!(
            journal.enumerate_unique().unwrap(),
            Some(b"PRIORITY=6".to_vec())
        );
    }

    #[test]
    fn cutoff_and_catalog_queries_work() {
        let mut journal = fixture();
        journal.insert_catalog(SdId128([2; 16]), "catalog-message-id");
        journal.seek_head().unwrap();
        journal.next().unwrap();
        assert_eq!(journal.get_cutoff_realtime_usec().unwrap(), (10, 20));
        assert_eq!(journal.get_catalog().unwrap(), "catalog-1");
        assert_eq!(
            journal
                .get_catalog_for_message_id(SdId128([2; 16]))
                .unwrap(),
            "catalog-message-id"
        );
    }

    #[test]
    fn foreach_visits_matching_entries() {
        let mut journal = fixture();
        let mut seen = Vec::new();
        journal
            .foreach(|entry| {
                seen.push(entry.cursor.clone());
                Ok(())
            })
            .unwrap();
        assert_eq!(seen, vec!["A", "B"]);
    }
}
