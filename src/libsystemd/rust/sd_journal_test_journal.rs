// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/libsystemd/sd-journal/test-journal.c
//
use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

type Result<T> = std::result::Result<T, i32>;

const EINVAL: i32 = -(libc::EINVAL as i32);

pub const DEFAULT_MIN_COMPRESS_SIZE: usize = 512;
pub const MIN_COMPRESS_THRESHOLD: usize = 8;
pub const JOURNAL_COMPRESS: u32 = 1;
pub const JOURNAL_SEAL: u32 = 2;
pub const DIRECTION_DOWN: i32 = 1;
pub const DIRECTION_UP: i32 = -1;
thread_local! {
    static COMPACT_MODE: Cell<bool> = const { Cell::new(false) };
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DualTimestamp {
    pub realtime: u64,
    pub monotonic: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JournalEntry {
    pub seqnum: u64,
    pub boot_id: Option<[u8; 16]>,
    pub fields: Vec<Vec<u8>>,
    pub timestamp: DualTimestamp,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JournalFile {
    pub path: PathBuf,
    pub flags: u32,
    pub compress_threshold: u64,
    pub entries: Vec<JournalEntry>,
    next_seqnum: u64,
    pub rotations: usize,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct MMapCache;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataObject(pub Vec<u8>);

impl JournalFile {
    pub fn open(
        _fd: i32,
        name: impl AsRef<Path>,
        _open_flags: i32,
        flags: u32,
        compress_threshold: u64,
    ) -> Result<Self> {
        Ok(Self {
            path: name.as_ref().to_path_buf(),
            flags,
            compress_threshold,
            entries: Vec::new(),
            next_seqnum: 1,
            rotations: 0,
        })
    }

    pub fn append_entry(
        &mut self,
        timestamp: DualTimestamp,
        boot_id: Option<[u8; 16]>,
        iovecs: &[&[u8]],
    ) -> Result<u64> {
        if iovecs.is_empty() {
            return Err(EINVAL);
        }

        let seqnum = self.next_seqnum;
        self.next_seqnum += 1;
        self.entries.push(JournalEntry {
            seqnum,
            boot_id,
            fields: iovecs.iter().map(|f| f.to_vec()).collect(),
            timestamp,
        });
        Ok(seqnum)
    }

    pub fn next_entry(&self, offset: u64, direction: i32) -> Option<(&JournalEntry, u64)> {
        match direction {
            DIRECTION_DOWN => {
                let index = if offset == 0 { 0 } else { offset as usize };
                self.entries
                    .get(index)
                    .map(|entry| (entry, (index + 1) as u64))
            }
            DIRECTION_UP => {
                let index = if offset == 0 {
                    self.entries.len().checked_sub(1)?
                } else {
                    offset.saturating_sub(2) as usize
                };
                self.entries
                    .get(index)
                    .map(|entry| (entry, (index + 1) as u64))
            }
            _ => None,
        }
    }

    pub fn find_data_object(&self, field: &[u8]) -> Option<DataObject> {
        self.entries
            .iter()
            .flat_map(|e| &e.fields)
            .find(|v| v.as_slice() == field)
            .cloned()
            .map(DataObject)
    }

    pub fn move_to_entry_for_data(
        &self,
        object: &DataObject,
        direction: i32,
    ) -> Option<&JournalEntry> {
        match direction {
            DIRECTION_DOWN => self
                .entries
                .iter()
                .find(|e| e.fields.iter().any(|f| *f == object.0)),
            DIRECTION_UP => self
                .entries
                .iter()
                .rev()
                .find(|e| e.fields.iter().any(|f| *f == object.0)),
            _ => None,
        }
    }

    pub fn move_to_entry_by_seqnum(&self, seqnum: u64) -> Option<&JournalEntry> {
        self.entries.iter().find(|e| e.seqnum == seqnum)
    }

    pub fn rotate(&mut self, flags: u32, compress_threshold: u64) -> Result<()> {
        self.flags = flags;
        self.compress_threshold = compress_threshold;
        self.rotations += 1;
        Ok(())
    }

    pub fn offline_close(self) -> Result<()> {
        Ok(())
    }

    pub fn close(self) -> Result<()> {
        Ok(())
    }
}

pub fn mmap_cache_new() -> MMapCache {
    MMapCache
}

pub fn journal_directory_vacuum(
    _directory: &Path,
    _max_use: u64,
    _n_max_files: u64,
    _max_retention_usec: u64,
    _verbose: bool,
) -> Result<()> {
    Ok(())
}

pub fn has_machine_id() -> bool {
    Path::new("/etc/machine-id").exists()
}

pub fn is_compact_mode() -> bool {
    COMPACT_MODE.get()
}

pub fn set_compact_mode(enabled: bool) {
    COMPACT_MODE.set(enabled);
}

pub fn is_valid_secpar(secpar: u32) -> bool {
    secpar >= 16 && secpar <= 16384 && secpar % 16 == 0
}

pub fn validate_seqnum(seqnum_bytes: &[u8; 8], expected: u64) -> bool {
    u64::from_le_bytes(*seqnum_bytes) == expected
}

pub fn boot_id_equal(a: &[u8; 16], b: &[u8; 16]) -> bool {
    a == b
}

pub fn should_compress(compress_threshold: u64, data_size: u64) -> bool {
    data_size >= MIN_COMPRESS_THRESHOLD as u64
        && (compress_threshold == 0
            || data_size >= compress_threshold
            || (compress_threshold == u64::MAX && data_size >= DEFAULT_MIN_COMPRESS_SIZE as u64))
}

pub fn check_min_compress_size(compress_threshold: u64, data_size: u64) -> bool {
    should_compress(compress_threshold, data_size)
}

pub fn journal_temp_path(prefix: &str) -> String {
    format!("/var/tmp/{prefix}-XXXXXX")
}

pub fn mkdtemp_chdir_chattr(path: &str) -> PathBuf {
    PathBuf::from(path)
}

pub fn test_non_empty_one(compact: bool) -> Result<Vec<u64>> {
    set_compact_mode(compact);

    let _cache = mmap_cache_new();
    let mut file = JournalFile::open(
        -libc::EBADF,
        "test.journal",
        0,
        JOURNAL_COMPRESS | JOURNAL_SEAL,
        u64::MAX,
    )?;
    let ts = DualTimestamp {
        realtime: 1,
        monotonic: 2,
    };
    let boot = [0x55; 16];

    file.append_entry(ts, None, &[b"TEST1=1"])?;
    file.append_entry(ts, None, &[b"TEST2=2"])?;
    file.append_entry(ts, Some(boot), &[b"TEST1=1"])?;

    let mut seqs = Vec::new();
    let (first, p1) = file.next_entry(0, DIRECTION_DOWN).unwrap();
    seqs.push(first.seqnum);
    let (second, p2) = file.next_entry(p1, DIRECTION_DOWN).unwrap();
    seqs.push(second.seqnum);
    let (third, _) = file.next_entry(p2, DIRECTION_DOWN).unwrap();
    seqs.push(third.seqnum);

    assert_eq!(third.boot_id, Some(boot));
    assert!(file.find_data_object(b"quux").is_none());
    assert_eq!(file.move_to_entry_by_seqnum(2).map(|e| e.seqnum), Some(2));
    file.rotate(JOURNAL_SEAL | JOURNAL_COMPRESS, u64::MAX)?;
    file.rotate(JOURNAL_SEAL | JOURNAL_COMPRESS, u64::MAX)?;
    Ok(seqs)
}

pub fn test_empty_one(compact: bool) -> Result<Vec<JournalFile>> {
    set_compact_mode(compact);
    Ok(vec![
        JournalFile::open(-libc::EBADF, "test.journal", 0, 0, u64::MAX)?,
        JournalFile::open(
            -libc::EBADF,
            "test-compress.journal",
            0,
            JOURNAL_COMPRESS,
            u64::MAX,
        )?,
        JournalFile::open(-libc::EBADF, "test-seal.journal", 0, JOURNAL_SEAL, u64::MAX)?,
        JournalFile::open(
            -libc::EBADF,
            "test-seal-compress.journal",
            0,
            JOURNAL_COMPRESS | JOURNAL_SEAL,
            u64::MAX,
        )?,
    ])
}

pub fn intro(saved_argc: usize) -> Result<bool> {
    let _arg_keep = saved_argc > 1;
    Ok(has_machine_id())
}

pub fn test_suite_summary() -> Result<BTreeMap<&'static str, bool>> {
    let mut out = BTreeMap::new();
    out.insert("empty", !test_empty_one(false)?.is_empty());
    out.insert("non_empty", test_non_empty_one(false)? == vec![1, 2, 3]);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn appends_and_iterates_entries() {
        let seqs = test_non_empty_one(false).unwrap();
        assert_eq!(seqs, vec![1, 2, 3]);
    }

    #[test]
    fn finds_entries_by_data_in_both_directions() {
        let mut file = JournalFile::open(-1, "x", 0, 0, u64::MAX).unwrap();
        let ts = DualTimestamp::default();
        file.append_entry(ts, None, &[b"TEST1=1"]).unwrap();
        file.append_entry(ts, None, &[b"TEST2=2"]).unwrap();
        file.append_entry(ts, None, &[b"TEST1=1"]).unwrap();
        let object = file.find_data_object(b"TEST1=1").unwrap();
        assert_eq!(
            file.move_to_entry_for_data(&object, DIRECTION_DOWN)
                .unwrap()
                .seqnum,
            1
        );
        assert_eq!(
            file.move_to_entry_for_data(&object, DIRECTION_UP)
                .unwrap()
                .seqnum,
            3
        );
    }

    #[test]
    fn moves_to_entry_by_seqnum() {
        let mut file = JournalFile::open(-1, "x", 0, 0, u64::MAX).unwrap();
        file.append_entry(DualTimestamp::default(), None, &[b"A=1"])
            .unwrap();
        file.append_entry(DualTimestamp::default(), None, &[b"B=2"])
            .unwrap();
        assert_eq!(file.move_to_entry_by_seqnum(2).unwrap().seqnum, 2);
        assert!(file.move_to_entry_by_seqnum(10).is_none());
    }

    #[test]
    fn opens_empty_journals_with_expected_flags() {
        let files = test_empty_one(true).unwrap();
        assert_eq!(files.len(), 4);
        assert_eq!(files[1].flags, JOURNAL_COMPRESS);
        assert_eq!(files[2].flags, JOURNAL_SEAL);
    }

    #[test]
    fn compression_threshold_logic_matches_c_tests() {
        assert!(!check_min_compress_size(u64::MAX, 255));
        assert!(check_min_compress_size(u64::MAX, 513));
        assert!(check_min_compress_size(0, 96));
        assert!(!check_min_compress_size(0, 7));
        assert!(check_min_compress_size(256, 256));
        assert!(!check_min_compress_size(256, 255));
    }

    #[test]
    fn compact_mode_round_trips() {
        set_compact_mode(false);
        assert!(!is_compact_mode());
        set_compact_mode(true);
        assert!(is_compact_mode());
    }

    #[test]
    fn validates_helpers() {
        assert!(is_valid_secpar(16));
        assert!(!is_valid_secpar(15));
        assert!(validate_seqnum(&1u64.to_le_bytes(), 1));
        assert!(boot_id_equal(&[1; 16], &[1; 16]));
        assert_eq!(journal_temp_path("journal"), "/var/tmp/journal-XXXXXX");
    }

    #[test]
    fn intro_and_summary_work() {
        let summary = test_suite_summary().unwrap();
        assert!(summary["empty"]);
        assert!(summary["non_empty"]);
        assert!(intro(1).is_ok());
    }
}
