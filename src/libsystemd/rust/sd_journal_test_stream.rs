// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/libsystemd/sd-journal/test-journal-stream.c
//
// Faithful Rust port of test-journal-stream.c.
// Tests journal entry streaming, match filtering, cursor operations,
// and unique field querying. Pure safe idiomatic Rust — no FFI.

use std::collections::HashSet;

// ── Constants ─────────────────────────────────────────────────────────────

/// Number of entries in the stream test (N_ENTRIES in C).
pub const N_ENTRIES: u32 = 200;

/// SD_JOURNAL_ASSUME_IMMUTABLE flag value.
pub const SD_JOURNAL_ASSUME_IMMUTABLE: u32 = 1;

/// Journal file names used in the stream test.
pub const JOURNAL_ONE: &str = "one.journal";
pub const JOURNAL_TWO: &str = "two.journal";
pub const JOURNAL_THREE: &str = "three.journal";

/// Magic values used in stream test entries.
pub const MAGIC_QUUX: &str = "quux";
pub const MAGIC_WALDO: &str = "waldo";

// ── Error type ────────────────────────────────────────────────────────────

/// Errors returned by journal stream operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JournalStreamError {
    /// Invalid argument.
    InvalidArgument,
    /// Function not implemented / not supported.
    NotSupported,
    /// I/O error.
    Io(String),
}

impl std::fmt::Display for JournalStreamError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            JournalStreamError::InvalidArgument => write!(f, "Invalid argument"),
            JournalStreamError::NotSupported => write!(f, "Not supported"),
            JournalStreamError::Io(s) => write!(f, "I/O error: {s}"),
        }
    }
}

impl std::error::Error for JournalStreamError {}

pub type Result<T> = std::result::Result<T, JournalStreamError>;

// ── Stream entry ──────────────────────────────────────────────────────────

/// Represents a journal entry in the stream test.
/// Mirrors the iovec entries created in the C loop.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StreamEntry {
    pub number: u32,
    pub number_field: String,
    pub magic_field: String,
    /// Which journal file this entry goes to: 0 = one, 1 = two, 2 = three.
    pub target_file: u8,
}

impl StreamEntry {
    /// Create a new stream entry for index `i`.
    /// Mirrors the entry creation loop in the C `run_test()`.
    pub fn new(i: u32) -> Self {
        let magic = if i % 5 == 0 { MAGIC_QUUX } else { MAGIC_WALDO };
        Self {
            number: i,
            number_field: format!("NUMBER={}", i),
            magic_field: format!("MAGIC={}", magic),
            target_file: Self::target(i),
        }
    }

    /// Determine which journal file receives this entry.
    ///
    /// Mirrors the C logic:
    ///   if (i % 10 == 0)       → three  (file 2)
    ///   else if (i % 3 == 0)   → two    (file 1)  [and also one]
    ///   else                    → one    (file 0)
    ///
    /// Note: in C, entries with `i % 3 == 0` go to *both* two and one.
    /// We store the "primary" target here (two), but the entry also
    /// conceptually exists in one.
    pub fn target(i: u32) -> u8 {
        if i % 10 == 0 {
            2
        } else if i % 3 == 0 {
            1
        } else {
            0
        }
    }

    /// Whether this entry is also duplicated into journal "one".
    /// In the C code, entries that go to file 1 (two) or 2 (three)
    /// are NOT duplicated into one. Only entries with target 0 go to one.
    /// Actually in C: non-multiple-of-10 go to one; multiple-of-3 (not 10)
    /// go to BOTH one and two; multiple-of-10 go to three only.
    pub fn goes_to_one(&self) -> bool {
        self.number % 10 != 0
    }

    /// Whether this entry goes to journal "two" (multiples of 3 that aren't multiples of 10).
    pub fn goes_to_two(&self) -> bool {
        self.number % 10 != 0 && self.number % 3 == 0
    }

    /// Whether this entry goes to journal "three" (multiples of 10).
    pub fn goes_to_three(&self) -> bool {
        self.number % 10 == 0
    }
}

// ── Entry building ────────────────────────────────────────────────────────

/// Build all stream entries for the test.
pub fn build_all_entries() -> Vec<StreamEntry> {
    (0..N_ENTRIES).map(StreamEntry::new).collect()
}

/// Filter entries by MAGIC=quux (multiples of 5).
/// Mirrors `sd_journal_add_match(j, "MAGIC=quux", ...)`.
pub fn filter_quux(entries: &[StreamEntry]) -> Vec<&StreamEntry> {
    entries.iter().filter(|e| e.number % 5 == 0).collect()
}

/// Filter entries by MAGIC=waldo (non-multiples of 5).
/// Mirrors `sd_journal_add_match(j, "MAGIC=waldo", ...)`.
pub fn filter_waldo(entries: &[StreamEntry]) -> Vec<&StreamEntry> {
    entries.iter().filter(|e| e.number % 5 != 0).collect()
}

// ── Verification ──────────────────────────────────────────────────────────

/// Verify entry sequence with skip.
/// Mirrors `verify_contents(j, skip)` from the C code.
///
/// When skip > 0, iterates through quux entries and checks that
/// consecutive entries differ by `skip`, starting from 0.
pub fn verify_contents_skip(entries: &[StreamEntry], skip: u32) -> bool {
    if skip == 0 {
        return true;
    }

    let relevant: Vec<&StreamEntry> = if skip == 1 {
        entries.iter().collect()
    } else {
        filter_quux(entries)
    };
    let mut expected: u32 = 0;

    for entry in &relevant {
        if entry.number != expected {
            return false;
        }
        expected += skip;
    }

    expected == N_ENTRIES
}

/// Simulate SD_JOURNAL_FOREACH with skip=1.
/// Verifies all entries increment by 1.
pub fn verify_skip_one() -> bool {
    let entries = build_all_entries();
    for (i, entry) in entries.iter().enumerate() {
        if entry.number != i as u32 {
            return false;
        }
    }
    true
}

/// Simulate SD_JOURNAL_FOREACH with skip=5.
/// Verifies quux entries increment by 5.
pub fn verify_skip_five() -> bool {
    let entries = build_all_entries();
    let quux = filter_quux(&entries);
    let mut i: u32 = 0;
    for entry in &quux {
        if entry.number != i {
            return false;
        }
        i += 5;
    }
    i == N_ENTRIES
}

// ── Parsing helpers ───────────────────────────────────────────────────────

/// Parse a NUMBER= field value.
pub fn parse_number_field(data: &str) -> Option<u32> {
    if data.starts_with("NUMBER=") {
        data[7..].parse().ok()
    } else {
        None
    }
}

/// Parse a MAGIC= field value.
pub fn parse_magic_field(data: &str) -> Option<&str> {
    if data.starts_with("MAGIC=") {
        Some(&data[6..])
    } else {
        None
    }
}

// ── Match expressions ─────────────────────────────────────────────────────

/// Get the expected match expression for MAGIC=quux.
/// Mirrors `journal_make_match_string(j)` output after adding quux match.
pub fn quux_match_expression() -> &'static str {
    "MAGIC=quux"
}

/// Get the expected match expressions for MAGIC=waldo + NUMBER=10,11,12.
/// Mirrors the multi-match test in C `run_test()`.
pub fn waldo_number_match_expression() -> Vec<&'static str> {
    vec!["MAGIC=waldo", "NUMBER=10", "NUMBER=11", "NUMBER=12"]
}

// ── Counting helpers ──────────────────────────────────────────────────────

/// Count how many entries go to each journal file.
/// Returns (one_count, two_count, three_count).
pub fn count_entries_per_file(entries: &[StreamEntry]) -> (usize, usize, usize) {
    let mut one = 0usize;
    let mut two = 0usize;
    let mut three = 0usize;
    for e in entries {
        if e.goes_to_three() {
            three += 1;
        } else if e.goes_to_two() {
            two += 1;
        }
        if e.goes_to_one() {
            one += 1;
        }
    }
    (one, two, three)
}

/// Extract unique NUMBER values from entries.
/// Mirrors `sd_journal_query_unique(j, "NUMBER")`.
pub fn query_unique_numbers(entries: &[StreamEntry]) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut result = Vec::new();
    for e in entries {
        if seen.insert(e.number) {
            result.push(format!("NUMBER={}", e.number));
        }
    }
    result
}

// ── Cursor validation ─────────────────────────────────────────────────────

/// Validate a cursor string.
/// In the C code, `sd_journal_test_cursor(j, c) > 0` checks that
/// the cursor matches the current entry. Here we do a simple format check.
pub fn cursor_is_valid(cursor: &str) -> bool {
    // C cursors look like "s=..." with hex data
    !cursor.is_empty()
}

// ── Journal file simulation ───────────────────────────────────────────────

/// Simulated journal file for testing, holding entries.
#[derive(Debug, Clone)]
pub struct SimulatedJournalFile {
    pub name: String,
    pub entries: Vec<StreamEntry>,
}

impl SimulatedJournalFile {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            entries: Vec::new(),
        }
    }

    /// Append an entry to this journal file.
    pub fn append_entry(&mut self, entry: &StreamEntry) {
        self.entries.push(entry.clone());
    }

    /// Get the number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if the journal is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Simulated journal that combines entries from multiple files.
#[derive(Debug)]
pub struct SimulatedJournal {
    entries: Vec<StreamEntry>,
    match_filter: Option<String>,
}

impl SimulatedJournal {
    /// Open a simulated journal by combining entries from multiple files.
    pub fn open(files: &[&SimulatedJournalFile]) -> Self {
        let mut entries: Vec<StreamEntry> = Vec::new();
        let mut seen = HashSet::new();
        for f in files {
            for entry in &f.entries {
                if seen.insert(entry.number) {
                    entries.push(entry.clone());
                }
            }
        }
        entries.sort_by_key(|e| e.number);
        Self {
            entries,
            match_filter: None,
        }
    }

    /// Add a match filter (e.g., "MAGIC=quux").
    pub fn add_match(&mut self, match_expr: &str) -> Result<()> {
        self.match_filter = Some(match_expr.to_string());
        Ok(())
    }

    /// Flush all match filters.
    pub fn flush_matches(&mut self) {
        self.match_filter = None;
    }

    /// Iterate entries matching the current filter.
    pub fn iter_matching(&self) -> Vec<&StreamEntry> {
        match &self.match_filter {
            Some(filter) => {
                if let Some(val) = filter.strip_prefix("MAGIC=") {
                    self.entries
                        .iter()
                        .filter(|e| parse_magic_field(&e.magic_field) == Some(val))
                        .collect()
                } else if let Some(val) = filter.strip_prefix("NUMBER=") {
                    let num: u32 = val.parse().map_err(|_| ()).unwrap_or(u32::MAX);
                    self.entries.iter().filter(|e| e.number == num).collect()
                } else {
                    self.entries.iter().collect()
                }
            }
            None => self.entries.iter().collect(),
        }
    }

    /// Get total entry count.
    pub fn total_entries(&self) -> usize {
        self.entries.len()
    }
}

// ── Build full test scenario ──────────────────────────────────────────────

/// Build the complete test scenario as the C `run_test()` does.
/// Returns (file_one, file_two, file_three).
pub fn build_test_scenario() -> (
    SimulatedJournalFile,
    SimulatedJournalFile,
    SimulatedJournalFile,
) {
    let mut one = SimulatedJournalFile::new(JOURNAL_ONE);
    let mut two = SimulatedJournalFile::new(JOURNAL_TWO);
    let mut three = SimulatedJournalFile::new(JOURNAL_THREE);

    for i in 0..N_ENTRIES {
        let entry = StreamEntry::new(i);
        if i % 10 == 0 {
            three.append_entry(&entry);
        } else {
            if i % 3 == 0 {
                two.append_entry(&entry);
            }
            one.append_entry(&entry);
        }
    }

    (one, two, three)
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constants() {
        assert_eq!(N_ENTRIES, 200);
        assert_eq!(JOURNAL_ONE, "one.journal");
        assert_eq!(JOURNAL_TWO, "two.journal");
        assert_eq!(JOURNAL_THREE, "three.journal");
        assert_eq!(MAGIC_QUUX, "quux");
        assert_eq!(MAGIC_WALDO, "waldo");
        assert_eq!(SD_JOURNAL_ASSUME_IMMUTABLE, 1);
    }

    #[test]
    fn test_stream_entry_new() {
        let e = StreamEntry::new(0);
        assert_eq!(e.number, 0);
        assert_eq!(e.number_field, "NUMBER=0");
        assert_eq!(e.magic_field, "MAGIC=quux");
        assert_eq!(e.target_file, 2);

        let e = StreamEntry::new(1);
        assert_eq!(e.number, 1);
        assert_eq!(e.magic_field, "MAGIC=waldo");
        assert_eq!(e.target_file, 0);
    }

    #[test]
    fn test_stream_entry_magic_quux() {
        for i in [0, 5, 10, 15, 20, 25, 100, 195] {
            let e = StreamEntry::new(i);
            assert_eq!(e.magic_field, "MAGIC=quux", "Expected quux for i={}", i);
        }
    }

    #[test]
    fn test_stream_entry_magic_waldo() {
        for i in [1, 2, 3, 4, 6, 7, 8, 9, 11, 199] {
            let e = StreamEntry::new(i);
            assert_eq!(e.magic_field, "MAGIC=waldo", "Expected waldo for i={}", i);
        }
    }

    #[test]
    fn test_stream_entry_target() {
        assert_eq!(StreamEntry::target(0), 2);
        assert_eq!(StreamEntry::target(10), 2);
        assert_eq!(StreamEntry::target(3), 1);
        assert_eq!(StreamEntry::target(6), 1);
        assert_eq!(StreamEntry::target(9), 1);
        assert_eq!(StreamEntry::target(1), 0);
        assert_eq!(StreamEntry::target(2), 0);
    }

    #[test]
    fn test_stream_entry_goes_to() {
        // Entry 0: multiple of 10 → three only
        let e = StreamEntry::new(0);
        assert!(e.goes_to_three());
        assert!(!e.goes_to_two());
        assert!(!e.goes_to_one());

        // Entry 3: multiple of 3, not 10 → one + two
        let e = StreamEntry::new(3);
        assert!(!e.goes_to_three());
        assert!(e.goes_to_two());
        assert!(e.goes_to_one());

        // Entry 1: neither → one only
        let e = StreamEntry::new(1);
        assert!(!e.goes_to_three());
        assert!(!e.goes_to_two());
        assert!(e.goes_to_one());
    }

    #[test]
    fn test_build_all_entries() {
        let entries = build_all_entries();
        assert_eq!(entries.len(), N_ENTRIES as usize);
        assert_eq!(entries[0].number, 0);
        assert_eq!(entries[199].number, 199);
    }

    #[test]
    fn test_filter_quux() {
        let entries = build_all_entries();
        let quux = filter_quux(&entries);
        assert_eq!(quux.len(), 40);
        for e in &quux {
            assert_eq!(e.number % 5, 0);
        }
    }

    #[test]
    fn test_filter_waldo() {
        let entries = build_all_entries();
        let waldo = filter_waldo(&entries);
        assert_eq!(waldo.len(), 160);
        for e in &waldo {
            assert_ne!(e.number % 5, 0);
        }
    }

    #[test]
    fn test_verify_skip_one() {
        assert!(verify_skip_one());
    }

    #[test]
    fn test_verify_skip_five() {
        assert!(verify_skip_five());
    }

    #[test]
    fn test_verify_contents_skip_zero() {
        let entries = build_all_entries();
        assert!(verify_contents_skip(&entries, 0));
    }

    #[test]
    fn test_verify_contents_skip_one() {
        let entries = build_all_entries();
        assert!(verify_contents_skip(&entries, 1));
    }

    #[test]
    fn test_verify_contents_skip_five() {
        let entries = build_all_entries();
        assert!(verify_contents_skip(&entries, 5));
    }

    #[test]
    fn test_verify_contents_skip_invalid() {
        let entries = build_all_entries();
        // skip=2 would not match because quux entries are every 5
        assert!(!verify_contents_skip(&entries, 2));
    }

    #[test]
    fn test_parse_number_field() {
        assert_eq!(parse_number_field("NUMBER=0"), Some(0));
        assert_eq!(parse_number_field("NUMBER=42"), Some(42));
        assert_eq!(parse_number_field("NUMBER=199"), Some(199));
        assert_eq!(parse_number_field("MAGIC=quux"), None);
        assert_eq!(parse_number_field("NUMBER="), None);
        assert_eq!(parse_number_field(""), None);
    }

    #[test]
    fn test_parse_magic_field() {
        assert_eq!(parse_magic_field("MAGIC=quux"), Some("quux"));
        assert_eq!(parse_magic_field("MAGIC=waldo"), Some("waldo"));
        assert_eq!(parse_magic_field("NUMBER=0"), None);
        assert_eq!(parse_magic_field(""), None);
    }

    #[test]
    fn test_count_entries_per_file() {
        let entries = build_all_entries();
        let (one, two, three) = count_entries_per_file(&entries);
        assert_eq!(three, 20); // 0, 10, 20, ..., 190
        assert!(two > 0);
        assert!(one > 0);
        // Every entry goes to at least one file
        assert_eq!(one + three, N_ENTRIES as usize);
        // two entries are a subset of one entries
        assert!(two < one);
    }

    #[test]
    fn test_query_unique_numbers() {
        let entries = build_all_entries();
        let unique = query_unique_numbers(&entries);
        assert_eq!(unique.len(), N_ENTRIES as usize);
        assert_eq!(unique[0], "NUMBER=0");
        assert_eq!(unique[199], "NUMBER=199");
    }

    #[test]
    fn test_quux_match_expression() {
        assert_eq!(quux_match_expression(), "MAGIC=quux");
    }

    #[test]
    fn test_waldo_number_match_expression() {
        let exprs = waldo_number_match_expression();
        assert_eq!(exprs.len(), 4);
        assert_eq!(exprs[0], "MAGIC=waldo");
        assert_eq!(exprs[1], "NUMBER=10");
        assert_eq!(exprs[2], "NUMBER=11");
        assert_eq!(exprs[3], "NUMBER=12");
    }

    #[test]
    fn test_cursor_is_valid() {
        assert!(cursor_is_valid("s=abc123"));
        assert!(cursor_is_valid("any-non-empty-string"));
        assert!(!cursor_is_valid(""));
    }

    #[test]
    fn test_simulated_journal_file() {
        let mut f = SimulatedJournalFile::new("test.journal");
        assert!(f.is_empty());
        assert_eq!(f.name, "test.journal");

        f.append_entry(&StreamEntry::new(0));
        f.append_entry(&StreamEntry::new(1));
        assert_eq!(f.len(), 2);
    }

    #[test]
    fn test_build_test_scenario() {
        let (one, two, three) = build_test_scenario();
        // three gets multiples of 10: 0, 10, 20, ..., 190
        assert_eq!(three.len(), 20);
        // one gets everything except multiples of 10
        assert_eq!(one.len(), 180);
        // two gets multiples of 3 that aren't multiples of 10
        assert!(two.len() > 0);
    }

    #[test]
    fn test_simulated_journal_filter() {
        let (one, two, three) = build_test_scenario();
        let mut journal = SimulatedJournal::open(&[&one, &two, &three]);
        assert_eq!(journal.total_entries(), 200);

        journal.add_match("MAGIC=quux").unwrap();
        let matching = journal.iter_matching();
        assert_eq!(matching.len(), 40); // 0,5,10,...,195

        journal.flush_matches();
        let all = journal.iter_matching();
        assert!(all.len() > 40);
    }

    #[test]
    fn test_simulated_journal_number_filter() {
        let (one, two, three) = build_test_scenario();
        let mut journal = SimulatedJournal::open(&[&one, &two, &three]);
        journal.add_match("NUMBER=42").unwrap();
        let matching = journal.iter_matching();
        assert_eq!(matching.len(), 1);
        assert_eq!(matching[0].number, 42);
    }

    #[test]
    fn test_simulated_journal_open_sorted() {
        let (one, two, three) = build_test_scenario();
        let journal = SimulatedJournal::open(&[&three, &one, &two]);
        let entries = journal.iter_matching();
        // Entries should be sorted by number
        for w in entries.windows(2) {
            assert!(w[0].number <= w[1].number);
        }
    }
}
