// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/pstore/pstore.c
//
// Archives and manages pstore (persistent store) entries from kernel crashes.
//
// Provides storage configuration parsing, entry classification, and dmesg
// file name parsing for EFI and ERST backends, faithfully mirroring the
// C implementation's file handling logic.

// ── Constants ─────────────────────────────────────────────────────────────

/// Default pstore source directory.
pub const DEFAULT_PSTORE_SOURCE_DIR: &str = "/sys/fs/pstore";

/// Default pstore archive directory.
pub const DEFAULT_PSTORE_ARCHIVE_DIR: &str = "/var/lib/systemd/pstore";

// ── Error type ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Errno(pub i32);

impl std::fmt::Display for Errno {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "errno {}", self.0)
    }
}

impl std::error::Error for Errno {}

pub type Result<T> = std::result::Result<T, Errno>;

// ── Enums ─────────────────────────────────────────────────────────────────

/// Storage backend for pstore data.
/// Mirrors `PStoreStorage` in the C source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PStoreStorage {
    None,
    External,
    Journal,
}

/// Classification of pstore file types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PStoreType {
    Dmesg,
    DmesgEfi,
    DmesgErst,
    Pmsg,
    Ftrace,
    Unknown,
}

// ── Storage parsing ───────────────────────────────────────────────────────

/// Parse a storage mode from its string representation.
/// Corresponds to `pstore_storage_from_string()` via the string table.
pub fn parse_pstore_storage(s: &str) -> Result<PStoreStorage> {
    match s.to_ascii_lowercase().as_str() {
        "none" => Ok(PStoreStorage::None),
        "external" => Ok(PStoreStorage::External),
        "journal" => Ok(PStoreStorage::Journal),
        _ => Err(Errno(-22)), // -EINVAL
    }
}

/// Convert a storage mode back to string.
/// Corresponds to `pstore_storage_to_string()`.
pub fn pstore_storage_to_string(storage: PStoreStorage) -> &'static str {
    match storage {
        PStoreStorage::None => "none",
        PStoreStorage::External => "external",
        PStoreStorage::Journal => "journal",
    }
}

// ── Configuration ─────────────────────────────────────────────────────────

/// PStore configuration, mirroring the static args in pstore.c.
#[derive(Debug, Clone)]
pub struct PStoreConfig {
    pub storage: PStoreStorage,
    pub unlink: bool,
    pub source_dir: String,
    pub archive_dir: String,
}

impl Default for PStoreConfig {
    fn default() -> Self {
        Self {
            storage: PStoreStorage::External,
            unlink: true,
            source_dir: DEFAULT_PSTORE_SOURCE_DIR.to_string(),
            archive_dir: DEFAULT_PSTORE_ARCHIVE_DIR.to_string(),
        }
    }
}

impl PStoreConfig {
    pub fn new() -> Self {
        Self::default()
    }

    /// Check whether pstore processing should be skipped entirely.
    /// Mirrors `if (arg_storage == PSTORE_STORAGE_NONE) return 0;` in `run()`.
    pub fn is_disabled(&self) -> bool {
        self.storage == PStoreStorage::None
    }
}

// ── Entry classification ──────────────────────────────────────────────────

/// Classify a pstore file by its type based on the filename.
/// Mirrors the logic in `process_dmesg_files()` and the filename-based dispatch.
pub fn classify_pstore_type(filename: &str) -> PStoreType {
    if filename.starts_with("dmesg-efi_pstore-") {
        PStoreType::DmesgEfi
    } else if filename.starts_with("dmesg-efi-") {
        PStoreType::DmesgEfi
    } else if filename.starts_with("dmesg-erst-") {
        PStoreType::DmesgErst
    } else if filename.starts_with("dmesg-") {
        PStoreType::Dmesg
    } else if filename.starts_with("pmsg") {
        PStoreType::Pmsg
    } else if filename.contains("ftrace") {
        PStoreType::Ftrace
    } else {
        PStoreType::Unknown
    }
}

/// Check whether a filename looks like a pstore entry.
/// Mirrors the filtering in `list_files()`.
pub fn is_pstore_entry(filename: &str) -> bool {
    filename.starts_with("dmesg-")
        || filename.contains("ramoops")
        || filename.starts_with("pmsg")
        || filename.contains("ftrace")
}

// ── EFI dmesg parsing ────────────────────────────────────────────────────

/// Parsed EFI dmesg record metadata, extracted from the filename.
/// Corresponds to the logic in `process_dmesg_files()` for EFI entries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EfiDmesgRecord {
    pub subdir1: String,
    pub subdir2: String,
}

/// Parse an EFI dmesg filename to extract record metadata.
/// The EFI backend encodes: `dmesg-efi-{timestamp}{part}{count}` or
/// `dmesg-efi_pstore-{timestamp}{part}{count}`.
/// Last 3 digits = count, next 2 = part, rest = timestamp.
/// Returns `None` if the filename doesn't match or is too short (< 6 trailing digits).
pub fn parse_efi_dmesg_filename(filename: &str) -> Option<EfiDmesgRecord> {
    let prefix = if filename.starts_with("dmesg-efi_pstore-") {
        "dmesg-efi_pstore-"
    } else if filename.starts_with("dmesg-efi-") {
        "dmesg-efi-"
    } else {
        return None;
    };

    let rest = &filename[prefix.len()..];
    if rest.len() < 6 {
        return None;
    }

    // All remaining chars should be hex digits for valid EFI records
    if !rest.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }

    let plen = rest.len();
    // subdir1 = rest[0..plen-5] (base record id, excluding part+count)
    // subdir2 = rest[plen-3..plen] (count field)
    let subdir1 = rest[..plen - 5].to_string();
    let subdir2 = rest[plen - 3..].to_string();

    Some(EfiDmesgRecord { subdir1, subdir2 })
}

/// Check if a dmesg filename indicates a problem (encrypted/compressed).
/// Corresponds to `endswith(pe->dirent.d_name, ".enc.z")`.
pub fn is_encrypted_dmesg(filename: &str) -> bool {
    filename.ends_with(".enc.z")
}

// ── Entry model ───────────────────────────────────────────────────────────

/// A pstore file entry, mirroring `PStoreEntry` in the C source.
#[derive(Debug, Clone)]
pub struct PStoreEntry {
    pub filename: String,
    pub content: Vec<u8>,
    pub is_binary: bool,
    pub handled: bool,
}

impl PStoreEntry {
    pub fn new(filename: &str, content: Vec<u8>) -> Self {
        Self {
            filename: filename.to_string(),
            content,
            is_binary: true,
            handled: false,
        }
    }
}

/// A sorted list of pstore entries, mirroring `PStoreList`.
#[derive(Debug, Clone, Default)]
pub struct PStoreList {
    pub entries: Vec<PStoreEntry>,
}

impl PStoreList {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an entry to the list.
    pub fn push(&mut self, entry: PStoreEntry) {
        self.entries.push(entry);
    }

    /// Sort entries lexicographically by filename.
    /// Corresponds to `typesafe_qsort(list.entries, list.n_entries, compare_pstore_entries)`.
    pub fn sort(&mut self) {
        self.entries.sort_by(|a, b| a.filename.cmp(&b.filename));
    }

    /// Count entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_storage_variants() {
        assert_eq!(parse_pstore_storage("none").unwrap(), PStoreStorage::None);
        assert_eq!(
            parse_pstore_storage("external").unwrap(),
            PStoreStorage::External
        );
        assert_eq!(
            parse_pstore_storage("journal").unwrap(),
            PStoreStorage::Journal
        );
        assert!(parse_pstore_storage("bad").is_err());
    }

    #[test]
    fn parse_storage_case_insensitive() {
        assert_eq!(
            parse_pstore_storage("External").unwrap(),
            PStoreStorage::External
        );
        assert_eq!(
            parse_pstore_storage("JOURNAL").unwrap(),
            PStoreStorage::Journal
        );
    }

    #[test]
    fn storage_roundtrip() {
        for s in [
            PStoreStorage::None,
            PStoreStorage::External,
            PStoreStorage::Journal,
        ] {
            let str = pstore_storage_to_string(s);
            assert_eq!(parse_pstore_storage(str).unwrap(), s);
        }
    }

    #[test]
    fn default_config() {
        let cfg = PStoreConfig::new();
        assert_eq!(cfg.storage, PStoreStorage::External);
        assert!(cfg.unlink);
        assert_eq!(cfg.source_dir, DEFAULT_PSTORE_SOURCE_DIR);
        assert_eq!(cfg.archive_dir, DEFAULT_PSTORE_ARCHIVE_DIR);
    }

    #[test]
    fn config_is_disabled_only_for_none() {
        assert!(
            PStoreConfig {
                storage: PStoreStorage::None,
                ..Default::default()
            }
            .is_disabled()
        );
        assert!(!PStoreConfig::new().is_disabled());
    }

    #[test]
    fn classify_dmesg_efi() {
        assert_eq!(
            classify_pstore_type("dmesg-efi-12345678901234"),
            PStoreType::DmesgEfi
        );
        assert_eq!(
            classify_pstore_type("dmesg-efi_pstore-12345678901234"),
            PStoreType::DmesgEfi
        );
    }

    #[test]
    fn classify_dmesg_erst() {
        assert_eq!(
            classify_pstore_type("dmesg-erst-123456789"),
            PStoreType::DmesgErst
        );
    }

    #[test]
    fn classify_other_types() {
        assert_eq!(classify_pstore_type("dmesg-unknown-123"), PStoreType::Dmesg);
        assert_eq!(classify_pstore_type("pmsg-ramoops-0"), PStoreType::Pmsg);
        assert_eq!(classify_pstore_type("ftrace-ramoops-0"), PStoreType::Ftrace);
        assert_eq!(classify_pstore_type("other.txt"), PStoreType::Unknown);
    }

    #[test]
    fn is_pstore_entry_detection() {
        assert!(is_pstore_entry("dmesg-efi-123456"));
        assert!(is_pstore_entry("pmsg-ramoops-0"));
        assert!(is_pstore_entry("ftrace-ramoops-0"));
        assert!(is_pstore_entry("something-ramoops-0"));
        assert!(!is_pstore_entry("random.txt"));
    }

    #[test]
    fn parse_efi_dmesg_filename_valid() {
        let rec = parse_efi_dmesg_filename("dmesg-efi-12345678901234").unwrap();
        // rest = "12345678901234" (14 chars), plen=14
        // subdir1 = rest[0..9] = "123456789"
        // subdir2 = rest[11..14] = "234"
        assert_eq!(rec.subdir1, "123456789");
        assert_eq!(rec.subdir2, "234");
    }

    #[test]
    fn parse_efi_dmesg_pstore_variant() {
        let rec = parse_efi_dmesg_filename("dmesg-efi_pstore-aabbccddeeff").unwrap();
        assert!(!rec.subdir1.is_empty());
        assert!(!rec.subdir2.is_empty());
    }

    #[test]
    fn parse_efi_dmesg_too_short() {
        assert!(parse_efi_dmesg_filename("dmesg-efi-12345").is_none());
    }

    #[test]
    fn parse_efi_dmesg_non_hex() {
        assert!(parse_efi_dmesg_filename("dmesg-efi-12x34567890").is_none());
    }

    #[test]
    fn parse_efi_dmesg_wrong_prefix() {
        assert!(parse_efi_dmesg_filename("dmesg-erst-1234567890").is_none());
    }

    #[test]
    fn is_encrypted_dmesg_check() {
        assert!(is_encrypted_dmesg("dmesg-efi-12345.enc.z"));
        assert!(!is_encrypted_dmesg("dmesg-efi-12345"));
    }

    #[test]
    fn entry_list_sort() {
        let mut list = PStoreList::new();
        list.push(PStoreEntry::new("dmesg-efi-002", vec![]));
        list.push(PStoreEntry::new("dmesg-efi-001", vec![]));
        list.push(PStoreEntry::new("dmesg-efi-003", vec![]));
        list.sort();
        assert_eq!(list.entries[0].filename, "dmesg-efi-001");
        assert_eq!(list.entries[1].filename, "dmesg-efi-002");
        assert_eq!(list.entries[2].filename, "dmesg-efi-003");
    }

    #[test]
    fn entry_list_len_and_empty() {
        let mut list = PStoreList::new();
        assert!(list.is_empty());
        list.push(PStoreEntry::new("test", vec![]));
        assert_eq!(list.len(), 1);
        assert!(!list.is_empty());
    }
}
