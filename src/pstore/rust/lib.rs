// SPDX-License-Identifier: LGPL-2.1-or-later
#![deny(unsafe_op_in_unsafe_fn)]
//
// PORT-SYNC: src/pstore/pstore.c
pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    InvalidStorage(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidStorage(value) => write!(f, "invalid pstore storage {value:?}"),
        }
    }
}

impl std::error::Error for Error {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PStoreStorage {
    None,
    External,
    Journal,
}

impl PStoreStorage {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::External => "external",
            Self::Journal => "journal",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    Dmesg,
    DmesgChunk,
    Pmsg,
    Ftrace,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PStoreEntry {
    pub filename: String,
    pub handled: bool,
    pub content: Vec<u8>,
}

pub fn parse_pstore_storage(value: &str) -> Result<PStoreStorage> {
    match value {
        "none" => Ok(PStoreStorage::None),
        "external" => Ok(PStoreStorage::External),
        "journal" => Ok(PStoreStorage::Journal),
        other => Err(Error::InvalidStorage(other.to_string())),
    }
}

pub fn classify_entry(filename: &str) -> EntryKind {
    if filename.starts_with("dmesg-") {
        if filename.contains("efi-") || filename.contains("efi_pstore-") {
            EntryKind::DmesgChunk
        } else {
            EntryKind::Dmesg
        }
    } else if filename.contains("pmsg") {
        EntryKind::Pmsg
    } else if filename.contains("ftrace") {
        EntryKind::Ftrace
    } else {
        EntryKind::Other
    }
}

pub fn is_binary(data: &[u8]) -> bool {
    data.iter()
        .any(|byte| *byte == 0 || (!byte.is_ascii_graphic() && !byte.is_ascii_whitespace()))
}

pub fn sort_entries(entries: &mut [PStoreEntry]) {
    entries.sort_by(|a, b| a.filename.cmp(&b.filename));
}

pub fn archive_path(archive_dir: &str, subdir1: &str, subdir2: &str, filename: &str) -> String {
    format!(
        "{}/{}/{}/{}",
        archive_dir.trim_end_matches('/'),
        subdir1,
        subdir2,
        filename
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_storage_accepts_all_known_values() {
        assert_eq!(parse_pstore_storage("none").unwrap(), PStoreStorage::None);
        assert_eq!(
            parse_pstore_storage("external").unwrap(),
            PStoreStorage::External
        );
        assert_eq!(
            parse_pstore_storage("journal").unwrap(),
            PStoreStorage::Journal
        );
    }

    #[test]
    fn parse_storage_rejects_unknown_values() {
        assert_eq!(
            parse_pstore_storage("both"),
            Err(Error::InvalidStorage("both".to_string()))
        );
    }

    #[test]
    fn storage_string_round_trips() {
        assert_eq!(PStoreStorage::External.as_str(), "external");
    }

    #[test]
    fn classify_entry_detects_efi_chunks() {
        assert_eq!(classify_entry("dmesg-efi-12345"), EntryKind::DmesgChunk);
    }

    #[test]
    fn classify_entry_detects_regular_kinds() {
        assert_eq!(classify_entry("dmesg-1"), EntryKind::Dmesg);
        assert_eq!(classify_entry("console-pmsg-0"), EntryKind::Pmsg);
        assert_eq!(classify_entry("ftrace-ramoops-0"), EntryKind::Ftrace);
    }

    #[test]
    fn is_binary_detects_nul_bytes() {
        assert!(is_binary(b"abc\0def"));
    }

    #[test]
    fn is_binary_allows_text() {
        assert!(!is_binary(b"kernel panic\n"));
    }

    #[test]
    fn sort_entries_orders_lexicographically() {
        let mut entries = vec![
            PStoreEntry {
                filename: "z".into(),
                handled: false,
                content: vec![],
            },
            PStoreEntry {
                filename: "a".into(),
                handled: false,
                content: vec![],
            },
        ];
        sort_entries(&mut entries);
        assert_eq!(entries[0].filename, "a");
    }

    #[test]
    fn archive_path_joins_all_segments() {
        assert_eq!(
            archive_path("/var/lib/systemd/pstore", "2026", "efi", "dmesg-1"),
            "/var/lib/systemd/pstore/2026/efi/dmesg-1"
        );
    }
}
