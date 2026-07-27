// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/smbios11.c

use std::fs::File;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use crate::ffi::Errno;

pub const DMI_FIELD_TYPE_OEM_STRINGS: u8 = 11;
pub const DMI_FIELD_HEADER_SIZE: usize = 5;
pub const DMI_ENTRIES_PATH: &str = "/sys/firmware/dmi/entries";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Smbios11Field {
    data: Vec<u8>,
    complete: bool,
}

impl Smbios11Field {
    pub fn new(data: Vec<u8>, complete: bool) -> Self {
        Self { data, complete }
    }

    pub fn data(&self) -> &[u8] {
        &self.data
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    pub fn is_complete(&self) -> bool {
        self.complete
    }

    pub fn into_nul_terminated_bytes(self) -> Vec<u8> {
        let mut data = self.data;
        data.push(0);
        data
    }
}

#[derive(Debug)]
pub enum Smbios11Error {
    Container,
    InvalidHeader,
    Io(io::Error),
    SizeOverflow,
}

impl Smbios11Error {
    pub fn to_neg_errno(&self) -> i32 {
        match self {
            Self::Container => Errno::ENOENT.to_neg_errno(),
            Self::InvalidHeader => Errno::EBADMSG.to_neg_errno(),
            Self::Io(error) => error
                .raw_os_error()
                .map_or(Errno::EIO.to_neg_errno(), |errno| -errno),
            Self::SizeOverflow => Errno::EOVERFLOW.to_neg_errno(),
        }
    }
}

impl std::fmt::Display for Smbios11Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Container => write!(f, "SMBIOS type 11 is unavailable in containers"),
            Self::InvalidHeader => write!(f, "invalid SMBIOS type 11 header"),
            Self::Io(error) => write!(f, "{error}"),
            Self::SizeOverflow => write!(f, "requested SMBIOS read size overflowed"),
        }
    }
}

impl std::error::Error for Smbios11Error {}

fn detect_container() -> bool {
    #[cfg(target_os = "linux")]
    {
        std::fs::read_to_string("/run/systemd/container")
            .map(|contents| !contents.trim().is_empty())
            .unwrap_or(false)
    }

    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

fn smbios11_entry_path(root: &Path, index: u32) -> PathBuf {
    root.join(format!("11-{index}/raw"))
}

fn read_limited_file(path: &Path, max_size: usize) -> Result<(Vec<u8>, bool), Smbios11Error> {
    let limit = DMI_FIELD_HEADER_SIZE
        .checked_add(max_size)
        .ok_or(Smbios11Error::SizeOverflow)?;

    let mut file = File::open(path).map_err(Smbios11Error::Io)?;
    let mut data = Vec::with_capacity(limit);
    file.by_ref()
        .take(limit as u64)
        .read_to_end(&mut data)
        .map_err(Smbios11Error::Io)?;

    if data.len() < limit {
        return Ok((data, true));
    }

    let mut probe = [0u8; 1];
    let complete = match file.read(&mut probe).map_err(Smbios11Error::Io)? {
        0 => true,
        _ => false,
    };

    Ok((data, complete))
}

fn parse_smbios11_field(raw: &[u8], complete: bool) -> Result<Smbios11Field, Smbios11Error> {
    if raw.len() < DMI_FIELD_HEADER_SIZE {
        return Err(Smbios11Error::InvalidHeader);
    }

    if raw[0] != DMI_FIELD_TYPE_OEM_STRINGS || raw[1] != DMI_FIELD_HEADER_SIZE as u8 {
        return Err(Smbios11Error::InvalidHeader);
    }

    Ok(Smbios11Field::new(
        raw[DMI_FIELD_HEADER_SIZE..].to_vec(),
        complete,
    ))
}

pub fn read_smbios11_field(index: u32, max_size: usize) -> Result<Smbios11Field, Smbios11Error> {
    if detect_container() {
        return Err(Smbios11Error::Container);
    }

    read_smbios11_field_from_sysfs_root(Path::new(DMI_ENTRIES_PATH), index, max_size)
}

pub fn read_smbios11_field_from_sysfs_root(
    root: &Path,
    index: u32,
    max_size: usize,
) -> Result<Smbios11Field, Smbios11Error> {
    let path = smbios11_entry_path(root, index);
    let (raw, complete) = read_limited_file(&path, max_size)?;
    parse_smbios11_field(&raw, complete)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    static NEXT_ID: AtomicU64 = AtomicU64::new(0);

    fn unique_temp_dir() -> PathBuf {
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time went backwards")
            .as_nanos();
        std::env::temp_dir().join(format!("systemd-smbios11-{nanos}-{id}"))
    }

    fn write_entry(root: &Path, index: u32, contents: &[u8]) -> PathBuf {
        let path = smbios11_entry_path(root, index);
        fs::create_dir_all(path.parent().expect("entry path has parent"))
            .expect("create entry directory");
        fs::write(&path, contents).expect("write entry file");
        path
    }

    fn sample_header() -> [u8; DMI_FIELD_HEADER_SIZE] {
        [
            DMI_FIELD_TYPE_OEM_STRINGS,
            DMI_FIELD_HEADER_SIZE as u8,
            0,
            0,
            1,
        ]
    }

    #[test]
    fn constant_values_match_c_layout() {
        assert_eq!(DMI_FIELD_TYPE_OEM_STRINGS, 11);
        assert_eq!(DMI_FIELD_HEADER_SIZE, 5);
        assert_eq!(DMI_ENTRIES_PATH, "/sys/firmware/dmi/entries");
    }

    #[test]
    fn entry_path_matches_c_format() {
        let path = smbios11_entry_path(Path::new("/sys/firmware/dmi/entries"), 7);
        assert_eq!(path, Path::new("/sys/firmware/dmi/entries/11-7/raw"));
    }

    #[test]
    fn parse_valid_field_preserves_payload() {
        let mut raw = sample_header().to_vec();
        raw.extend_from_slice(b"hello");

        let field = parse_smbios11_field(&raw, true).expect("field should parse");

        assert_eq!(field.data(), b"hello");
        assert_eq!(field.len(), 5);
        assert!(field.is_complete());
    }

    #[test]
    fn parse_valid_field_allows_empty_payload() {
        let raw = sample_header();
        let field = parse_smbios11_field(&raw, true).expect("field should parse");

        assert!(field.is_empty());
        assert!(field.is_complete());
    }

    #[test]
    fn parse_rejects_short_header() {
        let error = parse_smbios11_field(&[11, 5, 0, 0], true).expect_err("must fail");
        assert!(matches!(error, Smbios11Error::InvalidHeader));
    }

    #[test]
    fn parse_rejects_wrong_type() {
        let error = parse_smbios11_field(&[10, 5, 0, 0, 0, b'x'], true).expect_err("must fail");
        assert!(matches!(error, Smbios11Error::InvalidHeader));
    }

    #[test]
    fn parse_rejects_wrong_length() {
        let error = parse_smbios11_field(&[11, 4, 0, 0, 0, b'x'], true).expect_err("must fail");
        assert!(matches!(error, Smbios11Error::InvalidHeader));
    }

    #[test]
    fn nul_termination_matches_memdup_suffix0_behavior() {
        let bytes = Smbios11Field::new(b"abc".to_vec(), true).into_nul_terminated_bytes();
        assert_eq!(bytes, b"abc\0");
    }

    #[test]
    fn read_limited_file_reports_complete_when_shorter_than_limit() {
        let root = unique_temp_dir();
        fs::create_dir_all(&root).expect("create temp dir");
        let path = root.join("raw");
        fs::write(&path, b"abcdef").expect("write file");

        let (raw, complete) = read_limited_file(&path, 64).expect("read should succeed");

        assert_eq!(raw, b"abcdef");
        assert!(complete);

        fs::remove_dir_all(&root).expect("remove temp dir");
    }

    #[test]
    fn read_limited_file_reports_complete_when_exactly_at_limit() {
        let root = unique_temp_dir();
        fs::create_dir_all(&root).expect("create temp dir");
        let path = root.join("raw");
        fs::write(&path, b"abcdefgh").expect("write file");

        let (raw, complete) = read_limited_file(&path, 3).expect("read should succeed");

        assert_eq!(raw, b"abcdefgh");
        assert!(complete);

        fs::remove_dir_all(&root).expect("remove temp dir");
    }

    #[test]
    fn read_limited_file_truncates_and_marks_incomplete() {
        let root = unique_temp_dir();
        fs::create_dir_all(&root).expect("create temp dir");
        let path = root.join("raw");
        fs::write(&path, b"abcdefghi").expect("write file");

        let (raw, complete) = read_limited_file(&path, 3).expect("read should succeed");

        assert_eq!(raw, b"abcdefgh");
        assert!(!complete);

        fs::remove_dir_all(&root).expect("remove temp dir");
    }

    #[test]
    fn read_from_sysfs_root_reads_complete_entry() {
        let root = unique_temp_dir();
        let mut raw = sample_header().to_vec();
        raw.extend_from_slice(b"payload");
        write_entry(&root, 3, &raw);

        let field = read_smbios11_field_from_sysfs_root(&root, 3, 64).expect("read should work");

        assert_eq!(field.data(), b"payload");
        assert!(field.is_complete());

        fs::remove_dir_all(&root).expect("remove temp dir");
    }

    #[test]
    fn read_from_sysfs_root_marks_truncated_entry_incomplete() {
        let root = unique_temp_dir();
        let mut raw = sample_header().to_vec();
        raw.extend_from_slice(b"payload");
        write_entry(&root, 9, &raw);

        let field = read_smbios11_field_from_sysfs_root(&root, 9, 3).expect("read should work");

        assert_eq!(field.data(), b"pay");
        assert!(!field.is_complete());

        fs::remove_dir_all(&root).expect("remove temp dir");
    }

    #[test]
    fn read_from_sysfs_root_returns_not_found_errno_for_missing_file() {
        let root = unique_temp_dir();
        fs::create_dir_all(&root).expect("create temp dir");

        let error = read_smbios11_field_from_sysfs_root(&root, 42, 64).expect_err("must fail");

        assert_eq!(error.to_neg_errno(), Errno::ENOENT.to_neg_errno());

        fs::remove_dir_all(&root).expect("remove temp dir");
    }

    #[test]
    fn read_from_sysfs_root_rejects_invalid_header() {
        let root = unique_temp_dir();
        write_entry(&root, 5, &[99, 5, 0, 0, 0, b'x']);

        let error = read_smbios11_field_from_sysfs_root(&root, 5, 64).expect_err("must fail");

        assert_eq!(error.to_neg_errno(), Errno::EBADMSG.to_neg_errno());

        fs::remove_dir_all(&root).expect("remove temp dir");
    }

    #[test]
    fn size_overflow_maps_to_eoverflow() {
        let root = unique_temp_dir();
        let error =
            read_smbios11_field_from_sysfs_root(&root, 1, usize::MAX).expect_err("must fail");
        assert_eq!(error.to_neg_errno(), Errno::EOVERFLOW.to_neg_errno());
    }

    #[test]
    fn container_error_maps_to_enoent() {
        assert_eq!(
            Smbios11Error::Container.to_neg_errno(),
            Errno::ENOENT.to_neg_errno()
        );
    }

    #[test]
    fn detect_container_is_side_effect_free() {
        let _ = detect_container();
    }

    #[test]
    fn io_error_from_kind_creates_requested_kind() {
        let error = io::Error::from(io::ErrorKind::NotFound);
        assert_eq!(error.kind(), io::ErrorKind::NotFound);
    }
}
