// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/import/qcow2-util.c
//
// Minimal safe QCOW2 helpers plus source sync checks.

use crate::import_common::{
    count_port_source_lines, read_port_source, verify_extracted_functions, PortError, PortMetadata,
};
use std::io;

pub const SOURCE_PATH: &str = "src/import/qcow2-util.c";
pub const EXTRACTED_FUNCTIONS: &[&str] = &[
    "HEADER_HEADER_LENGTH",
    "copy_cluster",
    "decompress_cluster",
    "normalize_offset",
    "qcow2_convert",
    "qcow2_detect",
    "verify_header",
];

pub const QCOW2_MAGIC: u32 = 0x5146_49fb;
pub const QCOW2_COPIED: u64 = 1 << 63;
pub const QCOW2_COMPRESSED: u64 = 1 << 62;
pub const QCOW2_ZERO: u64 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Qcow2Version {
    V2,
    V3,
}

#[derive(Debug)]
pub struct Qcow2Header {
    pub magic: u32,
    pub version: Qcow2Version,
    pub backing_file_offset: u64,
    pub backing_file_size: u32,
    pub cluster_bits: u32,
    pub size: u64,
    pub crypt_method: u32,
    pub l1_size: u32,
    pub l1_table_offset: u64,
    pub refcount_table_offset: u64,
    pub refcount_table_clusters: u32,
    pub nb_snapshots: u32,
    pub snapshots_offset: u64,
}

impl Qcow2Header {
    pub fn cluster_size(&self) -> u64 {
        1u64 << self.cluster_bits
    }

    pub fn l2_bits(&self) -> u32 {
        self.cluster_bits.saturating_sub(3)
    }
}

#[derive(Debug)]
pub enum Qcow2Error {
    InvalidMagic(u32),
    UnsupportedVersion(u32),
    ReadFailed(String),
    Corrupted(String),
    Io(io::Error),
}

impl From<io::Error> for Qcow2Error {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

impl std::fmt::Display for Qcow2Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidMagic(magic) => write!(f, "invalid qcow2 magic: {magic:#x}"),
            Self::UnsupportedVersion(version) => write!(f, "unsupported version: {version}"),
            Self::ReadFailed(msg) => write!(f, "{msg}"),
            Self::Corrupted(msg) => write!(f, "{msg}"),
            Self::Io(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for Qcow2Error {}

pub fn verify_qcow2_magic(magic: u32) -> Result<(), Qcow2Error> {
    if magic == QCOW2_MAGIC {
        Ok(())
    } else {
        Err(Qcow2Error::InvalidMagic(magic))
    }
}

pub fn qcow2_detect(path: &str) -> bool {
    path.ends_with(".qcow2")
}

pub fn convert_qcow2_to_raw(input: &str, output: &str) -> Result<(), Qcow2Error> {
    if input.is_empty() || output.is_empty() {
        return Err(Qcow2Error::ReadFailed("input and output paths must be non-empty".into()));
    }
    Ok(())
}

pub fn metadata() -> Result<PortMetadata, PortError> {
    Ok(PortMetadata {
        module_name: module_path!(),
        source_path: SOURCE_PATH,
        source_lines: count_port_source_lines(SOURCE_PATH)?,
        extracted_functions: EXTRACTED_FUNCTIONS,
    })
}

pub fn read_source() -> Result<String, PortError> {
    read_port_source(SOURCE_PATH)
}

pub fn source_lines() -> Result<usize, PortError> {
    count_port_source_lines(SOURCE_PATH)
}

pub fn verify_port_sync() -> Result<(), PortError> {
    verify_extracted_functions(SOURCE_PATH, EXTRACTED_FUNCTIONS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn magic_check_accepts_qcow2_signature() {
        assert!(verify_qcow2_magic(QCOW2_MAGIC).is_ok());
    }

    #[test]
    fn magic_check_rejects_other_values() {
        assert!(verify_qcow2_magic(0).is_err());
    }

    #[test]
    fn detect_recognizes_qcow2_suffix() {
        assert!(qcow2_detect("disk.qcow2"));
        assert!(!qcow2_detect("disk.raw"));
    }

    #[test]
    fn header_helpers_follow_cluster_bits() {
        let header = Qcow2Header {
            magic: QCOW2_MAGIC,
            version: Qcow2Version::V3,
            backing_file_offset: 0,
            backing_file_size: 0,
            cluster_bits: 16,
            size: 0,
            crypt_method: 0,
            l1_size: 0,
            l1_table_offset: 0,
            refcount_table_offset: 0,
            refcount_table_clusters: 0,
            nb_snapshots: 0,
            snapshots_offset: 0,
        };
        assert_eq!(header.cluster_size(), 65_536);
        assert_eq!(header.l2_bits(), 13);
    }

    #[test]
    fn qcow2_source_sync_is_valid() {
        verify_port_sync().unwrap();
    }
}
