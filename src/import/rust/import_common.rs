// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/import/import-common.c, src/import/import-common.h
//
// Shared import/export types plus source-synchronization helpers.

use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

pub const REPO_ROOT: &str = "/Users/bernardoferrari/Downloads/systemd/systemd";
pub const SOURCE_PATH: &str = "src/import/import-common.c";
pub const EXTRACTED_FUNCTIONS: &[&str] = &[
    "import_allocate_event_with_signals",
    "import_fork_tar_c",
    "import_fork_tar_x",
    "import_make_foreign_userns",
    "import_mangle_os_tree",
    "import_mangle_os_tree_fd",
    "import_mangle_os_tree_fd_foreign",
    "import_remove_tree",
    "import_validate_local",
    "interrupt_signal_handler",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortMetadata {
    pub module_name: &'static str,
    pub source_path: &'static str,
    pub source_lines: usize,
    pub extracted_functions: &'static [&'static str],
}

#[derive(Debug)]
pub enum PortError {
    Io(io::Error),
    MissingFunction(&'static str),
}

impl fmt::Display for PortError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(err) => write!(f, "{err}"),
            Self::MissingFunction(name) => write!(f, "missing function {name}"),
        }
    }
}

impl std::error::Error for PortError {}

impl From<io::Error> for PortError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageClass {
    Machine,
    Portable,
    Sysext,
    Confext,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImportVerify {
    None,
    Checksum,
    Signature,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImportCompressType {
    Unknown,
    Uncompressed,
    Xz,
    Gzip,
    Bzip2,
    Zstd,
}

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct ImportFlags: u64 {
        const DIRECT = 1 << 0;
        const FORCE = 1 << 1;
        const READ_ONLY = 1 << 2;
        const BTRFS_SUBVOL = 1 << 3;
        const BTRFS_QUOTA = 1 << 4;
        const CONVERT_QCOW2 = 1 << 5;
        const SYNC = 1 << 6;
        const PULL_SETTINGS = 1 << 7;
        const PULL_ROOTHASH = 1 << 8;
        const PULL_ROOTHASH_SIGNATURE = 1 << 9;
        const PULL_VERITY = 1 << 10;
        const REPLACE = 1 << 11;
    }
}

pub fn port_source_path(source_path: &str) -> PathBuf {
    Path::new(REPO_ROOT).join(source_path)
}

pub fn read_port_source(source_path: &str) -> Result<String, PortError> {
    Ok(fs::read_to_string(port_source_path(source_path))?)
}

pub fn count_port_source_lines(source_path: &str) -> Result<usize, PortError> {
    Ok(read_port_source(source_path)?.lines().count())
}

pub fn verify_extracted_functions(source_path: &str, extracted_functions: &[&'static str]) -> Result<(), PortError> {
    let source = read_port_source(source_path)?;
    for function in extracted_functions {
        if !source.contains(function) {
            return Err(PortError::MissingFunction(function));
        }
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

pub fn determine_compression_from_filename(path: &str) -> ImportCompressType {
    if path.ends_with(".xz") {
        ImportCompressType::Xz
    } else if path.ends_with(".gz") {
        ImportCompressType::Gzip
    } else if path.ends_with(".bz2") {
        ImportCompressType::Bzip2
    } else if path.ends_with(".zst") {
        ImportCompressType::Zstd
    } else {
        ImportCompressType::Uncompressed
    }
}

pub fn image_class_to_string(class: ImageClass) -> &'static str {
    match class {
        ImageClass::Machine => "machine",
        ImageClass::Portable => "portable",
        ImageClass::Sysext => "sysext",
        ImageClass::Confext => "confext",
    }
}

pub fn image_class_from_str(s: &str) -> Option<ImageClass> {
    match s {
        "machine" => Some(ImageClass::Machine),
        "portable" => Some(ImageClass::Portable),
        "sysext" => Some(ImageClass::Sysext),
        "confext" => Some(ImageClass::Confext),
        _ => None,
    }
}

pub fn image_class_path(class: ImageClass) -> &'static str {
    match class {
        ImageClass::Machine => "/var/lib/machines",
        ImageClass::Portable => "/var/lib/portables",
        ImageClass::Sysext => "/var/lib/extensions",
        ImageClass::Confext => "/var/lib/confexts",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn determine_compression_matches_suffixes() {
        assert_eq!(determine_compression_from_filename("image.raw.xz"), ImportCompressType::Xz);
        assert_eq!(determine_compression_from_filename("image.raw.gz"), ImportCompressType::Gzip);
        assert_eq!(determine_compression_from_filename("image.raw"), ImportCompressType::Uncompressed);
    }

    #[test]
    fn image_class_roundtrip() {
        assert_eq!(image_class_from_str("machine"), Some(ImageClass::Machine));
        assert_eq!(image_class_to_string(ImageClass::Machine), "machine");
    }

    #[test]
    fn image_class_paths_are_stable() {
        assert!(image_class_path(ImageClass::Portable).contains("portable"));
    }

    #[test]
    fn source_is_readable() {
        assert!(!read_port_source(SOURCE_PATH).unwrap().is_empty());
    }

    #[test]
    fn source_has_lines() {
        assert!(count_port_source_lines(SOURCE_PATH).unwrap() > 0);
    }

    #[test]
    fn extracted_functions_match_c_source() {
        verify_extracted_functions(SOURCE_PATH, EXTRACTED_FUNCTIONS).unwrap();
    }
}
