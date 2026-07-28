// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/import/import-tar.c
//
// Safe Rust synchronization metadata for the matching import module.

use crate::import_common::{
    PortError, PortMetadata, count_port_source_lines, read_port_source, verify_extracted_functions,
};

pub const SOURCE_PATH: &str = "src/import/import-tar.c";
pub const EXTRACTED_FUNCTIONS: &[&str] = &[
    "tar_import_finish",
    "tar_import_fork_tar",
    "tar_import_new",
    "tar_import_on_defer",
    "tar_import_on_input",
    "tar_import_process",
    "tar_import_report_progress",
    "tar_import_start",
    "tar_import_unref",
    "tar_import_write",
];

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

pub fn has_function(name: &str) -> bool {
    EXTRACTED_FUNCTIONS.contains(&name)
}

pub fn verify_port_sync() -> Result<(), PortError> {
    verify_extracted_functions(SOURCE_PATH, EXTRACTED_FUNCTIONS)
}
