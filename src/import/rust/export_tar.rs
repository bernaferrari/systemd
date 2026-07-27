// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/import/export-tar.c
//
// Safe Rust synchronization metadata for the matching import module.

use crate::import_common::{count_port_source_lines, read_port_source, verify_extracted_functions, PortError, PortMetadata};

pub const SOURCE_PATH: &str = "src/import/export-tar.c";
pub const EXTRACTED_FUNCTIONS: &[&str] = &[
    "tar_export_finish",
    "tar_export_new",
    "tar_export_on_defer",
    "tar_export_on_output",
    "tar_export_process",
    "tar_export_report_progress",
    "tar_export_start",
    "tar_export_unref"
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
