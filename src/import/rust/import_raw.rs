// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/import/import-raw.c
//
// Safe Rust synchronization metadata for the matching import module.

use crate::import_common::{
    PortError, PortMetadata, count_port_source_lines, read_port_source, verify_extracted_functions,
};

pub const SOURCE_PATH: &str = "src/import/import-raw.c";
pub const EXTRACTED_FUNCTIONS: &[&str] = &[
    "raw_import_finish",
    "raw_import_maybe_convert_qcow2",
    "raw_import_new",
    "raw_import_on_defer",
    "raw_import_on_input",
    "raw_import_open_disk",
    "raw_import_process",
    "raw_import_report_progress",
    "raw_import_start",
    "raw_import_try_reflink",
    "raw_import_unref",
    "raw_import_write",
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
