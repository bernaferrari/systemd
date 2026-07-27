// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/import/pull-raw.c
//
// Safe Rust synchronization metadata for the matching import module.

use crate::import_common::{count_port_source_lines, read_port_source, verify_extracted_functions, PortError, PortMetadata};

pub const SOURCE_PATH: &str = "src/import/pull-raw.c";
pub const EXTRACTED_FUNCTIONS: &[&str] = &[
    "raw_pull_copy_auxiliary_file",
    "raw_pull_determine_path",
    "raw_pull_is_done",
    "raw_pull_job_on_finished",
    "raw_pull_job_on_open_disk_generic",
    "raw_pull_job_on_open_disk_raw",
    "raw_pull_job_on_open_disk_roothash",
    "raw_pull_job_on_open_disk_roothash_signature",
    "raw_pull_job_on_open_disk_settings",
    "raw_pull_job_on_open_disk_verity",
    "raw_pull_job_on_progress",
    "raw_pull_make_local_copy",
    "raw_pull_maybe_convert_qcow2",
    "raw_pull_new",
    "raw_pull_rename_auxiliary_file",
    "raw_pull_report_progress",
    "raw_pull_start",
    "raw_pull_unref"
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
