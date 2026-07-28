// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/import/pull-tar.c
//
// Safe Rust synchronization metadata for the matching import module.

use crate::import_common::{
    PortError, PortMetadata, count_port_source_lines, read_port_source, verify_extracted_functions,
};

pub const SOURCE_PATH: &str = "src/import/pull-tar.c";
pub const EXTRACTED_FUNCTIONS: &[&str] = &[
    "tar_pull_determine_path",
    "tar_pull_is_done",
    "tar_pull_job_on_finished",
    "tar_pull_job_on_open_disk_settings",
    "tar_pull_job_on_open_disk_tar",
    "tar_pull_job_on_progress",
    "tar_pull_make_local_copy",
    "tar_pull_new",
    "tar_pull_report_progress",
    "tar_pull_start",
    "tar_pull_unref",
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
