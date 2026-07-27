// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/import/pull-job.c
//
// Safe Rust synchronization metadata for the matching import module.

use crate::import_common::{count_port_source_lines, read_port_source, verify_extracted_functions, PortError, PortMetadata};

pub const SOURCE_PATH: &str = "src/import/pull-job.c";
pub const EXTRACTED_FUNCTIONS: &[&str] = &[
    "http_status_etag_exists",
    "http_status_need_authentication",
    "http_status_ok",
    "pull_job_add_request_header",
    "pull_job_begin",
    "pull_job_close_disk_fd",
    "pull_job_content_length_effective",
    "pull_job_curl_on_finished",
    "pull_job_description",
    "pull_job_detect_compression",
    "pull_job_finish",
    "pull_job_header_callback",
    "pull_job_new",
    "pull_job_open_disk",
    "pull_job_progress_callback",
    "pull_job_restart",
    "pull_job_set_accept",
    "pull_job_set_bearer_token",
    "pull_job_unref",
    "pull_job_write_callback",
    "pull_job_write_compressed",
    "pull_job_write_uncompressed"
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
