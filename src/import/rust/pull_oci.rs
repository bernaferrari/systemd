// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/import/pull-oci.c
//
// Safe Rust synchronization metadata for the matching import module.

use crate::import_common::{count_port_source_lines, read_port_source, verify_extracted_functions, PortError, PortMetadata};

pub const SOURCE_PATH: &str = "src/import/pull-oci.c";
pub const EXTRACTED_FUNCTIONS: &[&str] = &[
    "dispatch_unsupported",
    "json_dispatch_oci_digest",
    "json_dispatch_oci_index_entry",
    "json_dispatch_oci_manifest_config",
    "json_dispatch_oci_manifest_layer",
    "json_dispatch_oci_platform",
    "make_bearer_token_url",
    "oci_configuration_done",
    "oci_index_entry_done",
    "oci_index_entry_match",
    "oci_layer_dirname_for_digest",
    "oci_layer_state_free",
    "oci_layer_state_free_wrapper",
    "oci_manifest_config_done",
    "oci_manifest_layer_done",
    "oci_pull_fetch_config",
    "oci_pull_fetch_layers",
    "oci_pull_finish",
    "oci_pull_is_done",
    "oci_pull_job_on_finished_bearer_token",
    "oci_pull_job_on_finished_config",
    "oci_pull_job_on_finished_layer",
    "oci_pull_job_on_finished_manifest",
    "oci_pull_job_on_open_disk",
    "oci_pull_make_local",
    "oci_pull_new",
    "oci_pull_process_authentication_challenge",
    "oci_pull_process_index",
    "oci_pull_process_manifest",
    "oci_pull_queue_layer",
    "oci_pull_redirect_manifest",
    "oci_pull_save_mstack",
    "oci_pull_save_nspawn_settings",
    "oci_pull_save_oci_config",
    "oci_pull_start",
    "oci_pull_unref",
    "oci_pull_work",
    "print_pair_escaped",
    "pull_job_payload_as_json_object"
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
