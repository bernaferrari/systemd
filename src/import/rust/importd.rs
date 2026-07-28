// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/import/importd.c
//
// Safe Rust synchronization metadata for the matching import module.

use crate::import_common::{
    PortError, PortMetadata, count_port_source_lines, read_port_source, verify_extracted_functions,
};

pub const SOURCE_PATH: &str = "src/import/importd.c";
pub const EXTRACTED_FUNCTIONS: &[&str] = &[
    "make_transfer_json",
    "manager_check_idle",
    "manager_connect_bus",
    "manager_connect_varlink",
    "manager_find",
    "manager_new",
    "manager_on_notify",
    "manager_parse_env",
    "manager_unref",
    "method_cancel",
    "method_cancel_transfer",
    "method_export_tar_or_raw",
    "method_import_fs",
    "method_import_tar_or_raw",
    "method_list_images",
    "method_list_transfers",
    "method_pull_tar_or_raw_or_oci",
    "property_get_progress",
    "run",
    "transfer_cancel",
    "transfer_finalize",
    "transfer_new",
    "transfer_node_enumerator",
    "transfer_object_find",
    "transfer_on_log",
    "transfer_on_pid",
    "transfer_percent_as_double",
    "transfer_send_log_line",
    "transfer_send_logs",
    "transfer_send_progress_update",
    "transfer_start",
    "transfer_unref",
    "vl_method_list_transfers",
    "vl_method_pull",
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
