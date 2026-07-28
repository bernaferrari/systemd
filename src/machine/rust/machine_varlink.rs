// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/machine/machine-varlink.c
//
// Safe Rust synchronization metadata for the matching machine module.

use crate::common::{
    Errno, PortMetadata, count_port_source_lines, read_port_source, verify_extracted_functions,
};

pub const SOURCE_PATH: &str = "src/machine/machine-varlink.c";
pub const EXTRACTED_FUNCTIONS: &[&str] = &[
    "copy_done",
    "lookup_machine_by_name",
    "lookup_machine_by_name_or_pidref",
    "lookup_machine_by_pidref",
    "machine_cid",
    "machine_copy_paramaters_done",
    "machine_ifindices",
    "machine_kill_paramaters_done",
    "machine_map_paramaters_done",
    "machine_mount_paramaters_done",
    "machine_name",
    "machine_open_paramaters_done",
    "machine_open_polkit_action",
    "machine_open_polkit_details",
    "machine_pidref",
    "vl_method_bind_mount",
    "vl_method_copy_internal",
    "vl_method_kill",
    "vl_method_map_from",
    "vl_method_map_to",
    "vl_method_open",
    "vl_method_open_root_directory_internal",
    "vl_method_register",
    "vl_method_terminate_internal",
    "vl_method_unregister_internal",
];

pub fn metadata() -> Result<PortMetadata, Errno> {
    Ok(PortMetadata {
        module_name: module_path!(),
        source_path: SOURCE_PATH,
        source_lines: count_port_source_lines(SOURCE_PATH)?,
        extracted_functions: EXTRACTED_FUNCTIONS,
    })
}

pub fn read_source() -> Result<String, Errno> {
    read_port_source(SOURCE_PATH)
}

pub fn source_lines() -> Result<usize, Errno> {
    count_port_source_lines(SOURCE_PATH)
}

pub fn has_function(name: &str) -> bool {
    EXTRACTED_FUNCTIONS.contains(&name)
}

pub fn verify_port_sync() -> Result<(), Errno> {
    verify_extracted_functions(SOURCE_PATH, EXTRACTED_FUNCTIONS)
}
