// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/machine/machined-varlink.c
//
// Safe Rust synchronization metadata for the matching machine module.

use crate::common::{count_port_source_lines, read_port_source, verify_extracted_functions, Errno, PortMetadata};

pub const SOURCE_PATH: &str = "src/machine/machined-varlink.c";
pub const EXTRACTED_FUNCTIONS: &[&str] = &[
    "build_group_json",
    "build_user_json",
    "group_lookup_gid",
    "group_lookup_name",
    "group_match_lookup_parameters",
    "json_build_local_addresses",
    "list_image_one_and_maybe_read_metadata",
    "list_machine_one_and_maybe_read_metadata",
    "lookup_machine_and_call_method",
    "machine_lookup_parameters_done",
    "manager_varlink_done",
    "manager_varlink_init",
    "manager_varlink_init_machine",
    "manager_varlink_init_resolve_hook",
    "manager_varlink_init_userdb",
    "on_resolve_hook_disconnect",
    "user_lookup_name",
    "user_lookup_uid",
    "user_match_lookup_parameters",
    "vl_method_copy_from",
    "vl_method_copy_to",
    "vl_method_get_group_record",
    "vl_method_get_memberships",
    "vl_method_get_user_record",
    "vl_method_list",
    "vl_method_list_images",
    "vl_method_open_root_directory",
    "vl_method_terminate",
    "vl_method_unregister"
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
