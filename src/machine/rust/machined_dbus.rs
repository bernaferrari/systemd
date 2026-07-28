// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/machine/machined-dbus.c
//
// Safe Rust synchronization metadata for the matching machine module.

use crate::common::{
    Errno, PortMetadata, count_port_source_lines, read_port_source, verify_extracted_functions,
};

pub const SOURCE_PATH: &str = "src/machine/machined-dbus.c";
pub const EXTRACTED_FUNCTIONS: &[&str] = &[
    "clean_pool_done",
    "machine_add_from_params",
    "manager_job_is_active",
    "manager_kill_unit",
    "manager_stop_unit",
    "manager_unit_is_active",
    "manager_unref_unit",
    "match_job_removed",
    "match_properties_changed",
    "match_reloading",
    "match_unit_removed",
    "method_bind_mount_machine",
    "method_clean_pool",
    "method_clone_image",
    "method_copy_machine",
    "method_create_machine",
    "method_create_or_register_machine",
    "method_create_or_register_machine_ex",
    "method_get_image",
    "method_get_image_hostname",
    "method_get_image_machine_id",
    "method_get_image_machine_info",
    "method_get_image_os_release",
    "method_get_machine",
    "method_get_machine_addresses",
    "method_get_machine_by_pid",
    "method_get_machine_os_release",
    "method_get_machine_ssh_info",
    "method_get_machine_uid_shift",
    "method_kill_machine",
    "method_list_images",
    "method_list_machines",
    "method_map_from_machine_group",
    "method_map_from_machine_user",
    "method_map_to_machine_group",
    "method_map_to_machine_user",
    "method_mark_image_read_only",
    "method_open_machine_login",
    "method_open_machine_pty",
    "method_open_machine_root_directory",
    "method_open_machine_shell",
    "method_register_machine",
    "method_remove_image",
    "method_rename_image",
    "method_set_image_limit",
    "method_set_pool_limit",
    "method_terminate_machine",
    "method_unregister_machine",
    "property_get_pool_limit",
    "property_get_pool_path",
    "property_get_pool_usage",
    "redirect_method_to_image",
    "redirect_method_to_machine",
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
