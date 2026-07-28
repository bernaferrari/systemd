// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/machine/machinectl.c
//
// Safe Rust synchronization metadata for the matching machine module.

use crate::common::{
    Errno, PortMetadata, count_port_source_lines, read_port_source, verify_extracted_functions,
};

pub const SOURCE_PATH: &str = "src/machine/machinectl.c";
pub const EXTRACTED_FUNCTIONS: &[&str] = &[
    "call_get_addresses",
    "call_get_os_release",
    "chainload_importctl",
    "get_output_flags",
    "get_settings_path",
    "help",
    "image_exists",
    "machine_status_info_done",
    "machinectl_main",
    "make_service_name",
    "map_netif",
    "normalize_nspawn_filename",
    "on_machine_removed",
    "parse_argv",
    "parse_machine_uid",
    "print_image_hostname",
    "print_image_machine_id",
    "print_image_machine_info",
    "print_image_status_info",
    "print_machine_status_info",
    "print_os_release",
    "print_pool_status_info",
    "print_process_info",
    "print_uid_shift",
    "process_forward",
    "run",
    "select_copy_method",
    "show_image_info",
    "show_image_properties",
    "show_machine_info",
    "show_machine_properties",
    "show_pool_info",
    "show_table",
    "show_unit_cgroup",
    "verb_bind_mount",
    "verb_cat_settings",
    "verb_clean_images",
    "verb_clone_image",
    "verb_copy_files",
    "verb_edit_settings",
    "verb_enable_machine",
    "verb_help",
    "verb_kill_machine",
    "verb_list_images",
    "verb_list_machines",
    "verb_login_machine",
    "verb_poweroff_machine",
    "verb_read_only_image",
    "verb_reboot_machine",
    "verb_remove_image",
    "verb_rename_image",
    "verb_set_limit",
    "verb_shell_machine",
    "verb_show_image",
    "verb_show_machine",
    "verb_start_machine",
    "verb_terminate_machine",
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
