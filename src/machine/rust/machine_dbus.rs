// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/machine/machine-dbus.c
//
// Safe Rust synchronization metadata for the matching machine module.

use crate::common::{count_port_source_lines, read_port_source, verify_extracted_functions, Errno, PortMetadata};

pub const SOURCE_PATH: &str = "src/machine/machine-dbus.c";
pub const EXTRACTED_FUNCTIONS: &[&str] = &[
    "bus_machine_method_bind_mount",
    "bus_machine_method_copy",
    "bus_machine_method_get_addresses",
    "bus_machine_method_get_os_release",
    "bus_machine_method_get_ssh_info",
    "bus_machine_method_get_uid_shift",
    "bus_machine_method_kill",
    "bus_machine_method_open_login",
    "bus_machine_method_open_pty",
    "bus_machine_method_open_root_directory",
    "bus_machine_method_open_shell",
    "bus_machine_method_terminate",
    "bus_machine_method_unregister",
    "machine_bus_path",
    "machine_node_enumerator",
    "machine_object_find",
    "machine_send_create_reply",
    "machine_send_signal",
    "property_get_netif"
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
