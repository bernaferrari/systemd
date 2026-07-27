// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/machine/image-dbus.c
//
// Safe Rust synchronization metadata for the matching machine module.

use crate::common::{count_port_source_lines, read_port_source, verify_extracted_functions, Errno, PortMetadata};

pub const SOURCE_PATH: &str = "src/machine/image-dbus.c";
pub const EXTRACTED_FUNCTIONS: &[&str] = &[
    "bus_image_method_clone",
    "bus_image_method_get_hostname",
    "bus_image_method_get_machine_id",
    "bus_image_method_get_machine_info",
    "bus_image_method_get_os_release",
    "bus_image_method_mark_read_only",
    "bus_image_method_remove",
    "bus_image_method_rename",
    "bus_image_method_set_limit",
    "image_bus_path",
    "image_node_enumerator",
    "image_object_find"
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
