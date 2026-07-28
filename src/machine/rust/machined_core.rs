// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/machine/machined-core.c
//
// Safe Rust synchronization metadata for the matching machine module.

use crate::common::{
    Errno, PortMetadata, count_port_source_lines, read_port_source, verify_extracted_functions,
};

pub const SOURCE_PATH: &str = "src/machine/machined-core.c";
pub const EXTRACTED_FUNCTIONS: &[&str] = &[
    "image_flush_cache",
    "machine_get_addresses",
    "machine_get_os_release",
    "manager_acquire_image",
    "manager_add_machine",
    "manager_enqueue_gc",
    "manager_find_machine_for_gid",
    "manager_find_machine_for_uid",
    "manager_gc",
    "manager_get_machine_by_pidref",
    "on_deferred_gc",
    "rename_image_and_update_cache",
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
