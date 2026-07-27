// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/machine/image-varlink.c
//
// Safe Rust synchronization metadata for the matching machine module.

use crate::common::{count_port_source_lines, read_port_source, verify_extracted_functions, Errno, PortMetadata};

pub const SOURCE_PATH: &str = "src/machine/image-varlink.c";
pub const EXTRACTED_FUNCTIONS: &[&str] = &[
    "clean_pool_done",
    "clean_pool_done_internal",
    "clean_pool_list_one_image",
    "vl_method_clean_pool",
    "vl_method_clone_image",
    "vl_method_remove_image",
    "vl_method_set_pool_limit",
    "vl_method_update_image"
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
