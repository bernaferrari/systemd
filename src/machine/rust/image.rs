// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/machine/image.c
//
// Safe Rust synchronization metadata for the matching machine module.

use crate::common::{count_port_source_lines, read_port_source, verify_extracted_functions, Errno, PortMetadata};

pub const SOURCE_PATH: &str = "src/machine/image.c";
pub const EXTRACTED_FUNCTIONS: &[&str] = &[
    "clean_pool_read_first_entry",
    "clean_pool_read_next_entry",
    "image_clean_pool_operation"
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
