// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/import/import-compress.c
//
// Safe Rust synchronization metadata for the matching import module.

use crate::import_common::{
    PortError, PortMetadata, count_port_source_lines, read_port_source, verify_extracted_functions,
};

pub const SOURCE_PATH: &str = "src/import/import-compress.c";
pub const EXTRACTED_FUNCTIONS: &[&str] = &[
    "enlarge_buffer",
    "import_compress",
    "import_compress_finish",
    "import_compress_free",
    "import_compress_init",
    "import_uncompress",
    "import_uncompress_detect",
    "import_uncompress_force_off",
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
