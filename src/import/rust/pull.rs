// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/import/pull.c
//
// Safe Rust synchronization metadata for the matching import module.

use crate::import_common::{
    PortError, PortMetadata, count_port_source_lines, read_port_source, verify_extracted_functions,
};

pub const SOURCE_PATH: &str = "src/import/pull.c";
pub const EXTRACTED_FUNCTIONS: &[&str] = &[
    "help",
    "normalize_local",
    "on_oci_finished",
    "on_raw_finished",
    "on_tar_finished",
    "parse_argv",
    "parse_env",
    "pull_main",
    "run",
    "verb_help",
    "verb_pull_oci",
    "verb_pull_raw",
    "verb_pull_tar",
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
