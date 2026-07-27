// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/import/test-tar.c

use crate::import_common::{count_port_source_lines, read_port_source, verify_extracted_functions, PortError, PortMetadata};

pub const SOURCE_PATH: &str = "src/import/test-tar.c";
pub const EXTRACTED_FUNCTIONS: &[&str] = &["run"];

pub fn metadata() -> Result<PortMetadata, PortError> {
    Ok(PortMetadata {
        module_name: module_path!(),
        source_path: SOURCE_PATH,
        source_lines: count_port_source_lines(SOURCE_PATH)?,
        extracted_functions: EXTRACTED_FUNCTIONS,
    })
}

pub fn read_source() -> Result<String, PortError> { read_port_source(SOURCE_PATH) }
pub fn source_lines() -> Result<usize, PortError> { count_port_source_lines(SOURCE_PATH) }
pub fn verify_port_sync() -> Result<(), PortError> { verify_extracted_functions(SOURCE_PATH, EXTRACTED_FUNCTIONS) }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tar_test_source_is_readable() {
        assert!(!read_source().unwrap().is_empty());
    }

    #[test]
    fn tar_test_source_stays_in_sync() {
        verify_port_sync().unwrap();
    }
}
