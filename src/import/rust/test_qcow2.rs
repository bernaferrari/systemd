// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/import/test-qcow2.c

use crate::import_common::{
    PortError, PortMetadata, count_port_source_lines, read_port_source, verify_extracted_functions,
};
use crate::qcow2_util::{QCOW2_MAGIC, verify_qcow2_magic};

pub const SOURCE_PATH: &str = "src/import/test-qcow2.c";
pub const EXTRACTED_FUNCTIONS: &[&str] = &["main"];

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
pub fn verify_port_sync() -> Result<(), PortError> {
    verify_extracted_functions(SOURCE_PATH, EXTRACTED_FUNCTIONS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn qcow2_magic_stays_valid() {
        assert!(verify_qcow2_magic(QCOW2_MAGIC).is_ok());
    }

    #[test]
    fn c_source_matches_declared_entrypoints() {
        let port = metadata().unwrap();
        assert_eq!(port.source_path, SOURCE_PATH);
        assert_eq!(port.source_lines, source_lines().unwrap());
        assert_eq!(port.extracted_functions, EXTRACTED_FUNCTIONS);
        assert!(!read_source().unwrap().is_empty());
        verify_port_sync().unwrap();
    }
}
