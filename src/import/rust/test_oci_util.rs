// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/import/test-oci-util.c

use crate::import_common::{count_port_source_lines, read_port_source, verify_extracted_functions, PortError, PortMetadata};
use crate::oci_util::{oci_digest_from_string, oci_normalize_reference};

pub const SOURCE_PATH: &str = "src/import/test-oci-util.c";
pub const EXTRACTED_FUNCTIONS: &[&str] = &["TEST", "test_urlescape_one"];

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
    fn oci_helpers_still_work() {
        assert_eq!(oci_digest_from_string("sha256:abc").unwrap(), ("sha256", "abc"));
        assert_eq!(oci_normalize_reference("alpine").unwrap(), "alpine:latest");
    }

    #[test]
    fn oci_test_source_stays_in_sync() {
        verify_port_sync().unwrap();
    }
}
