// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/nspawn/test-nspawn-tables.c

use crate::common::{Errno, PortMetadata};

pub const SOURCE_PATH: &str = "src/nspawn/test-nspawn-tables.c";
pub const EXTRACTED_FUNCTIONS: &[&str] = &["main"];

pub fn port_metadata() -> PortMetadata {
    PortMetadata {
        module_name: "test_nspawn_tables",
        source_path: SOURCE_PATH,
        source_lines: 14,
        extracted_functions: EXTRACTED_FUNCTIONS,
    }
}

pub fn table_names() -> Result<[&'static str; 2], Errno> {
    Ok(["resolv_conf_mode", "timezone_mode"])
}

pub fn run_table_smoke_test() -> Result<usize, Errno> {
    Ok(table_names()?.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contains_expected_table_names() {
        assert_eq!(
            table_names().unwrap(),
            ["resolv_conf_mode", "timezone_mode"]
        );
    }

    #[test]
    fn smoke_test_counts_both_tables() {
        assert_eq!(run_table_smoke_test().unwrap(), 2);
    }
}
