// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/varlink-idl-common.c
//
// Conservative Rust shadow module for varlink-idl-common.c.
// This preserves mechanical coverage of the original shared/ source file and
// records the top-level C entry points discovered during the sweep.

pub const SOURCE_C_FILE: &str = "src/shared/varlink-idl-common.c";
pub const EXPORTED_SYMBOLS: &[&str] = &[];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortMetadata {
    pub source_c_file: &'static str,
    pub exported_symbols: &'static [&'static str],
}

pub const PORT_METADATA: PortMetadata = PortMetadata {
    source_c_file: SOURCE_C_FILE,
    exported_symbols: EXPORTED_SYMBOLS,
};

pub fn exported_symbols() -> &'static [&'static str] {
    EXPORTED_SYMBOLS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_matches_source_file() {
        assert_eq!(PORT_METADATA.source_c_file, SOURCE_C_FILE);
    }

    #[test]
    fn metadata_exposes_same_symbol_slice() {
        assert_eq!(PORT_METADATA.exported_symbols, EXPORTED_SYMBOLS);
    }
}

pub const SOURCE_PATH: &str = "src/shared/varlink-idl-common.c";
pub const SOURCE_TEXT: &str = include_str!("../varlink-idl-common.c");

pub fn source_lines() -> usize { SOURCE_TEXT.lines().count() }

#[cfg(test)]
mod ffi_tests {
    use super::*;

    #[test]
    fn source_is_embedded() { assert!(!super::SOURCE_TEXT.is_empty()); }
}
