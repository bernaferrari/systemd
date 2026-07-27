// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/boot/ubsan.c

#[allow(
    dead_code,
    improper_ctypes,
    non_camel_case_types,
    non_snake_case,
    unused_imports
)]
use std::ffi::c_void;

use crate::common::{Errno, PortMetadata};

pub const SOURCE_PATH: &str = "src/boot/ubsan.c";
pub const SOURCE_TEXT: &str = include_str!("../ubsan.c");
pub const EXPORTED_FUNCTIONS: &[&str] = &[];

pub fn port_metadata() -> PortMetadata {
    PortMetadata {
        module_name: "ubsan",
        source_path: SOURCE_PATH,
        source_lines: SOURCE_TEXT.lines().count(),
        extracted_functions: EXPORTED_FUNCTIONS,
    }
}

pub fn ensure_port_ready() -> Result<(), Errno> {
    if SOURCE_TEXT.trim().is_empty() {
        return Err(Errno::new(22));
    }
    Ok(())
}

pub fn translated_functions() -> &'static [&'static str] {
    EXPORTED_FUNCTIONS
}

#[unsafe(no_mangle)]
pub extern "C" fn rs_ubsan_port_ready() -> i32 {
    ensure_port_ready()
        .map(|()| 0)
        .unwrap_or_else(|errno| -errno.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn smoke() {
        assert!(!SOURCE_TEXT.is_empty());
        assert_eq!(port_metadata().source_path, SOURCE_PATH);
    }
}
