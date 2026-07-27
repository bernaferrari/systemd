// SPDX-License-Identifier: GPL-2.0-or-later
//
// PORT-SYNC: src/udev/dmi_memory_id/dmi_memory_id.c
//
// Conservative Rust shadow for dmi memory id.
// This module records source metadata and exposes an explicit rs_ FFI stub
// until the behavioral port is implemented.

use crate::ffi::Errno;

pub const SOURCE_PATH: &str = "src/udev/dmi_memory_id/dmi_memory_id.c";
pub const SOURCE_LINE_COUNT: usize = 721;
pub const INCLUDED_HEADERS: &[&str] = &[
    "alloc-util.h",
    "build.h",
    "fileio.h",
    "getopt.h",
    "main-func.h",
    "stdio.h",
    "string-util.h",
    "udev-util.h",
    "unaligned.h",
    "utf8.h"
];
pub const EXPORTED_C_FUNCTIONS: &[&str] = &[
    "verify_checksum",
    "dmi_string",
    "dmi_print_memory_size",
    "dmi_memory_array_location",
    "dmi_memory_array_ec_type",
    "dmi_memory_device_string",
    "dmi_memory_device_width",
    "dmi_memory_device_size",
    "dmi_memory_device_extended_size",
    "dmi_memory_device_rank",
    "dmi_memory_device_voltage_value",
    "dmi_memory_device_form_factor",
    "dmi_memory_device_set",
    "dmi_memory_device_type",
    "dmi_memory_device_type_detail",
    "dmi_memory_device_speed",
    "dmi_memory_device_technology",
    "dmi_memory_device_operating_mode_capability",
    "dmi_memory_device_manufacturer_id",
    "dmi_memory_device_product_id",
    "dmi_memory_device_size_detail",
    "dmi_decode",
    "dmi_table_decode",
    "dmi_table",
    "smbios3_decode",
    "smbios_decode",
    "legacy_decode",
    "help",
    "parse_argv",
    "run"
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortSummary {
    pub source_path: &'static str,
    pub line_count: usize,
    pub include_count: usize,
    pub function_count: usize,
}

pub fn port_summary() -> PortSummary {
    PortSummary {
        source_path: SOURCE_PATH,
        line_count: SOURCE_LINE_COUNT,
        include_count: INCLUDED_HEADERS.len(),
        function_count: EXPORTED_C_FUNCTIONS.len(),
    }
}

pub fn port_status() -> Result<(), Errno> {
    Err(Errno::ENOSYS)
}

#[no_mangle]
pub extern "C" fn rs_dmi_memory_id_dmi_memory_id_port_stub() -> i32 {
    port_status().err().unwrap_or(Errno::EINVAL).to_neg_errno()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summary_references_expected_source() {
        let summary = port_summary();
        assert_eq!(summary.source_path, SOURCE_PATH);
        assert_eq!(summary.line_count, SOURCE_LINE_COUNT);
    }

    #[test]
    fn ffi_stub_reports_enosys() {
        assert_eq!(rs_dmi_memory_id_dmi_memory_id_port_stub(), Errno::ENOSYS.to_neg_errno());
    }

    #[test]
    fn extracted_metadata_is_stable() {
        assert!(SOURCE_LINE_COUNT > 0);
        assert!(SOURCE_PATH.ends_with(".c"));
    }
}
