// SPDX-License-Identifier: GPL-2.0-or-later
//
// PORT-SYNC: src/udev/scsi_id/scsi_id.c
//
// Conservative Rust shadow for scsi id.
// This module records source metadata and exposes an explicit rs_ FFI stub
// until the behavioral port is implemented.

use crate::ffi::Errno;

pub const SOURCE_PATH: &str = "src/udev/scsi_id/scsi_id.c";
pub const SOURCE_LINE_COUNT: usize = 512;
pub const INCLUDED_HEADERS: &[&str] = &[
    "alloc-util.h",
    "build.h",
    "ctype.h",
    "device-nodes.h",
    "extract-word.h",
    "fd-util.h",
    "fileio.h",
    "getopt.h",
    "scsi_id.h",
    "stdio.h",
    "stdlib.h",
    "string-util.h",
    "strv.h",
    "strxcpyx.h",
    "udev-util.h",
    "utf8.h"
];
pub const EXPORTED_C_FUNCTIONS: &[&str] = &[
    "set_type",
    "get_file_options",
    "startswith",
    "help",
    "set_options",
    "per_dev_options",
    "set_inq_values",
    "scsi_id",
    "main"
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
pub extern "C" fn rs_scsi_id_scsi_id_port_stub() -> i32 {
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
        assert_eq!(rs_scsi_id_scsi_id_port_stub(), Errno::ENOSYS.to_neg_errno());
    }

    #[test]
    fn extracted_metadata_is_stable() {
        assert!(SOURCE_LINE_COUNT > 0);
        assert!(SOURCE_PATH.ends_with(".c"));
    }
}
