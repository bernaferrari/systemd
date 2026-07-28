// SPDX-License-Identifier: GPL-2.0-or-later
//
// PORT-SYNC: src/udev/scsi_id/scsi_serial.c
//
// Conservative Rust shadow for scsi serial.
// This module records source metadata and exposes an explicit rs_ FFI stub
// until the behavioral port is implemented.

use crate::ffi::Errno;

pub const SOURCE_PATH: &str = "src/udev/scsi_id/scsi_serial.c";
pub const SOURCE_LINE_COUNT: usize = 883;
pub const INCLUDED_HEADERS: &[&str] = &[
    "devnum-util.h",
    "fcntl.h",
    "hexdecoct.h",
    "linux/bsg.h",
    "log.h",
    "random-util.h",
    "scsi.h",
    "scsi/scsi.h",
    "scsi/sg.h",
    "scsi_id.h",
    "stdio.h",
    "string-util.h",
    "sys/ioctl.h",
    "sys/stat.h",
    "time-util.h",
    "unistd.h",
];
pub const EXPORTED_C_FUNCTIONS: &[&str] = &[
    "sg_err_category_new",
    "sg_err_category3",
    "sg_err_category4",
    "scsi_dump_sense",
    "scsi_dump",
    "scsi_dump_v4",
    "scsi_inquiry",
    "do_scsi_page0_inquiry",
    "append_vendor_model",
    "check_fill_0x83_id",
    "check_fill_0x83_prespc3",
    "do_scsi_page83_inquiry",
    "FOREACH_ELEMENT",
    "do_scsi_page83_prespc3_inquiry",
    "do_scsi_page80_inquiry",
    "scsi_std_inquiry",
    "scsi_get_serial",
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

#[unsafe(no_mangle)]
pub extern "C" fn rs_scsi_id_scsi_serial_port_stub() -> i32 {
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
        assert_eq!(
            rs_scsi_id_scsi_serial_port_stub(),
            Errno::ENOSYS.to_neg_errno()
        );
    }

    #[test]
    fn extracted_metadata_is_stable() {
        assert!(SOURCE_LINE_COUNT > 0);
        assert!(SOURCE_PATH.ends_with(".c"));
    }
}
