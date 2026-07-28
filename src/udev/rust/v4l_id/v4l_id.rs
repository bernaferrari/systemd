// SPDX-License-Identifier: GPL-2.0-or-later
//
// PORT-SYNC: src/udev/v4l_id/v4l_id.c
//
// Conservative Rust shadow for v4l id.
// This module records source metadata and exposes an explicit rs_ FFI stub
// until the behavioral port is implemented.

use crate::ffi::Errno;

pub const SOURCE_PATH: &str = "src/udev/v4l_id/v4l_id.c";
pub const SOURCE_LINE_COUNT: usize = 106;
pub const INCLUDED_HEADERS: &[&str] = &[
    "build.h",
    "errno-util.h",
    "fcntl.h",
    "fd-util.h",
    "getopt.h",
    "linux/videodev2.h",
    "log.h",
    "main-func.h",
    "stdio.h",
    "string-util.h",
    "sys/ioctl.h",
    "utf8.h",
];
pub const EXPORTED_C_FUNCTIONS: &[&str] = &["parse_argv", "run"];

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
pub extern "C" fn rs_v4l_id_v4l_id_port_stub() -> i32 {
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
        assert_eq!(rs_v4l_id_v4l_id_port_stub(), Errno::ENOSYS.to_neg_errno());
    }

    #[test]
    fn extracted_metadata_is_stable() {
        assert!(SOURCE_LINE_COUNT > 0);
        assert!(SOURCE_PATH.ends_with(".c"));
    }
}
