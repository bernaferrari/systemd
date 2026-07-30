// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/udev/iocost/iocost.c
//
// Conservative Rust shadow for iocost.
// This module records source metadata and exposes an explicit rs_ FFI stub
// until the behavioral port is implemented.

use crate::ffi::Errno;

pub const SOURCE_PATH: &str = "src/udev/iocost/iocost.c";
pub const SOURCE_LINE_COUNT: usize = 319;
pub const INCLUDED_HEADERS: &[&str] = &[
    "alloc-util.h",
    "build.h",
    "cgroup-util.h",
    "conf-parser.h",
    "device-util.h",
    "devnum-util.h",
    "getopt.h",
    "main-func.h",
    "sd-device.h",
    "stdio.h",
    "string-util.h",
    "strv.h",
    "udev-util.h",
    "verbs.h",
];
pub const EXPORTED_C_FUNCTIONS: &[&str] = &[
    "parse_config",
    "help",
    "parse_argv",
    "get_known_solutions",
    "query_named_solution",
    "apply_solution_for_path",
    "query_solutions_for_path",
    "STRV_FOREACH",
    "verb_query",
    "verb_apply",
    "iocost_main",
    "run",
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
pub extern "C" fn rs_iocost_iocost_port_stub() -> i32 {
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
        assert_eq!(rs_iocost_iocost_port_stub(), Errno::ENOSYS.to_neg_errno());
    }

    #[test]
    fn extracted_metadata_is_stable() {
        const { assert!(SOURCE_LINE_COUNT > 0) };
        assert!(SOURCE_PATH.ends_with(".c"));
    }
}
