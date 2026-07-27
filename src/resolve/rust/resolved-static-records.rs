// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/resolve/resolved-static-records.c
//
// Static DNS record loading from JSON drop-in files and manager lookup.
//
// Reads .rr files from systemd/resolve/static.d/, parses JSON-formatted
// resource records, and makes them available for synthesis via the manager.
// Rechecks files at most once every 2 seconds for efficiency.

use crate::port_sync::{PortSyncConstant, PortSyncError, PortSyncFunction, PortSyncModule};

// ── Constants ─────────────────────────────────────────────────────────────

/// Minimum interval between static-record rechecks (2 seconds in microseconds).
pub const STATIC_RECORDS_RECHECK_USEC: u64 = 2_000_000;

// ── Module inventory ──────────────────────────────────────────────────────

pub const SOURCE_PATH: &str = "src/resolve/resolved-static-records.c";

pub const INCLUDED_HEADERS: &[&str] = &[
    "sd-json.h",
    "alloc-util.h",
    "conf-files.h",
    "constants.h",
    "dns-answer.h",
    "dns-domain.h",
    "dns-question.h",
    "dns-rr.h",
    "errno-util.h",
    "fd-util.h",
    "fileio.h",
    "hashmap.h",
    "json-util.h",
    "log.h",
    "resolved-manager.h",
    "resolved-static-records.h",
    "set.h",
    "stat-util.h",
];

pub const LOCAL_DEFINES: &[&str] = &["STATIC_RECORDS_RECHECK_USEC"];

pub const FUNCTIONS: &[PortSyncFunction] = &[
    PortSyncFunction {
        rust_name: "rs_manager_static_records_lookup",
        c_name: "manager_static_records_lookup",
        purpose: "Looks up static records matching a DNS question.",
    },
    PortSyncFunction {
        rust_name: "rs_manager_static_records_flush",
        c_name: "manager_static_records_flush",
        purpose: "Frees all loaded static records and stat entries.",
    },
];

pub const CONSTANTS: &[PortSyncConstant] = &[PortSyncConstant {
    name: "STATIC_RECORDS_RECHECK_USEC",
    value: "2000000",
    purpose: "Minimum interval in microseconds between static record file rechecks.",
}];

// ── Helpers ───────────────────────────────────────────────────────────────

/// Returns the module specification for this PORT-SYNC inventory.
pub fn module_spec() -> PortSyncModule<'static> {
    PortSyncModule {
        rust_module: "resolved_static_records",
        source_path: SOURCE_PATH,
        summary: "Static DNS record loading from JSON drop-in files and manager lookup.",
        included_headers: INCLUDED_HEADERS,
        local_defines: LOCAL_DEFINES,
        functions: FUNCTIONS,
        constants: CONSTANTS,
    }
}

/// Look up a function descriptor by its Rust symbol name.
pub fn function(rust_name: &str) -> Result<&'static PortSyncFunction, PortSyncError> {
    module_spec().function(rust_name)
}

/// Look up a constant descriptor by name.
pub fn constant(name: &str) -> Result<&'static PortSyncConstant, PortSyncError> {
    module_spec().constant(name)
}

/// Validate the module inventory for internal consistency.
pub fn validate() -> Result<(), PortSyncError> {
    module_spec().validate()
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_path_targets_resolve_subdirectory() {
        assert!(SOURCE_PATH.starts_with("src/resolve/"));
        assert!(SOURCE_PATH.ends_with(".c"));
    }

    #[test]
    fn validate_accepts_well_formed_inventory() {
        assert_eq!(validate(), Ok(()));
    }

    #[test]
    fn module_summary_is_nonempty() {
        assert!(!module_spec().summary.trim().is_empty());
    }

    #[test]
    fn function_lookup_finds_lookup() {
        let f = function("rs_manager_static_records_lookup").unwrap();
        assert_eq!(f.c_name, "manager_static_records_lookup");
        assert!(!f.purpose.is_empty());
    }

    #[test]
    fn function_lookup_finds_flush() {
        let f = function("rs_manager_static_records_flush").unwrap();
        assert_eq!(f.c_name, "manager_static_records_flush");
    }

    #[test]
    fn constant_lookup_finds_recheck_interval() {
        let c = constant("STATIC_RECORDS_RECHECK_USEC").unwrap();
        assert_eq!(c.value, "2000000");
    }

    #[test]
    fn all_functions_have_nonempty_purpose() {
        for f in FUNCTIONS {
            assert!(!f.purpose.is_empty(), "purpose empty for {}", f.rust_name);
        }
    }

    #[test]
    fn unknown_function_reports_requested_name() {
        assert_eq!(
            function("does_not_exist"),
            Err(PortSyncError::UnknownFunction("does_not_exist".to_owned())),
        );
    }

    #[test]
    fn unknown_constant_reports_requested_name() {
        assert_eq!(
            constant("does_not_exist"),
            Err(PortSyncError::UnknownConstant("does_not_exist".to_owned())),
        );
    }

    #[test]
    fn recheck_interval_is_two_seconds() {
        assert_eq!(STATIC_RECORDS_RECHECK_USEC, 2_000_000);
    }
}
