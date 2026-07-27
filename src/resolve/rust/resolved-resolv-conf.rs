// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/resolve/resolved-resolv-conf.c
//
// /etc/resolv.conf mode detection, reading, and writing.
//
// Determines whether resolv.conf is managed by stub, uplink, static, or
// foreign configuration. Handles reading upstream DNS servers and writing
// the stub listener configuration back to the file.

use crate::port_sync::{PortSyncConstant, PortSyncError, PortSyncFunction, PortSyncModule};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolvConfMode {
    Uplink,
    Stub,
    Static,
    Foreign,
    Missing,
}

pub const SOURCE_PATH: &str = "src/resolve/resolved-resolv-conf.c";

pub const INCLUDED_HEADERS: &[&str] = &[
    "resolv.h",
    "sys/stat.h",
    "alloc-util.h",
    "fd-util.h",
    "fileio.h",
    "fs-util.h",
    "log.h",
    "ordered-set.h",
    "path-util.h",
    "resolved-dns-cache.h",
    "resolved-dns-scope.h",
    "resolved-dns-search-domain.h",
    "resolved-dns-server.h",
    "resolved-dns-stub.h",
    "resolved-manager.h",
    "resolved-resolv-conf.h",
    "stat-util.h",
    "string-table.h",
    "string-util.h",
    "strv.h",
    "tmpfile-util-label.h",
];

pub const LOCAL_DEFINES: &[&str] = &[];

pub const FUNCTIONS: &[PortSyncFunction] = &[
    PortSyncFunction {
        rust_name: "rs_manager_check_resolv_conf",
        c_name: "manager_check_resolv_conf",
        purpose: "Detects changes to /etc/resolv.conf.",
    },
    PortSyncFunction {
        rust_name: "rs_manager_read_resolv_conf",
        c_name: "manager_read_resolv_conf",
        purpose: "Parses upstream DNS servers from resolv.conf.",
    },
    PortSyncFunction {
        rust_name: "rs_manager_write_resolv_conf",
        c_name: "manager_write_resolv_conf",
        purpose: "Writes the stub listener configuration to resolv.conf.",
    },
    PortSyncFunction {
        rust_name: "rs_resolv_conf_mode",
        c_name: "resolv_conf_mode",
        purpose: "Returns the current ResolvConfMode.",
    },
];

pub const CONSTANTS: &[PortSyncConstant] = &[];

pub fn module_spec() -> PortSyncModule<'static> {
    PortSyncModule {
        rust_module: "resolved_resolv_conf",
        source_path: SOURCE_PATH,
        summary: "/etc/resolv.conf mode detection, reading, and writing.",
        included_headers: INCLUDED_HEADERS,
        local_defines: LOCAL_DEFINES,
        functions: FUNCTIONS,
        constants: CONSTANTS,
    }
}

pub fn function(rust_name: &str) -> Result<&'static PortSyncFunction, PortSyncError> {
    module_spec().function(rust_name)
}

pub fn constant(name: &str) -> Result<&'static PortSyncConstant, PortSyncError> {
    module_spec().constant(name)
}

pub fn validate() -> Result<(), PortSyncError> {
    module_spec().validate()
}

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
    fn function_lookup_finds_read() {
        let f = function("rs_manager_read_resolv_conf").unwrap();
        assert_eq!(f.c_name, "manager_read_resolv_conf");
    }

    #[test]
    fn function_lookup_finds_mode() {
        let f = function("rs_resolv_conf_mode").unwrap();
        assert_eq!(f.c_name, "resolv_conf_mode");
    }

    #[test]
    fn all_functions_have_nonempty_purpose() {
        for f in FUNCTIONS {
            assert!(!f.purpose.is_empty(), "purpose empty for {}", f.rust_name);
        }
    }

    #[test]
    fn resolv_conf_mode_variants_are_distinct() {
        use ResolvConfMode::*;
        let modes = [Uplink, Stub, Static, Foreign, Missing];
        for (i, a) in modes.iter().enumerate() {
            for (j, b) in modes.iter().enumerate() {
                assert_eq!(i == j, a == b);
            }
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
}
