// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/resolve/resolved-varlink.c
//
// Varlink endpoint bootstrap, resolve methods, and monitor wiring.
//
// Exposes ResolveHostname, ResolveAddress, ResolveRecord, ResolveService,
// and browse-services methods over Varlink. Manages service browsers,
// DNS configuration subscriptions, and query-result monitor notifications.

use crate::port_sync::{PortSyncConstant, PortSyncError, PortSyncFunction, PortSyncModule};

// ── Module inventory ──────────────────────────────────────────────────────

pub const SOURCE_PATH: &str = "src/resolve/resolved-varlink.c";

pub const INCLUDED_HEADERS: &[&str] = &[
    "sd-event.h",
    "alloc-util.h",
    "bus-polkit.h",
    "dns-answer.h",
    "dns-domain.h",
    "dns-packet.h",
    "dns-question.h",
    "dns-rr.h",
    "dns-type.h",
    "errno-util.h",
    "in-addr-util.h",
    "iovec-util.h",
    "json-util.h",
    "resolved-dns-browse-services.h",
    "resolved-dns-dnssec.h",
    "resolved-dns-query.h",
    "resolved-dns-scope.h",
    "resolved-dns-search-domain.h",
    "resolved-dns-server.h",
    "resolved-dns-synthesize.h",
    "resolved-dns-transaction.h",
    "resolved-link.h",
    "resolved-manager.h",
    "resolved-varlink.h",
    "set.h",
    "socket-netlink.h",
    "string-util.h",
    "varlink-io.systemd.Resolve.h",
    "varlink-io.systemd.Resolve.Monitor.h",
    "varlink-io.systemd.service.h",
    "varlink-util.h",
];

pub const LOCAL_DEFINES: &[&str] = &[];

pub const FUNCTIONS: &[PortSyncFunction] = &[
    PortSyncFunction {
        rust_name: "rs_manager_varlink_init",
        c_name: "manager_varlink_init",
        purpose: "Creates and registers the Varlink server on the manager.",
    },
    PortSyncFunction {
        rust_name: "rs_manager_varlink_done",
        c_name: "manager_varlink_done",
        purpose: "Releases the Varlink server and associated resources.",
    },
];

pub const CONSTANTS: &[PortSyncConstant] = &[];

// ── Helpers ───────────────────────────────────────────────────────────────

/// Returns the module specification for this PORT-SYNC inventory.
pub fn module_spec() -> PortSyncModule<'static> {
    PortSyncModule {
        rust_module: "resolved_varlink",
        source_path: SOURCE_PATH,
        summary: "Varlink endpoint bootstrap, resolve methods, and monitor wiring.",
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
    fn function_lookup_finds_init() {
        let f = function("rs_manager_varlink_init").unwrap();
        assert_eq!(f.c_name, "manager_varlink_init");
        assert!(!f.purpose.is_empty());
    }

    #[test]
    fn function_lookup_finds_done() {
        let f = function("rs_manager_varlink_done").unwrap();
        assert_eq!(f.c_name, "manager_varlink_done");
    }

    #[test]
    fn all_functions_have_nonempty_purpose() {
        for f in FUNCTIONS {
            assert!(!f.purpose.is_empty(), "purpose empty for {}", f.rust_name);
        }
    }

    #[test]
    fn constants_inventory_is_empty() {
        assert!(CONSTANTS.is_empty());
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
    fn headers_include_varlink_util() {
        assert!(INCLUDED_HEADERS.contains(&"varlink-util.h"));
    }
}
