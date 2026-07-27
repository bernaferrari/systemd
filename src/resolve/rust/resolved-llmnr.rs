// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/resolve/resolved-llmnr.c
//
// LLMNR socket provisioning and teardown inventory.

use crate::port_sync::{PortSyncConstant, PortSyncError, PortSyncFunction, PortSyncModule};

pub const SOURCE_PATH: &str = "src/resolve/resolved-llmnr.c";

pub const LLMNR_PORT: u16 = 5355;

pub const INCLUDED_HEADERS: &[&str] = &[
    "netinet/in.h",
    "netinet/tcp.h",
    "sd-event.h",
    "dns-packet.h",
    "errno-util.h",
    "fd-util.h",
    "hashmap.h",
    "log.h",
    "resolved-dns-scope.h",
    "resolved-dns-transaction.h",
    "resolved-link.h",
    "resolved-llmnr.h",
    "resolved-manager.h",
];
pub const LOCAL_DEFINES: &[&str] = &[];
pub const FUNCTIONS: &[PortSyncFunction] = &[
    PortSyncFunction {
        rust_name: "rs_manager_llmnr_ipv4_udp_fd",
        c_name: "manager_llmnr_ipv4_udp_fd",
        purpose: "Documents the manager llmnr ipv4 udp fd entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_manager_llmnr_ipv6_udp_fd",
        c_name: "manager_llmnr_ipv6_udp_fd",
        purpose: "Documents the manager llmnr ipv6 udp fd entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_manager_llmnr_ipv4_tcp_fd",
        c_name: "manager_llmnr_ipv4_tcp_fd",
        purpose: "Documents the manager llmnr ipv4 tcp fd entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_manager_llmnr_ipv6_tcp_fd",
        c_name: "manager_llmnr_ipv6_tcp_fd",
        purpose: "Documents the manager llmnr ipv6 tcp fd entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_manager_llmnr_stop",
        c_name: "manager_llmnr_stop",
        purpose: "Documents the manager llmnr stop entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_manager_llmnr_maybe_stop",
        c_name: "manager_llmnr_maybe_stop",
        purpose: "Documents the manager llmnr maybe stop entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_manager_llmnr_start",
        c_name: "manager_llmnr_start",
        purpose: "Documents the manager llmnr start entry point from the synced C module.",
    },
];
pub const CONSTANTS: &[PortSyncConstant] = &[PortSyncConstant {
    name: "LLMNR_PORT",
    value: "5355",
    purpose: "Documents the llmnr_port constant carried over from the existing Rust shadow module.",
}];

pub fn module_spec() -> PortSyncModule<'static> {
    PortSyncModule {
        rust_module: "resolved_llmnr",
        source_path: SOURCE_PATH,
        summary: "LLMNR socket provisioning and teardown inventory.",
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
    fn source_path_matches_synced_c_file() {
        assert_eq!(module_spec().source_path, SOURCE_PATH);
    }
    #[test]
    fn validate_accepts_generated_inventory() {
        assert_eq!(validate(), Ok(()));
    }
    #[test]
    fn module_summary_mentions_inventory() {
        assert!(module_spec().summary.contains("inventory"));
    }
    #[test]
    fn function_lookup_finds_primary_symbol() {
        let function = function("rs_manager_llmnr_ipv4_udp_fd").unwrap();
        assert_eq!(function.c_name, "manager_llmnr_ipv4_udp_fd");
    }
    #[test]
    fn function_lookup_finds_tail_symbol() {
        let function = function("rs_manager_llmnr_start").unwrap();
        assert_eq!(function.rust_name, "rs_manager_llmnr_start");
    }
    #[test]
    fn constant_lookup_finds_documented_constant() {
        let constant = constant("LLMNR_PORT").unwrap();
        assert_eq!(constant.name, "LLMNR_PORT");
    }
    #[test]
    fn unknown_function_reports_requested_name() {
        assert_eq!(
            function("does_not_exist"),
            Err(PortSyncError::UnknownFunction("does_not_exist".to_owned())),
        );
    }
}
