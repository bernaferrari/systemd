// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/resolve/resolved-bus.c
//
// D-Bus connection setup and exported DNS property interface.
//
// Implements the org.freedesktop.resolve1 D-Bus interface including
// ResolveHostname, ResolveAddress, ResolveRecord, ResolveService methods,
// property getters for DNS servers/domains/statistics, and DNS-SD
// service registration over the bus.

use crate::port_sync::{PortSyncConstant, PortSyncError, PortSyncFunction, PortSyncModule};

pub const SOURCE_PATH: &str = "src/resolve/resolved-bus.c";

pub const INCLUDED_HEADERS: &[&str] = &[
    "sd-bus.h",
    "alloc-util.h",
    "bus-common-errors.h",
    "bus-get-properties.h",
    "bus-locator.h",
    "bus-log-control-api.h",
    "bus-message-util.h",
    "bus-object.h",
    "bus-polkit.h",
    "bus-util.h",
    "dns-answer.h",
    "dns-domain.h",
    "dns-packet.h",
    "dns-question.h",
    "dns-rr.h",
    "format-util.h",
    "path-util.h",
    "resolve-util.h",
    "resolved-bus.h",
    "resolved-def.h",
    "resolved-dns-delegate-bus.h",
    "resolved-dns-delegate.h",
    "resolved-dns-dnssec.h",
    "resolved-dns-query.h",
    "resolved-dns-scope.h",
    "resolved-dns-search-domain.h",
    "resolved-dns-server.h",
    "resolved-dns-stream.h",
    "resolved-dns-stub.h",
    "resolved-dns-synthesize.h",
    "resolved-dns-transaction.h",
    "resolved-dnssd-bus.h",
    "resolved-dnssd.h",
    "resolved-link-bus.h",
    "resolved-link.h",
    "resolved-manager.h",
    "resolved-resolv-conf.h",
    "set.h",
    "socket-netlink.h",
    "string-util.h",
    "utf8.h",
];

pub const LOCAL_DEFINES: &[&str] = &[];

pub const FUNCTIONS: &[PortSyncFunction] = &[
    PortSyncFunction {
        rust_name: "rs_manager_connect_bus",
        c_name: "manager_connect_bus",
        purpose: "Opens the D-Bus connection and registers the resolve1 vtable.",
    },
    PortSyncFunction {
        rust_name: "rs_manager_send_changed_strv",
        c_name: "manager_send_changed_strv",
        purpose: "Emits PropertiesChanged for the given property names.",
    },
    PortSyncFunction {
        rust_name: "rs_bus_dns_server_append",
        c_name: "bus_dns_server_append",
        purpose: "Appends a DNS server address to a D-Bus message.",
    },
    PortSyncFunction {
        rust_name: "rs_bus_property_get_resolve_support",
        c_name: "bus_property_get_resolve_support",
        purpose: "D-Bus property getter for ResolveSupport enum.",
    },
    PortSyncFunction {
        rust_name: "rs_bus_client_log",
        c_name: "bus_client_log",
        purpose: "Logs a message on behalf of the D-Bus client.",
    },
];

pub const CONSTANTS: &[PortSyncConstant] = &[];

pub fn module_spec() -> PortSyncModule<'static> {
    PortSyncModule {
        rust_module: "resolved_bus",
        source_path: SOURCE_PATH,
        summary: "D-Bus connection setup and exported DNS property interface.",
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
    fn function_lookup_finds_connect_bus() {
        let f = function("rs_manager_connect_bus").unwrap();
        assert_eq!(f.c_name, "manager_connect_bus");
    }

    #[test]
    fn function_lookup_finds_client_log() {
        let f = function("rs_bus_client_log").unwrap();
        assert_eq!(f.c_name, "bus_client_log");
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
}
