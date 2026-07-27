// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/resolve/resolved-link-bus.c
//
// Per-link D-Bus mutator methods and object path inventory.

use crate::port_sync::{PortSyncConstant, PortSyncError, PortSyncFunction, PortSyncModule};

pub const SOURCE_PATH: &str = "src/resolve/resolved-link-bus.c";

pub const INCLUDED_HEADERS: &[&str] = &[
    "net/if.h",
    "sd-bus.h",
    "alloc-util.h",
    "bus-common-errors.h",
    "bus-get-properties.h",
    "bus-message-util.h",
    "bus-object.h",
    "bus-polkit.h",
    "dns-domain.h",
    "log-link.h",
    "parse-util.h",
    "resolve-util.h",
    "resolved-bus.h",
    "resolved-def.h",
    "resolved-dns-search-domain.h",
    "resolved-dns-server.h",
    "resolved-link.h",
    "resolved-link-bus.h",
    "resolved-llmnr.h",
    "resolved-manager.h",
    "resolved-mdns.h",
    "resolved-resolv-conf.h",
    "set.h",
    "socket-netlink.h",
    "stdio-util.h",
    "string-util.h",
    "strv.h",
];
pub const LOCAL_DEFINES: &[&str] = &[];
pub const FUNCTIONS: &[PortSyncFunction] = &[
    PortSyncFunction {
        rust_name: "rs_bus_link_method_set_dns_servers",
        c_name: "bus_link_method_set_dns_servers",
        purpose: "Documents the bus link method set dns servers entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_bus_link_method_set_dns_servers_ex",
        c_name: "bus_link_method_set_dns_servers_ex",
        purpose: "Documents the bus link method set dns servers ex entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_bus_link_method_set_domains",
        c_name: "bus_link_method_set_domains",
        purpose: "Documents the bus link method set domains entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_bus_link_method_set_default_route",
        c_name: "bus_link_method_set_default_route",
        purpose: "Documents the bus link method set default route entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_bus_link_method_set_llmnr",
        c_name: "bus_link_method_set_llmnr",
        purpose: "Documents the bus link method set llmnr entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_bus_link_method_set_mdns",
        c_name: "bus_link_method_set_mdns",
        purpose: "Documents the bus link method set mdns entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_bus_link_method_set_dns_over_tls",
        c_name: "bus_link_method_set_dns_over_tls",
        purpose: "Documents the bus link method set dns over tls entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_bus_link_method_set_dnssec",
        c_name: "bus_link_method_set_dnssec",
        purpose: "Documents the bus link method set dnssec entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_bus_link_method_set_dnssec_negative_trust_anchors",
        c_name: "bus_link_method_set_dnssec_negative_trust_anchors",
        purpose: "Documents the bus link method set dnssec negative trust anchors entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_bus_link_method_revert",
        c_name: "bus_link_method_revert",
        purpose: "Documents the bus link method revert entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_link_bus_path",
        c_name: "link_bus_path",
        purpose: "Documents the link bus path entry point from the synced C module.",
    },
];
pub const CONSTANTS: &[PortSyncConstant] = &[];

pub fn module_spec() -> PortSyncModule<'static> {
    PortSyncModule {
        rust_module: "resolved_link_bus",
        source_path: SOURCE_PATH,
        summary: "Per-link D-Bus mutator methods and object path inventory.",
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
        let function = function("rs_bus_link_method_set_dns_servers").unwrap();
        assert_eq!(function.c_name, "bus_link_method_set_dns_servers");
    }
    #[test]
    fn function_lookup_finds_tail_symbol() {
        let function = function("rs_link_bus_path").unwrap();
        assert_eq!(function.rust_name, "rs_link_bus_path");
    }
    #[test]
    fn constants_inventory_is_empty_when_no_public_constants_exist() {
        assert!(module_spec().constants.is_empty());
    }
    #[test]
    fn unknown_function_reports_requested_name() {
        assert_eq!(
            function("does_not_exist"),
            Err(PortSyncError::UnknownFunction("does_not_exist".to_owned())),
        );
    }
}
