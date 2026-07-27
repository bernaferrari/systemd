// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/resolve/resolved-link.c
//
// Resolved link lifecycle, persisted settings, and address inventory.

use crate::port_sync::{PortSyncConstant, PortSyncError, PortSyncFunction, PortSyncModule};

pub const SOURCE_PATH: &str = "src/resolve/resolved-link.c";

pub const INCLUDED_HEADERS: &[&str] = &[
    "linux/if.h",
    "unistd.h",
    "sd-netlink.h",
    "sd-network.h",
    "alloc-util.h",
    "dns-domain.h",
    "dns-packet.h",
    "dns-rr.h",
    "env-file.h",
    "extract-word.h",
    "fd-util.h",
    "fileio.h",
    "fs-util.h",
    "log-link.h",
    "mkdir.h",
    "netif-util.h",
    "parse-util.h",
    "resolved-dns-browse-services.h",
    "resolved-dns-scope.h",
    "resolved-dns-search-domain.h",
    "resolved-dns-server.h",
    "resolved-link.h",
    "resolved-llmnr.h",
    "resolved-manager.h",
    "resolved-mdns.h",
    "set.h",
    "socket-netlink.h",
    "stat-util.h",
    "string-util.h",
    "strv.h",
    "tmpfile-util.h",
];
pub const LOCAL_DEFINES: &[&str] = &[];
pub const FUNCTIONS: &[PortSyncFunction] = &[
    PortSyncFunction {
        rust_name: "rs_link_new",
        c_name: "link_new",
        purpose: "Documents the link new entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_link_free",
        c_name: "link_free",
        purpose: "Documents the link free entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_link_process_rtnl",
        c_name: "link_process_rtnl",
        purpose: "Documents the link process rtnl entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_link_update",
        c_name: "link_update",
        purpose: "Documents the link update entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_link_relevant",
        c_name: "link_relevant",
        purpose: "Documents the link relevant entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_link_find_address",
        c_name: "link_find_address",
        purpose: "Documents the link find address entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_link_add_rrs",
        c_name: "link_add_rrs",
        purpose: "Documents the link add rrs entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_link_flush_settings",
        c_name: "link_flush_settings",
        purpose: "Documents the link flush settings entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_link_set_dnssec_mode",
        c_name: "link_set_dnssec_mode",
        purpose: "Documents the link set dnssec mode entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_link_set_dns_over_tls_mode",
        c_name: "link_set_dns_over_tls_mode",
        purpose: "Documents the link set dns over tls mode entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_link_allocate_scopes",
        c_name: "link_allocate_scopes",
        purpose: "Documents the link allocate scopes entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_link_set_dns_server",
        c_name: "link_set_dns_server",
        purpose: "Documents the link set dns server entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_link_get_dns_server",
        c_name: "link_get_dns_server",
        purpose: "Documents the link get dns server entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_link_next_dns_server",
        c_name: "link_next_dns_server",
        purpose: "Documents the link next dns server entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_link_set_default_route",
        c_name: "link_set_default_route",
        purpose: "Documents the link set default route entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_link_get_dnssec_mode",
        c_name: "link_get_dnssec_mode",
        purpose: "Documents the link get dnssec mode entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_link_dnssec_supported",
        c_name: "link_dnssec_supported",
        purpose: "Documents the link dnssec supported entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_link_get_dns_over_tls_mode",
        c_name: "link_get_dns_over_tls_mode",
        purpose: "Documents the link get dns over tls mode entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_link_get_llmnr_support",
        c_name: "link_get_llmnr_support",
        purpose: "Documents the link get llmnr support entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_link_get_mdns_support",
        c_name: "link_get_mdns_support",
        purpose: "Documents the link get mdns support entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_link_get_default_route",
        c_name: "link_get_default_route",
        purpose: "Documents the link get default route entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_link_save_user",
        c_name: "link_save_user",
        purpose: "Documents the link save user entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_link_load_user",
        c_name: "link_load_user",
        purpose: "Documents the link load user entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_link_remove_user",
        c_name: "link_remove_user",
        purpose: "Documents the link remove user entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_link_address_new",
        c_name: "link_address_new",
        purpose: "Documents the link address new entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_link_address_free",
        c_name: "link_address_free",
        purpose: "Documents the link address free entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_link_address_update_rtnl",
        c_name: "link_address_update_rtnl",
        purpose: "Documents the link address update rtnl entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_link_address_relevant",
        c_name: "link_address_relevant",
        purpose: "Documents the link address relevant entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_link_address_add_rrs",
        c_name: "link_address_add_rrs",
        purpose: "Documents the link address add rrs entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_link_negative_trust_anchor_lookup",
        c_name: "link_negative_trust_anchor_lookup",
        purpose: "Documents the link negative trust anchor lookup entry point from the synced C module.",
    },
];
pub const CONSTANTS: &[PortSyncConstant] = &[];

pub fn module_spec() -> PortSyncModule<'static> {
    PortSyncModule {
        rust_module: "resolved_link",
        source_path: SOURCE_PATH,
        summary: "Resolved link lifecycle, persisted settings, and address inventory.",
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
        let function = function("rs_link_new").unwrap();
        assert_eq!(function.c_name, "link_new");
    }
    #[test]
    fn function_lookup_finds_tail_symbol() {
        let function = function("rs_link_negative_trust_anchor_lookup").unwrap();
        assert_eq!(function.rust_name, "rs_link_negative_trust_anchor_lookup");
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
