// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/resolve/resolved-dns-browse-services.c
//
// mDNS browse-service discovery, update, and notification inventory.

use crate::port_sync::{PortSyncConstant, PortSyncError, PortSyncFunction, PortSyncModule};

pub const SOURCE_PATH: &str = "src/resolve/resolved-dns-browse-services.c";

pub const INCLUDED_HEADERS: &[&str] = &[
    "af-list.h",
    "alloc-util.h",
    "dns-domain.h",
    "dns-question.h",
    "dns-rr.h",
    "event-util.h",
    "log.h",
    "random-util.h",
    "resolved-dns-browse-services.h",
    "resolved-dns-cache.h",
    "resolved-dns-query.h",
    "resolved-dns-scope.h",
    "resolved-manager.h",
    "string-table.h",
    "string-util.h",
];
pub const LOCAL_DEFINES: &[&str] = &[];
pub const FUNCTIONS: &[PortSyncFunction] = &[
    PortSyncFunction {
        rust_name: "rs_dns_service_browser_free",
        c_name: "dns_service_browser_free",
        purpose: "Documents the dns service browser free entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_service_browser_unref",
        c_name: "dns_service_browser_unref",
        purpose: "Documents the dns service browser unref entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_service_browser_ref",
        c_name: "dns_service_browser_ref",
        purpose: "Documents the dns service browser ref entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_remove_service",
        c_name: "dns_remove_service",
        purpose: "Documents the dns remove service entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_service_free",
        c_name: "dns_service_free",
        purpose: "Documents the dns service free entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dnssd_discovered_service_unref",
        c_name: "dnssd_discovered_service_unref",
        purpose: "Documents the dnssd discovered service unref entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dnssd_discovered_service_ref",
        c_name: "dnssd_discovered_service_ref",
        purpose: "Documents the dnssd discovered service ref entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_browse_services_purge",
        c_name: "dns_browse_services_purge",
        purpose: "Documents the dns browse services purge entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_browse_services_restart",
        c_name: "dns_browse_services_restart",
        purpose: "Documents the dns browse services restart entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_service_match_and_update",
        c_name: "dns_service_match_and_update",
        purpose: "Documents the dns service match and update entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_mdns_manage_services_answer",
        c_name: "mdns_manage_services_answer",
        purpose: "Documents the mdns manage services answer entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_add_new_service",
        c_name: "dns_add_new_service",
        purpose: "Documents the dns add new service entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_mdns_service_update",
        c_name: "mdns_service_update",
        purpose: "Documents the mdns service update entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_mdns_browser_revisit_cache",
        c_name: "mdns_browser_revisit_cache",
        purpose: "Documents the mdns browser revisit cache entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_subscribe_browse_service",
        c_name: "dns_subscribe_browse_service",
        purpose: "Documents the dns subscribe browse service entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_mdns_notify_browsers_unsolicited_updates",
        c_name: "mdns_notify_browsers_unsolicited_updates",
        purpose: "Documents the mdns notify browsers unsolicited updates entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_mdns_notify_browsers_goodbye",
        c_name: "mdns_notify_browsers_goodbye",
        purpose: "Documents the mdns notify browsers goodbye entry point from the synced C module.",
    },
];
pub const CONSTANTS: &[PortSyncConstant] = &[];

pub fn module_spec() -> PortSyncModule<'static> {
    PortSyncModule {
        rust_module: "resolved_dns_browse_services",
        source_path: SOURCE_PATH,
        summary: "mDNS browse-service discovery, update, and notification inventory.",
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
        let function = function("rs_dns_service_browser_free").unwrap();
        assert_eq!(function.c_name, "dns_service_browser_free");
    }
    #[test]
    fn function_lookup_finds_tail_symbol() {
        let function = function("rs_mdns_notify_browsers_goodbye").unwrap();
        assert_eq!(function.rust_name, "rs_mdns_notify_browsers_goodbye");
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
