// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/resolve/resolved-dns-zone.c
//
// Authoritative DNS zone lookup, mutation, and conflict verification inventory.

use crate::port_sync::{PortSyncConstant, PortSyncError, PortSyncFunction, PortSyncModule};

pub const SOURCE_PATH: &str = "src/resolve/resolved-dns-zone.c";

pub const INCLUDED_HEADERS: &[&str] = &[
    "stdio.h",
    "alloc-util.h",
    "dns-answer.h",
    "dns-domain.h",
    "dns-packet.h",
    "dns-rr.h",
    "list.h",
    "log.h",
    "resolved-dns-scope.h",
    "resolved-dns-transaction.h",
    "resolved-dns-zone.h",
    "resolved-dnssd.h",
    "resolved-manager.h",
    "set.h",
    "string-util.h",
];
pub const LOCAL_DEFINES: &[&str] = &["ZONE_MAX"];
pub const FUNCTIONS: &[PortSyncFunction] = &[
    PortSyncFunction {
        rust_name: "rs_dns_zone_flush",
        c_name: "dns_zone_flush",
        purpose: "Documents the dns zone flush entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_zone_put",
        c_name: "dns_zone_put",
        purpose: "Documents the dns zone put entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_zone_get",
        c_name: "dns_zone_get",
        purpose: "Documents the dns zone get entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_zone_remove_rr",
        c_name: "dns_zone_remove_rr",
        purpose: "Documents the dns zone remove rr entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_zone_remove_rrs_by_key",
        c_name: "dns_zone_remove_rrs_by_key",
        purpose: "Documents the dns zone remove rrs by key entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_zone_lookup",
        c_name: "dns_zone_lookup",
        purpose: "Documents the dns zone lookup entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_zone_item_conflict",
        c_name: "dns_zone_item_conflict",
        purpose: "Documents the dns zone item conflict entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_zone_item_notify",
        c_name: "dns_zone_item_notify",
        purpose: "Documents the dns zone item notify entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_zone_check_conflicts",
        c_name: "dns_zone_check_conflicts",
        purpose: "Documents the dns zone check conflicts entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_zone_verify_conflicts",
        c_name: "dns_zone_verify_conflicts",
        purpose: "Documents the dns zone verify conflicts entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_zone_verify_all",
        c_name: "dns_zone_verify_all",
        purpose: "Documents the dns zone verify all entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_zone_item_probe_stop",
        c_name: "dns_zone_item_probe_stop",
        purpose: "Documents the dns zone item probe stop entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_zone_dump",
        c_name: "dns_zone_dump",
        purpose: "Documents the dns zone dump entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_zone_is_empty",
        c_name: "dns_zone_is_empty",
        purpose: "Documents the dns zone is empty entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_zone_contains_name",
        c_name: "dns_zone_contains_name",
        purpose: "Documents the dns zone contains name entry point from the synced C module.",
    },
];
pub const CONSTANTS: &[PortSyncConstant] = &[];

pub fn module_spec() -> PortSyncModule<'static> {
    PortSyncModule {
        rust_module: "resolved_dns_zone",
        source_path: SOURCE_PATH,
        summary: "Authoritative DNS zone lookup, mutation, and conflict verification inventory.",
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
        let function = function("rs_dns_zone_flush").unwrap();
        assert_eq!(function.c_name, "dns_zone_flush");
    }
    #[test]
    fn function_lookup_finds_tail_symbol() {
        let function = function("rs_dns_zone_contains_name").unwrap();
        assert_eq!(function.rust_name, "rs_dns_zone_contains_name");
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
