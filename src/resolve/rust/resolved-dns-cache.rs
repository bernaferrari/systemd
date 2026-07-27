// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/resolve/resolved-dns-cache.c
//
// DNS cache lookup, conflict detection, and export inventory.

use crate::port_sync::{PortSyncConstant, PortSyncError, PortSyncFunction, PortSyncModule};

pub const SOURCE_PATH: &str = "src/resolve/resolved-dns-cache.c";

pub const INCLUDED_HEADERS: &[&str] = &[
    "sd-json.h",
    "af-list.h",
    "alloc-util.h",
    "bitmap.h",
    "dns-answer.h",
    "dns-domain.h",
    "dns-packet.h",
    "dns-rr.h",
    "format-ifname.h",
    "log.h",
    "prioq.h",
    "resolve-util.h",
    "resolved-dns-cache.h",
    "resolved-dns-dnssec.h",
    "string-util.h",
    "time-util.h",
];
pub const LOCAL_DEFINES: &[&str] = &[
    "CACHE_MAX",
    "CACHE_TTL_MAX_USEC",
    "CACHE_STALE_TTL_MAX_USEC",
    "CACHE_TTL_STRANGE_RCODE_USEC",
    "CACHEABLE_QUERY_FLAGS",
    "DNS_CACHE_ITEM_IS_PRIMARY",
];
pub const FUNCTIONS: &[PortSyncFunction] = &[
    PortSyncFunction {
        rust_name: "rs_dns_cache_flush",
        c_name: "dns_cache_flush",
        purpose: "Documents the dns cache flush entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_cache_prune",
        c_name: "dns_cache_prune",
        purpose: "Documents the dns cache prune entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_cache_put",
        c_name: "dns_cache_put",
        purpose: "Documents the dns cache put entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_cache_lookup",
        c_name: "dns_cache_lookup",
        purpose: "Documents the dns cache lookup entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_cache_check_conflicts",
        c_name: "dns_cache_check_conflicts",
        purpose: "Documents the dns cache check conflicts entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_cache_dump",
        c_name: "dns_cache_dump",
        purpose: "Documents the dns cache dump entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_cache_dump_to_json",
        c_name: "dns_cache_dump_to_json",
        purpose: "Documents the dns cache dump to json entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_cache_is_empty",
        c_name: "dns_cache_is_empty",
        purpose: "Documents the dns cache is empty entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_cache_size",
        c_name: "dns_cache_size",
        purpose: "Documents the dns cache size entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_cache_export_shared_to_packet",
        c_name: "dns_cache_export_shared_to_packet",
        purpose: "Documents the dns cache export shared to packet entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_cache_expiry_in_one_second",
        c_name: "dns_cache_expiry_in_one_second",
        purpose: "Documents the dns cache expiry in one second entry point from the synced C module.",
    },
];
pub const CONSTANTS: &[PortSyncConstant] = &[];

pub fn module_spec() -> PortSyncModule<'static> {
    PortSyncModule {
        rust_module: "resolved_dns_cache",
        source_path: SOURCE_PATH,
        summary: "DNS cache lookup, conflict detection, and export inventory.",
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
        let function = function("rs_dns_cache_flush").unwrap();
        assert_eq!(function.c_name, "dns_cache_flush");
    }
    #[test]
    fn function_lookup_finds_tail_symbol() {
        let function = function("rs_dns_cache_expiry_in_one_second").unwrap();
        assert_eq!(function.rust_name, "rs_dns_cache_expiry_in_one_second");
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
