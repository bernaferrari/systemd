// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/resolve/resolved-dns-dnssec.c
//
// DNSSEC signature matching, verification, and proof helper inventory.

use crate::port_sync::{PortSyncConstant, PortSyncError, PortSyncFunction, PortSyncModule};

pub const SOURCE_PATH: &str = "src/resolve/resolved-dns-dnssec.c";

pub const INCLUDED_HEADERS: &[&str] = &[
    "alloc-util.h",
    "bitmap.h",
    "dns-answer.h",
    "dns-domain.h",
    "dns-rr.h",
    "dns-type.h",
    "hexdecoct.h",
    "log.h",
    "memory-util.h",
    "memstream-util.h",
    "openssl-util.h",
    "resolved-dns-dnssec.h",
    "sort-util.h",
    "string-table.h",
    "string-util.h",
    "time-util.h",
];
pub const LOCAL_DEFINES: &[&str] = &[
    "VERIFY_RRS_MAX",
    "MAX_KEY_SIZE",
    "SKEW_MAX",
    "NSEC3_ITERATIONS_MAX",
];
pub const FUNCTIONS: &[PortSyncFunction] = &[
    PortSyncFunction {
        rust_name: "rs_dnssec_rrsig_match_dnskey",
        c_name: "dnssec_rrsig_match_dnskey",
        purpose: "Documents the dnssec rrsig match dnskey entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dnssec_key_match_rrsig",
        c_name: "dnssec_key_match_rrsig",
        purpose: "Documents the dnssec key match rrsig entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dnssec_verify_rrset",
        c_name: "dnssec_verify_rrset",
        purpose: "Documents the dnssec verify rrset entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dnssec_verify_rrset_search",
        c_name: "dnssec_verify_rrset_search",
        purpose: "Documents the dnssec verify rrset search entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dnssec_verify_dnskey_by_ds",
        c_name: "dnssec_verify_dnskey_by_ds",
        purpose: "Documents the dnssec verify dnskey by ds entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dnssec_verify_dnskey_by_ds_search",
        c_name: "dnssec_verify_dnskey_by_ds_search",
        purpose: "Documents the dnssec verify dnskey by ds search entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dnssec_has_rrsig",
        c_name: "dnssec_has_rrsig",
        purpose: "Documents the dnssec has rrsig entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dnssec_nsec3_hash",
        c_name: "dnssec_nsec3_hash",
        purpose: "Documents the dnssec nsec3 hash entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dnssec_nsec_test",
        c_name: "dnssec_nsec_test",
        purpose: "Documents the dnssec nsec test entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dnssec_test_positive_wildcard",
        c_name: "dnssec_test_positive_wildcard",
        purpose: "Documents the dnssec test positive wildcard entry point from the synced C module.",
    },
];
pub const CONSTANTS: &[PortSyncConstant] = &[];

pub fn module_spec() -> PortSyncModule<'static> {
    PortSyncModule {
        rust_module: "resolved_dns_dnssec",
        source_path: SOURCE_PATH,
        summary: "DNSSEC signature matching, verification, and proof helper inventory.",
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
        let function = function("rs_dnssec_rrsig_match_dnskey").unwrap();
        assert_eq!(function.c_name, "dnssec_rrsig_match_dnskey");
    }
    #[test]
    fn function_lookup_finds_tail_symbol() {
        let function = function("rs_dnssec_test_positive_wildcard").unwrap();
        assert_eq!(function.rust_name, "rs_dnssec_test_positive_wildcard");
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
