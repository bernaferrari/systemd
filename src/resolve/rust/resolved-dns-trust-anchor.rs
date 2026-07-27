// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/resolve/resolved-dns-trust-anchor.c
//
// DNSSEC trust anchor loading, flushing, and revocation inventory.

use crate::port_sync::{PortSyncConstant, PortSyncError, PortSyncFunction, PortSyncModule};

pub const SOURCE_PATH: &str = "src/resolve/resolved-dns-trust-anchor.c";

pub const SOURCE_LINE_COUNT: usize = 787;

pub const INCLUDED_HEADERS: &[&str] = &[
    "sd-messages.h",
    "alloc-util.h",
    "conf-files.h",
    "constants.h",
    "dns-answer.h",
    "dns-domain.h",
    "dns-rr.h",
    "extract-word.h",
    "fd-util.h",
    "fileio.h",
    "hexdecoct.h",
    "log.h",
    "nulstr-util.h",
    "parse-util.h",
    "resolved-dns-dnssec.h",
    "resolved-dns-trust-anchor.h",
    "set.h",
    "string-util.h",
    "strv.h",
];
pub const LOCAL_DEFINES: &[&str] = &[];
pub const FUNCTIONS: &[PortSyncFunction] = &[
    PortSyncFunction {
        rust_name: "rs_dns_trust_anchor_load",
        c_name: "dns_trust_anchor_load",
        purpose: "Documents the dns trust anchor load entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_trust_anchor_flush",
        c_name: "dns_trust_anchor_flush",
        purpose: "Documents the dns trust anchor flush entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_trust_anchor_lookup_positive",
        c_name: "dns_trust_anchor_lookup_positive",
        purpose: "Documents the dns trust anchor lookup positive entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_trust_anchor_lookup_negative",
        c_name: "dns_trust_anchor_lookup_negative",
        purpose: "Documents the dns trust anchor lookup negative entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_trust_anchor_check_revoked",
        c_name: "dns_trust_anchor_check_revoked",
        purpose: "Documents the dns trust anchor check revoked entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_trust_anchor_is_revoked",
        c_name: "dns_trust_anchor_is_revoked",
        purpose: "Documents the dns trust anchor is revoked entry point from the synced C module.",
    },
];
pub const CONSTANTS: &[PortSyncConstant] = &[PortSyncConstant {
    name: "SOURCE_LINE_COUNT",
    value: "787",
    purpose: "Tracks the synced C source line count for quick drift checks.",
}];

pub fn module_spec() -> PortSyncModule<'static> {
    PortSyncModule {
        rust_module: "resolved_dns_trust_anchor",
        source_path: SOURCE_PATH,
        summary: "DNSSEC trust anchor loading, flushing, and revocation inventory.",
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
        let function = function("rs_dns_trust_anchor_load").unwrap();
        assert_eq!(function.c_name, "dns_trust_anchor_load");
    }
    #[test]
    fn function_lookup_finds_tail_symbol() {
        let function = function("rs_dns_trust_anchor_is_revoked").unwrap();
        assert_eq!(function.rust_name, "rs_dns_trust_anchor_is_revoked");
    }
    #[test]
    fn constant_lookup_finds_documented_constant() {
        let constant = constant("SOURCE_LINE_COUNT").unwrap();
        assert_eq!(constant.name, "SOURCE_LINE_COUNT");
    }
    #[test]
    fn unknown_function_reports_requested_name() {
        assert_eq!(
            function("does_not_exist"),
            Err(PortSyncError::UnknownFunction("does_not_exist".to_owned())),
        );
    }
}
