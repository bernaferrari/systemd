// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/resolve/resolved-dns-transaction.c
//
// DNS transaction lifecycle, progression, and key-request inventory.

use crate::port_sync::{PortSyncConstant, PortSyncError, PortSyncFunction, PortSyncModule};

pub const SOURCE_PATH: &str = "src/resolve/resolved-dns-transaction.c";

pub const INCLUDED_HEADERS: &[&str] = &[
    "sd-event.h",
    "sd-messages.h",
    "af-list.h",
    "alloc-util.h",
    "dns-answer.h",
    "dns-domain.h",
    "dns-packet.h",
    "dns-question.h",
    "dns-rr.h",
    "errno-list.h",
    "errno-util.h",
    "fd-util.h",
    "glyph-util.h",
    "log.h",
    "random-util.h",
    "resolved-dns-cache.h",
    "resolved-dns-query.h",
    "resolved-dns-scope.h",
    "resolved-dns-server.h",
    "resolved-dns-stream.h",
    "resolved-dns-transaction.h",
    "resolved-dnstls.h",
    "resolved-link.h",
    "resolved-llmnr.h",
    "resolved-manager.h",
    "resolved-socket-graveyard.h",
    "resolved-timeouts.h",
    "set.h",
    "string-table.h",
    "string-util.h",
];
pub const LOCAL_DEFINES: &[&str] = &["TRANSACTIONS_MAX"];
pub const FUNCTIONS: &[PortSyncFunction] = &[
    PortSyncFunction {
        rust_name: "rs_dns_transaction_new",
        c_name: "dns_transaction_new",
        purpose: "Documents the dns transaction new entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_transaction_free",
        c_name: "dns_transaction_free",
        purpose: "Documents the dns transaction free entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_transaction_gc",
        c_name: "dns_transaction_gc",
        purpose: "Documents the dns transaction gc entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_transaction_go",
        c_name: "dns_transaction_go",
        purpose: "Documents the dns transaction go entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_transaction_process_reply",
        c_name: "dns_transaction_process_reply",
        purpose: "Documents the dns transaction process reply entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_transaction_complete",
        c_name: "dns_transaction_complete",
        purpose: "Documents the dns transaction complete entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_transaction_notify",
        c_name: "dns_transaction_notify",
        purpose: "Documents the dns transaction notify entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_transaction_validate_dnssec",
        c_name: "dns_transaction_validate_dnssec",
        purpose: "Documents the dns transaction validate dnssec entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_transaction_request_dnssec_keys",
        c_name: "dns_transaction_request_dnssec_keys",
        purpose: "Documents the dns transaction request dnssec keys entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_transaction_key",
        c_name: "dns_transaction_key",
        purpose: "Documents the dns transaction key entry point from the synced C module.",
    },
];
pub const CONSTANTS: &[PortSyncConstant] = &[];

pub fn module_spec() -> PortSyncModule<'static> {
    PortSyncModule {
        rust_module: "resolved_dns_transaction",
        source_path: SOURCE_PATH,
        summary: "DNS transaction lifecycle, progression, and key-request inventory.",
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
        let function = function("rs_dns_transaction_new").unwrap();
        assert_eq!(function.c_name, "dns_transaction_new");
    }
    #[test]
    fn function_lookup_finds_tail_symbol() {
        let function = function("rs_dns_transaction_key").unwrap();
        assert_eq!(function.rust_name, "rs_dns_transaction_key");
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
