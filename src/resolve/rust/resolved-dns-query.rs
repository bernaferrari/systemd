// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/resolve/resolved-dns-query.c
//
// DNS query candidate lifecycle, completion, and reply-flag inventory.

use crate::port_sync::{PortSyncConstant, PortSyncError, PortSyncFunction, PortSyncModule};

pub const SOURCE_PATH: &str = "src/resolve/resolved-dns-query.c";

pub const INCLUDED_HEADERS: &[&str] = &[
    "sd-bus.h",
    "sd-varlink.h",
    "alloc-util.h",
    "dns-answer.h",
    "dns-domain.h",
    "dns-packet.h",
    "dns-question.h",
    "dns-rr.h",
    "dns-type.h",
    "event-util.h",
    "glyph-util.h",
    "log.h",
    "resolved-dns-query.h",
    "resolved-dns-scope.h",
    "resolved-dns-search-domain.h",
    "resolved-dns-synthesize.h",
    "resolved-dns-transaction.h",
    "resolved-etc-hosts.h",
    "resolved-hook.h",
    "resolved-manager.h",
    "resolved-static-records.h",
    "resolved-timeouts.h",
    "set.h",
    "string-util.h",
];
pub const LOCAL_DEFINES: &[&str] = &[
    "QUERIES_MAX",
    "AUXILIARY_QUERIES_MAX",
    "CNAME_REDIRECTS_MAX",
];
pub const FUNCTIONS: &[PortSyncFunction] = &[
    PortSyncFunction {
        rust_name: "rs_dns_query_candidate_unref",
        c_name: "dns_query_candidate_unref",
        purpose: "Documents the dns query candidate unref entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_query_candidate_ref",
        c_name: "dns_query_candidate_ref",
        purpose: "Documents the dns query candidate ref entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_query_candidate_notify",
        c_name: "dns_query_candidate_notify",
        purpose: "Documents the dns query candidate notify entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_query_new",
        c_name: "dns_query_new",
        purpose: "Documents the dns query new entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_query_free",
        c_name: "dns_query_free",
        purpose: "Documents the dns query free entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_query_make_auxiliary",
        c_name: "dns_query_make_auxiliary",
        purpose: "Documents the dns query make auxiliary entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_query_go",
        c_name: "dns_query_go",
        purpose: "Documents the dns query go entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_query_ready",
        c_name: "dns_query_ready",
        purpose: "Documents the dns query ready entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_query_process_cname_one",
        c_name: "dns_query_process_cname_one",
        purpose: "Documents the dns query process cname one entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_query_process_cname_many",
        c_name: "dns_query_process_cname_many",
        purpose: "Documents the dns query process cname many entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_query_complete",
        c_name: "dns_query_complete",
        purpose: "Documents the dns query complete entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_query_question_for_protocol",
        c_name: "dns_query_question_for_protocol",
        purpose: "Documents the dns query question for protocol entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_query_string",
        c_name: "dns_query_string",
        purpose: "Documents the dns query string entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_query_fully_authenticated",
        c_name: "dns_query_fully_authenticated",
        purpose: "Documents the dns query fully authenticated entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_query_fully_confidential",
        c_name: "dns_query_fully_confidential",
        purpose: "Documents the dns query fully confidential entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_query_fully_authoritative",
        c_name: "dns_query_fully_authoritative",
        purpose: "Documents the dns query fully authoritative entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_validate_and_mangle_query_flags",
        c_name: "validate_and_mangle_query_flags",
        purpose: "Documents the validate and mangle query flags entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_query_reply_flags_make",
        c_name: "dns_query_reply_flags_make",
        purpose: "Documents the dns query reply flags make entry point from the synced C module.",
    },
];
pub const CONSTANTS: &[PortSyncConstant] = &[];

pub fn module_spec() -> PortSyncModule<'static> {
    PortSyncModule {
        rust_module: "resolved_dns_query",
        source_path: SOURCE_PATH,
        summary: "DNS query candidate lifecycle, completion, and reply-flag inventory.",
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
        let function = function("rs_dns_query_candidate_unref").unwrap();
        assert_eq!(function.c_name, "dns_query_candidate_unref");
    }
    #[test]
    fn function_lookup_finds_tail_symbol() {
        let function = function("rs_dns_query_reply_flags_make").unwrap();
        assert_eq!(function.rust_name, "rs_dns_query_reply_flags_make");
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
