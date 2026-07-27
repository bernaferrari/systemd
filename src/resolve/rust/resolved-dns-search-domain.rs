// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/resolve/resolved-dns-search-domain.c
//
// Search-domain lifecycle, marking, and JSON export inventory.

use crate::port_sync::{PortSyncConstant, PortSyncError, PortSyncFunction, PortSyncModule};

pub const SOURCE_PATH: &str = "src/resolve/resolved-dns-search-domain.c";

pub const SOURCE_LINE_COUNT: usize = 245;

pub const INCLUDED_HEADERS: &[&str] = &[
    "sd-json.h",
    "alloc-util.h",
    "dns-domain.h",
    "resolved-dns-delegate.h",
    "resolved-dns-search-domain.h",
    "resolved-link.h",
    "resolved-manager.h",
];
pub const LOCAL_DEFINES: &[&str] = &[];
pub const FUNCTIONS: &[PortSyncFunction] = &[
    PortSyncFunction {
        rust_name: "rs_dns_search_domain_new",
        c_name: "dns_search_domain_new",
        purpose: "Documents the dns search domain new entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_search_domain_unref",
        c_name: "dns_search_domain_unref",
        purpose: "Documents the dns search domain unref entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_search_domain_ref",
        c_name: "dns_search_domain_ref",
        purpose: "Documents the dns search domain ref entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_search_domain_unlink",
        c_name: "dns_search_domain_unlink",
        purpose: "Documents the dns search domain unlink entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_search_domain_move_back_and_unmark",
        c_name: "dns_search_domain_move_back_and_unmark",
        purpose: "Documents the dns search domain move back and unmark entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_search_domain_unlink_all",
        c_name: "dns_search_domain_unlink_all",
        purpose: "Documents the dns search domain unlink all entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_search_domain_unlink_marked",
        c_name: "dns_search_domain_unlink_marked",
        purpose: "Documents the dns search domain unlink marked entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_search_domain_mark_all",
        c_name: "dns_search_domain_mark_all",
        purpose: "Documents the dns search domain mark all entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_search_domain_find",
        c_name: "dns_search_domain_find",
        purpose: "Documents the dns search domain find entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_search_domain_dump_to_json",
        c_name: "dns_search_domain_dump_to_json",
        purpose: "Documents the dns search domain dump to json entry point from the synced C module.",
    },
];
pub const CONSTANTS: &[PortSyncConstant] = &[PortSyncConstant {
    name: "SOURCE_LINE_COUNT",
    value: "245",
    purpose: "Tracks the synced C source line count for quick drift checks.",
}];

pub fn module_spec() -> PortSyncModule<'static> {
    PortSyncModule {
        rust_module: "resolved_dns_search_domain",
        source_path: SOURCE_PATH,
        summary: "Search-domain lifecycle, marking, and JSON export inventory.",
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
        let function = function("rs_dns_search_domain_new").unwrap();
        assert_eq!(function.c_name, "dns_search_domain_new");
    }
    #[test]
    fn function_lookup_finds_tail_symbol() {
        let function = function("rs_dns_search_domain_dump_to_json").unwrap();
        assert_eq!(function.rust_name, "rs_dns_search_domain_dump_to_json");
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
