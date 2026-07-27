// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/resolve/resolved-dns-delegate.c
//
// Delegated DNS zone configuration loading and server management.
//
// Loads per-zone DNS delegation configuration from drop-in files, manages
// delegated DNS servers with round-robin selection, and creates associated
// DNS scopes for delegated domains.

use crate::port_sync::{PortSyncConstant, PortSyncError, PortSyncFunction, PortSyncModule};

pub const DNS_DELEGATES_MAX: u32 = 4096;

pub const SOURCE_PATH: &str = "src/resolve/resolved-dns-delegate.c";

pub const INCLUDED_HEADERS: &[&str] = &[
    "alloc-util.h",
    "conf-files.h",
    "conf-parser.h",
    "constants.h",
    "dns-domain.h",
    "extract-word.h",
    "hashmap.h",
    "in-addr-util.h",
    "log.h",
    "path-util.h",
    "resolved-dns-delegate.h",
    "resolved-dns-scope.h",
    "resolved-dns-search-domain.h",
    "resolved-dns-server.h",
    "resolved-manager.h",
    "socket-netlink.h",
    "string-util.h",
    "strv.h",
];

pub const LOCAL_DEFINES: &[&str] = &["DNS_DELEGATES_MAX", "DNS_DELEGATE_SEARCH_DIRS"];

pub const FUNCTIONS: &[PortSyncFunction] = &[
    PortSyncFunction {
        rust_name: "rs_dns_delegate_new",
        c_name: "dns_delegate_new",
        purpose: "Allocates a new DNS delegate structure.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_delegate_free",
        c_name: "dns_delegate_free",
        purpose: "Frees a DNS delegate and its servers/domains.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_delegate_set_dns_server",
        c_name: "dns_delegate_set_dns_server",
        purpose: "Sets the current DNS server for a delegate.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_delegate_get_dns_server",
        c_name: "dns_delegate_get_dns_server",
        purpose: "Returns the current DNS server for a delegate.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_delegate_next_dns_server",
        c_name: "dns_delegate_next_dns_server",
        purpose: "Advances to the next DNS server (round-robin).",
    },
    PortSyncFunction {
        rust_name: "rs_manager_load_delegates",
        c_name: "manager_load_delegates",
        purpose: "Loads all delegate configuration files.",
    },
];

pub const CONSTANTS: &[PortSyncConstant] = &[PortSyncConstant {
    name: "DNS_DELEGATES_MAX",
    value: "4096",
    purpose: "Maximum number of DNS delegates allowed.",
}];

pub fn module_spec() -> PortSyncModule<'static> {
    PortSyncModule {
        rust_module: "resolved_dns_delegate",
        source_path: SOURCE_PATH,
        summary: "Delegated DNS zone configuration loading and server management.",
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
    fn source_path_targets_resolve_subdirectory() {
        assert!(SOURCE_PATH.starts_with("src/resolve/"));
        assert!(SOURCE_PATH.ends_with(".c"));
    }

    #[test]
    fn validate_accepts_well_formed_inventory() {
        assert_eq!(validate(), Ok(()));
    }

    #[test]
    fn module_summary_is_nonempty() {
        assert!(!module_spec().summary.trim().is_empty());
    }

    #[test]
    fn function_lookup_finds_new() {
        let f = function("rs_dns_delegate_new").unwrap();
        assert_eq!(f.c_name, "dns_delegate_new");
    }

    #[test]
    fn function_lookup_finds_load() {
        let f = function("rs_manager_load_delegates").unwrap();
        assert_eq!(f.c_name, "manager_load_delegates");
    }

    #[test]
    fn all_functions_have_nonempty_purpose() {
        for f in FUNCTIONS {
            assert!(!f.purpose.is_empty(), "purpose empty for {}", f.rust_name);
        }
    }

    #[test]
    fn delegates_max_is_positive() {
        assert!(DNS_DELEGATES_MAX > 0);
    }

    #[test]
    fn unknown_function_reports_requested_name() {
        assert_eq!(
            function("does_not_exist"),
            Err(PortSyncError::UnknownFunction("does_not_exist".to_owned())),
        );
    }

    #[test]
    fn unknown_constant_reports_requested_name() {
        assert_eq!(
            constant("does_not_exist"),
            Err(PortSyncError::UnknownConstant("does_not_exist".to_owned())),
        );
    }
}
