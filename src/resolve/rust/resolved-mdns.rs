// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/resolve/resolved-mdns.c
//
// Multicast DNS (mDNS) socket setup, probe tiebreaking, and reply logic.
//
// Manages IPv4/IPv6 multicast sockets, implements probe tiebreaking per
// RFC 6762 section 8.2, handles goodbye packet detection, and populates
// the cache from unsolicited replies.

use crate::port_sync::{PortSyncConstant, PortSyncError, PortSyncFunction, PortSyncModule};

pub const MDNS_PORT: u16 = 5353;
pub const MDNS_ANNOUNCE_DELAY: u64 = 1_000_000;

pub const SOURCE_PATH: &str = "src/resolve/resolved-mdns.c";

pub const INCLUDED_HEADERS: &[&str] = &[
    "netinet/in.h",
    "sd-event.h",
    "alloc-util.h",
    "dns-answer.h",
    "dns-domain.h",
    "dns-packet.h",
    "dns-question.h",
    "dns-rr.h",
    "fd-util.h",
    "log.h",
    "resolved-dns-scope.h",
    "resolved-dns-transaction.h",
    "resolved-link.h",
    "resolved-manager.h",
    "resolved-mdns.h",
    "sort-util.h",
    "time-util.h",
];

pub const LOCAL_DEFINES: &[&str] = &["CLEAR_CACHE_FLUSH"];

pub const FUNCTIONS: &[PortSyncFunction] = &[
    PortSyncFunction {
        rust_name: "rs_manager_mdns_ipv4_fd",
        c_name: "manager_mdns_ipv4_fd",
        purpose: "Creates the IPv4 multicast mDNS socket.",
    },
    PortSyncFunction {
        rust_name: "rs_manager_mdns_ipv6_fd",
        c_name: "manager_mdns_ipv6_fd",
        purpose: "Creates the IPv6 multicast mDNS socket.",
    },
    PortSyncFunction {
        rust_name: "rs_manager_mdns_stop",
        c_name: "manager_mdns_stop",
        purpose: "Closes all mDNS sockets.",
    },
    PortSyncFunction {
        rust_name: "rs_manager_mdns_maybe_stop",
        c_name: "manager_mdns_maybe_stop",
        purpose: "Closes mDNS sockets if no link requires mDNS.",
    },
    PortSyncFunction {
        rust_name: "rs_manager_mdns_start",
        c_name: "manager_mdns_start",
        purpose: "Opens mDNS sockets if any link requires mDNS.",
    },
];

pub const CONSTANTS: &[PortSyncConstant] = &[
    PortSyncConstant {
        name: "MDNS_PORT",
        value: "5353",
        purpose: "Standard mDNS port number (RFC 6762).",
    },
    PortSyncConstant {
        name: "MDNS_ANNOUNCE_DELAY",
        value: "1000000",
        purpose: "Delay before mDNS announcements in microseconds.",
    },
];

pub fn module_spec() -> PortSyncModule<'static> {
    PortSyncModule {
        rust_module: "resolved_mdns",
        source_path: SOURCE_PATH,
        summary: "Multicast DNS socket setup, probe tiebreaking, and reply logic.",
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
    fn function_lookup_finds_ipv4_fd() {
        let f = function("rs_manager_mdns_ipv4_fd").unwrap();
        assert_eq!(f.c_name, "manager_mdns_ipv4_fd");
    }

    #[test]
    fn function_lookup_finds_start() {
        let f = function("rs_manager_mdns_start").unwrap();
        assert_eq!(f.c_name, "manager_mdns_start");
    }

    #[test]
    fn all_functions_have_nonempty_purpose() {
        for f in FUNCTIONS {
            assert!(!f.purpose.is_empty(), "purpose empty for {}", f.rust_name);
        }
    }

    #[test]
    fn constant_lookup_finds_port() {
        let c = constant("MDNS_PORT").unwrap();
        assert_eq!(c.value, "5353");
    }

    #[test]
    fn mdns_port_matches_rfc() {
        assert_eq!(MDNS_PORT, 5353);
    }

    #[test]
    fn unknown_function_reports_requested_name() {
        assert_eq!(
            function("does_not_exist"),
            Err(PortSyncError::UnknownFunction("does_not_exist".to_owned())),
        );
    }
}
