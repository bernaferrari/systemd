// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/resolve/resolved-dns-scope.c
//
// DNS scope lifecycle, socket access, protocol checks, and JSON inventory.

use crate::port_sync::{PortSyncConstant, PortSyncError, PortSyncFunction, PortSyncModule};

pub const SOURCE_PATH: &str = "src/resolve/resolved-dns-scope.c";

pub const INCLUDED_HEADERS: &[&str] = &[
    "netinet/tcp.h",
    "sd-event.h",
    "sd-json.h",
    "af-list.h",
    "alloc-util.h",
    "dns-answer.h",
    "dns-domain.h",
    "dns-packet.h",
    "dns-question.h",
    "dns-rr.h",
    "dns-type.h",
    "errno-util.h",
    "fd-util.h",
    "hostname-util.h",
    "log.h",
    "random-util.h",
    "resolved-dns-browse-services.h",
    "resolved-dns-delegate.h",
    "resolved-dns-query.h",
    "resolved-dns-scope.h",
    "resolved-dns-search-domain.h",
    "resolved-dns-server.h",
    "resolved-dns-synthesize.h",
    "resolved-dns-transaction.h",
    "resolved-dns-zone.h",
    "resolved-dnssd.h",
    "resolved-link.h",
    "resolved-llmnr.h",
    "resolved-manager.h",
    "resolved-mdns.h",
    "resolved-timeouts.h",
    "set.h",
    "socket-util.h",
    "string-table.h",
];
pub const LOCAL_DEFINES: &[&str] = &[
    "MULTICAST_RATELIMIT_INTERVAL_USEC",
    "MULTICAST_RATELIMIT_BURST",
    "MULTICAST_RESEND_TIMEOUT_MIN_USEC",
    "MULTICAST_RESEND_TIMEOUT_MAX_USEC",
];
pub const FUNCTIONS: &[PortSyncFunction] = &[
    PortSyncFunction {
        rust_name: "rs_dns_scope_new",
        c_name: "dns_scope_new",
        purpose: "Documents the dns scope new entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_scope_free",
        c_name: "dns_scope_free",
        purpose: "Documents the dns scope free entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_scope_packet_received",
        c_name: "dns_scope_packet_received",
        purpose: "Documents the dns scope packet received entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_scope_packet_lost",
        c_name: "dns_scope_packet_lost",
        purpose: "Documents the dns scope packet lost entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_scope_emit_udp",
        c_name: "dns_scope_emit_udp",
        purpose: "Documents the dns scope emit udp entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_scope_socket_tcp",
        c_name: "dns_scope_socket_tcp",
        purpose: "Documents the dns scope socket tcp entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_scope_socket_udp",
        c_name: "dns_scope_socket_udp",
        purpose: "Documents the dns scope socket udp entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_scope_good_domain",
        c_name: "dns_scope_good_domain",
        purpose: "Documents the dns scope good domain entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_scope_good_key",
        c_name: "dns_scope_good_key",
        purpose: "Documents the dns scope good key entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_scope_get_dns_server",
        c_name: "dns_scope_get_dns_server",
        purpose: "Documents the dns scope get dns server entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_scope_get_n_dns_servers",
        c_name: "dns_scope_get_n_dns_servers",
        purpose: "Documents the dns scope get n dns servers entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_scope_next_dns_server",
        c_name: "dns_scope_next_dns_server",
        purpose: "Documents the dns scope next dns server entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_scope_llmnr_membership",
        c_name: "dns_scope_llmnr_membership",
        purpose: "Documents the dns scope llmnr membership entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_scope_mdns_membership",
        c_name: "dns_scope_mdns_membership",
        purpose: "Documents the dns scope mdns membership entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_scope_make_reply_packet",
        c_name: "dns_scope_make_reply_packet",
        purpose: "Documents the dns scope make reply packet entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_scope_process_query",
        c_name: "dns_scope_process_query",
        purpose: "Documents the dns scope process query entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_scope_find_transaction",
        c_name: "dns_scope_find_transaction",
        purpose: "Documents the dns scope find transaction entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_scope_notify_conflict",
        c_name: "dns_scope_notify_conflict",
        purpose: "Documents the dns scope notify conflict entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_scope_check_conflicts",
        c_name: "dns_scope_check_conflicts",
        purpose: "Documents the dns scope check conflicts entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_scope_dump",
        c_name: "dns_scope_dump",
        purpose: "Documents the dns scope dump entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_scope_get_search_domains",
        c_name: "dns_scope_get_search_domains",
        purpose: "Documents the dns scope get search domains entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_scope_name_wants_search_domain",
        c_name: "dns_scope_name_wants_search_domain",
        purpose: "Documents the dns scope name wants search domain entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_scope_network_good",
        c_name: "dns_scope_network_good",
        purpose: "Documents the dns scope network good entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_scope_ifindex",
        c_name: "dns_scope_ifindex",
        purpose: "Documents the dns scope ifindex entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_scope_ifname",
        c_name: "dns_scope_ifname",
        purpose: "Documents the dns scope ifname entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_scope_announce",
        c_name: "dns_scope_announce",
        purpose: "Documents the dns scope announce entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_scope_add_dnssd_registered_services",
        c_name: "dns_scope_add_dnssd_registered_services",
        purpose: "Documents the dns scope add dnssd registered services entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_scope_remove_dnssd_registered_services",
        c_name: "dns_scope_remove_dnssd_registered_services",
        purpose: "Documents the dns scope remove dnssd registered services entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_scope_is_default_route",
        c_name: "dns_scope_is_default_route",
        purpose: "Documents the dns scope is default route entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_scope_to_json",
        c_name: "dns_scope_to_json",
        purpose: "Documents the dns scope to json entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_type_suitable_for_protocol",
        c_name: "dns_type_suitable_for_protocol",
        purpose: "Documents the dns type suitable for protocol entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_question_types_suitable_for_protocol",
        c_name: "dns_question_types_suitable_for_protocol",
        purpose: "Documents the dns question types suitable for protocol entry point from the synced C module.",
    },
];
pub const CONSTANTS: &[PortSyncConstant] = &[];

pub fn module_spec() -> PortSyncModule<'static> {
    PortSyncModule {
        rust_module: "resolved_dns_scope",
        source_path: SOURCE_PATH,
        summary: "DNS scope lifecycle, socket access, protocol checks, and JSON inventory.",
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
        let function = function("rs_dns_scope_new").unwrap();
        assert_eq!(function.c_name, "dns_scope_new");
    }
    #[test]
    fn function_lookup_finds_tail_symbol() {
        let function = function("rs_dns_question_types_suitable_for_protocol").unwrap();
        assert_eq!(
            function.rust_name,
            "rs_dns_question_types_suitable_for_protocol"
        );
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
