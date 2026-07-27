// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/resolve/resolved-dns-server.c
//
// DNS server lifecycle, selection, formatting, and configuration dump inventory.

use crate::port_sync::{PortSyncConstant, PortSyncError, PortSyncFunction, PortSyncModule};

pub const SOURCE_PATH: &str = "src/resolve/resolved-dns-server.c";

pub const SOURCE_LINE_COUNT: usize = 1383;

pub const INCLUDED_HEADERS: &[&str] = &[
    "sd-event.h",
    "sd-messages.h",
    "alloc-util.h",
    "dns-domain.h",
    "dns-packet.h",
    "errno-util.h",
    "extract-word.h",
    "fd-util.h",
    "hash-funcs.h",
    "json-util.h",
    "resolved-bus.h",
    "resolved-dns-cache.h",
    "resolved-dns-delegate.h",
    "resolved-dns-scope.h",
    "resolved-dns-search-domain.h",
    "resolved-dns-server.h",
    "resolved-link.h",
    "resolved-manager.h",
    "resolved-resolv-conf.h",
    "siphash24.h",
    "socket-netlink.h",
    "socket-util.h",
    "string-table.h",
    "string-util.h",
    "time-util.h",
];
pub const LOCAL_DEFINES: &[&str] = &[
    "DNS_SERVER_FEATURE_GRACE_PERIOD_MAX_USEC",
    "DNS_SERVER_FEATURE_GRACE_PERIOD_MIN_USEC",
    "DNS_SERVER_FEATURE_RETRY_ATTEMPTS",
];
pub const FUNCTIONS: &[PortSyncFunction] = &[
    PortSyncFunction {
        rust_name: "rs_dns_server_new",
        c_name: "dns_server_new",
        purpose: "Documents the dns server new entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_server_unref",
        c_name: "dns_server_unref",
        purpose: "Documents the dns server unref entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_server_ref",
        c_name: "dns_server_ref",
        purpose: "Documents the dns server ref entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_server_unlink",
        c_name: "dns_server_unlink",
        purpose: "Documents the dns server unlink entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_server_move_back_and_unmark",
        c_name: "dns_server_move_back_and_unmark",
        purpose: "Documents the dns server move back and unmark entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_server_packet_received",
        c_name: "dns_server_packet_received",
        purpose: "Documents the dns server packet received entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_server_packet_lost",
        c_name: "dns_server_packet_lost",
        purpose: "Documents the dns server packet lost entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_server_packet_truncated",
        c_name: "dns_server_packet_truncated",
        purpose: "Documents the dns server packet truncated entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_server_packet_rrsig_missing",
        c_name: "dns_server_packet_rrsig_missing",
        purpose: "Documents the dns server packet rrsig missing entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_server_packet_bad_opt",
        c_name: "dns_server_packet_bad_opt",
        purpose: "Documents the dns server packet bad opt entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_server_packet_rcode_downgrade",
        c_name: "dns_server_packet_rcode_downgrade",
        purpose: "Documents the dns server packet rcode downgrade entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_server_packet_invalid",
        c_name: "dns_server_packet_invalid",
        purpose: "Documents the dns server packet invalid entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_server_packet_do_off",
        c_name: "dns_server_packet_do_off",
        purpose: "Documents the dns server packet do off entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_server_packet_udp_fragmented",
        c_name: "dns_server_packet_udp_fragmented",
        purpose: "Documents the dns server packet udp fragmented entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_server_possible_feature_level",
        c_name: "dns_server_possible_feature_level",
        purpose: "Documents the dns server possible feature level entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_server_adjust_opt",
        c_name: "dns_server_adjust_opt",
        purpose: "Documents the dns server adjust opt entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_server_string",
        c_name: "dns_server_string",
        purpose: "Documents the dns server string entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_server_string_full",
        c_name: "dns_server_string_full",
        purpose: "Documents the dns server string full entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_server_ifindex",
        c_name: "dns_server_ifindex",
        purpose: "Documents the dns server ifindex entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_server_port",
        c_name: "dns_server_port",
        purpose: "Documents the dns server port entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_server_dnssec_supported",
        c_name: "dns_server_dnssec_supported",
        purpose: "Documents the dns server dnssec supported entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_server_warn_downgrade",
        c_name: "dns_server_warn_downgrade",
        purpose: "Documents the dns server warn downgrade entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_server_find",
        c_name: "dns_server_find",
        purpose: "Documents the dns server find entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_server_unlink_all",
        c_name: "dns_server_unlink_all",
        purpose: "Documents the dns server unlink all entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_server_unlink_on_reload",
        c_name: "dns_server_unlink_on_reload",
        purpose: "Documents the dns server unlink on reload entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_server_unlink_marked",
        c_name: "dns_server_unlink_marked",
        purpose: "Documents the dns server unlink marked entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_server_mark_all",
        c_name: "dns_server_mark_all",
        purpose: "Documents the dns server mark all entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_manager_parse_search_domains_and_warn",
        c_name: "manager_parse_search_domains_and_warn",
        purpose: "Documents the manager parse search domains and warn entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_manager_parse_dns_server_string_and_warn",
        c_name: "manager_parse_dns_server_string_and_warn",
        purpose: "Documents the manager parse dns server string and warn entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_manager_get_first_dns_server",
        c_name: "manager_get_first_dns_server",
        purpose: "Documents the manager get first dns server entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_manager_set_dns_server",
        c_name: "manager_set_dns_server",
        purpose: "Documents the manager set dns server entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_manager_get_dns_server",
        c_name: "manager_get_dns_server",
        purpose: "Documents the manager get dns server entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_manager_next_dns_server",
        c_name: "manager_next_dns_server",
        purpose: "Documents the manager next dns server entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_server_get_dnssec_mode",
        c_name: "dns_server_get_dnssec_mode",
        purpose: "Documents the dns server get dnssec mode entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_server_get_dns_over_tls_mode",
        c_name: "dns_server_get_dns_over_tls_mode",
        purpose: "Documents the dns server get dns over tls mode entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_server_get_mtu",
        c_name: "dns_server_get_mtu",
        purpose: "Documents the dns server get mtu entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_server_flush_cache",
        c_name: "dns_server_flush_cache",
        purpose: "Documents the dns server flush cache entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_server_reset_features",
        c_name: "dns_server_reset_features",
        purpose: "Documents the dns server reset features entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_server_reset_features_all",
        c_name: "dns_server_reset_features_all",
        purpose: "Documents the dns server reset features all entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_server_dump",
        c_name: "dns_server_dump",
        purpose: "Documents the dns server dump entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_server_unref_stream",
        c_name: "dns_server_unref_stream",
        purpose: "Documents the dns server unref stream entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_server_scope",
        c_name: "dns_server_scope",
        purpose: "Documents the dns server scope entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_server_dump_state_to_json",
        c_name: "dns_server_dump_state_to_json",
        purpose: "Documents the dns server dump state to json entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_server_dump_configuration_to_json",
        c_name: "dns_server_dump_configuration_to_json",
        purpose: "Documents the dns server dump configuration to json entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_server_is_accessible",
        c_name: "dns_server_is_accessible",
        purpose: "Documents the dns server is accessible entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_server_reset_accessible",
        c_name: "dns_server_reset_accessible",
        purpose: "Documents the dns server reset accessible entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_server_reset_accessible_all",
        c_name: "dns_server_reset_accessible_all",
        purpose: "Documents the dns server reset accessible all entry point from the synced C module.",
    },
];
pub const CONSTANTS: &[PortSyncConstant] = &[PortSyncConstant {
    name: "SOURCE_LINE_COUNT",
    value: "1383",
    purpose: "Tracks the synced C source line count for quick drift checks.",
}];

pub fn module_spec() -> PortSyncModule<'static> {
    PortSyncModule {
        rust_module: "resolved_dns_server",
        source_path: SOURCE_PATH,
        summary: "DNS server lifecycle, selection, formatting, and configuration dump inventory.",
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
        let function = function("rs_dns_server_new").unwrap();
        assert_eq!(function.c_name, "dns_server_new");
    }
    #[test]
    fn function_lookup_finds_tail_symbol() {
        let function = function("rs_dns_server_reset_accessible_all").unwrap();
        assert_eq!(function.rust_name, "rs_dns_server_reset_accessible_all");
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
