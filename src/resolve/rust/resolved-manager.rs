// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/resolve/resolved-manager.c
//
// Resolver manager lifecycle, packet routing, and configuration export inventory.

use crate::port_sync::{PortSyncConstant, PortSyncError, PortSyncFunction, PortSyncModule};

pub const SOURCE_PATH: &str = "src/resolve/resolved-manager.c";

pub const MANAGER_SEARCH_DOMAINS_MAX: u32 = 1024;
pub const MANAGER_DNS_SERVERS_MAX: u32 = 256;
pub const EXTRA_CMSG_SPACE: u32 = 1024;

pub const INCLUDED_HEADERS: &[&str] = &[
    "fcntl.h",
    "linux/ipv6.h",
    "netinet/in.h",
    "poll.h",
    "unistd.h",
    "sd-bus.h",
    "sd-netlink.h",
    "sd-network.h",
    "af-list.h",
    "alloc-util.h",
    "daemon-util.h",
    "dirent-util.h",
    "dns-answer.h",
    "dns-domain.h",
    "dns-packet.h",
    "dns-question.h",
    "dns-rr.h",
    "errno-util.h",
    "event-util.h",
    "fd-util.h",
    "hostname-setup.h",
    "hostname-util.h",
    "io-util.h",
    "iovec-util.h",
    "json-util.h",
    "memstream-util.h",
    "missing-network.h",
    "ordered-set.h",
    "parse-util.h",
    "random-util.h",
    "resolved-bus.h",
    "resolved-conf.h",
    "resolved-dns-delegate.h",
    "resolved-dns-query.h",
    "resolved-dns-scope.h",
    "resolved-dns-search-domain.h",
    "resolved-dns-server.h",
    "resolved-dns-stub.h",
    "resolved-dns-transaction.h",
    "resolved-dnssd.h",
    "resolved-etc-hosts.h",
    "resolved-link.h",
    "resolved-llmnr.h",
    "resolved-manager.h",
    "resolved-mdns.h",
    "resolved-resolv-conf.h",
    "resolved-socket-graveyard.h",
    "resolved-static-records.h",
    "resolved-util.h",
    "resolved-varlink.h",
    "set.h",
    "socket-util.h",
    "string-util.h",
    "time-util.h",
    "varlink-util.h",
];
pub const LOCAL_DEFINES: &[&str] = &["SEND_TIMEOUT_USEC"];
pub const FUNCTIONS: &[PortSyncFunction] = &[
    PortSyncFunction {
        rust_name: "rs_manager_new",
        c_name: "manager_new",
        purpose: "Documents the manager new entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_manager_free",
        c_name: "manager_free",
        purpose: "Documents the manager free entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_manager_start",
        c_name: "manager_start",
        purpose: "Documents the manager start entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_manager_find_mtu",
        c_name: "manager_find_mtu",
        purpose: "Documents the manager find mtu entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_manager_monitor_send",
        c_name: "manager_monitor_send",
        purpose: "Documents the manager monitor send entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_sendmsg_loop",
        c_name: "sendmsg_loop",
        purpose: "Documents the sendmsg loop entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_manager_write",
        c_name: "manager_write",
        purpose: "Documents the manager write entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_manager_send",
        c_name: "manager_send",
        purpose: "Documents the manager send entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_manager_recv",
        c_name: "manager_recv",
        purpose: "Documents the manager recv entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_manager_find_ifindex",
        c_name: "manager_find_ifindex",
        purpose: "Documents the manager find ifindex entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_manager_find_link_address",
        c_name: "manager_find_link_address",
        purpose: "Documents the manager find link address entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_manager_refresh_rrs",
        c_name: "manager_refresh_rrs",
        purpose: "Documents the manager refresh rrs entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_manager_next_hostname",
        c_name: "manager_next_hostname",
        purpose: "Documents the manager next hostname entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_manager_packet_from_local_address",
        c_name: "manager_packet_from_local_address",
        purpose: "Documents the manager packet from local address entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_manager_packet_from_our_transaction",
        c_name: "manager_packet_from_our_transaction",
        purpose: "Documents the manager packet from our transaction entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_manager_find_scope_from_protocol",
        c_name: "manager_find_scope_from_protocol",
        purpose: "Documents the manager find scope from protocol entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_manager_verify_all",
        c_name: "manager_verify_all",
        purpose: "Documents the manager verify all entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_manager_is_own_hostname",
        c_name: "manager_is_own_hostname",
        purpose: "Documents the manager is own hostname entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_manager_compile_dns_servers",
        c_name: "manager_compile_dns_servers",
        purpose: "Documents the manager compile dns servers entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_manager_compile_search_domains",
        c_name: "manager_compile_search_domains",
        purpose: "Documents the manager compile search domains entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_manager_get_dnssec_mode",
        c_name: "manager_get_dnssec_mode",
        purpose: "Documents the manager get dnssec mode entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_manager_dnssec_supported",
        c_name: "manager_dnssec_supported",
        purpose: "Documents the manager dnssec supported entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_manager_get_dns_over_tls_mode",
        c_name: "manager_get_dns_over_tls_mode",
        purpose: "Documents the manager get dns over tls mode entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_manager_dnssec_verdict",
        c_name: "manager_dnssec_verdict",
        purpose: "Documents the manager dnssec verdict entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_manager_routable",
        c_name: "manager_routable",
        purpose: "Documents the manager routable entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_manager_flush_caches",
        c_name: "manager_flush_caches",
        purpose: "Documents the manager flush caches entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_manager_reset_server_features",
        c_name: "manager_reset_server_features",
        purpose: "Documents the manager reset server features entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_manager_cleanup_saved_user",
        c_name: "manager_cleanup_saved_user",
        purpose: "Documents the manager cleanup saved user entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_manager_next_dnssd_names",
        c_name: "manager_next_dnssd_names",
        purpose: "Documents the manager next dnssd names entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_manager_server_is_stub",
        c_name: "manager_server_is_stub",
        purpose: "Documents the manager server is stub entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_socket_disable_pmtud",
        c_name: "socket_disable_pmtud",
        purpose: "Documents the socket disable pmtud entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_manager_dump_statistics_json",
        c_name: "dns_manager_dump_statistics_json",
        purpose: "Documents the dns manager dump statistics json entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_manager_reset_statistics",
        c_name: "dns_manager_reset_statistics",
        purpose: "Documents the dns manager reset statistics entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_manager_dump_dns_configuration_json",
        c_name: "manager_dump_dns_configuration_json",
        purpose: "Documents the manager dump dns configuration json entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_manager_send_dns_configuration_changed",
        c_name: "manager_send_dns_configuration_changed",
        purpose: "Documents the manager send dns configuration changed entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_manager_start_dns_configuration_monitor",
        c_name: "manager_start_dns_configuration_monitor",
        purpose: "Documents the manager start dns configuration monitor entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_manager_stop_dns_configuration_monitor",
        c_name: "manager_stop_dns_configuration_monitor",
        purpose: "Documents the manager stop dns configuration monitor entry point from the synced C module.",
    },
];
pub const CONSTANTS: &[PortSyncConstant] = &[
    PortSyncConstant {
        name: "MANAGER_SEARCH_DOMAINS_MAX",
        value: "1024",
        purpose: "Documents the manager_search_domains_max constant carried over from the existing Rust shadow module.",
    },
    PortSyncConstant {
        name: "MANAGER_DNS_SERVERS_MAX",
        value: "256",
        purpose: "Documents the manager_dns_servers_max constant carried over from the existing Rust shadow module.",
    },
    PortSyncConstant {
        name: "EXTRA_CMSG_SPACE",
        value: "1024",
        purpose: "Documents the extra_cmsg_space constant carried over from the existing Rust shadow module.",
    },
];

pub fn module_spec() -> PortSyncModule<'static> {
    PortSyncModule {
        rust_module: "resolved_manager",
        source_path: SOURCE_PATH,
        summary: "Resolver manager lifecycle, packet routing, and configuration export inventory.",
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
        let function = function("rs_manager_new").unwrap();
        assert_eq!(function.c_name, "manager_new");
    }
    #[test]
    fn function_lookup_finds_tail_symbol() {
        let function = function("rs_manager_stop_dns_configuration_monitor").unwrap();
        assert_eq!(
            function.rust_name,
            "rs_manager_stop_dns_configuration_monitor"
        );
    }
    #[test]
    fn constant_lookup_finds_documented_constant() {
        let constant = constant("MANAGER_SEARCH_DOMAINS_MAX").unwrap();
        assert_eq!(constant.name, "MANAGER_SEARCH_DOMAINS_MAX");
    }
    #[test]
    fn unknown_function_reports_requested_name() {
        assert_eq!(
            function("does_not_exist"),
            Err(PortSyncError::UnknownFunction("does_not_exist".to_owned())),
        );
    }
}
