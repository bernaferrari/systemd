// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/resolve/resolved-dns-stub.c
//
// DNS stub listener on 127.0.0.53/54 with UDP/TCP support.
//
// Handles DNS stub queries from local applications via the stub listener,
// supports extra listeners on configurable addresses, builds reply packets
// with EDNS0/DNSSEC extensions, and manages TCP stream processing.

use crate::port_sync::{PortSyncConstant, PortSyncError, PortSyncFunction, PortSyncModule};

pub const ADVERTISE_DATAGRAM_SIZE_MAX: u32 = 65536 - 14 - 20 - 8;

pub const SOURCE_PATH: &str = "src/resolve/resolved-dns-stub.c";
pub const SOURCE_LINE_COUNT: usize = 1464;

pub const INCLUDED_HEADERS: &[&str] = &[
    "netinet/tcp.h",
    "sd-event.h",
    "sd-id128.h",
    "alloc-util.h",
    "capability-util.h",
    "dns-answer.h",
    "dns-packet.h",
    "dns-question.h",
    "dns-rr.h",
    "dns-type.h",
    "errno-util.h",
    "fd-util.h",
    "log.h",
    "missing-network.h",
    "resolve-util.h",
    "resolved-dns-query.h",
    "resolved-dns-stream.h",
    "resolved-dns-stub.h",
    "resolved-dns-transaction.h",
    "resolved-manager.h",
    "set.h",
    "siphash24.h",
    "socket-util.h",
    "stdio-util.h",
    "string-table.h",
    "string-util.h",
    "time-util.h",
];

pub const LOCAL_DEFINES: &[&str] = &[
    "ADVERTISE_DATAGRAM_SIZE_MAX",
    "ADVERTISE_EXTRA_DATAGRAM_SIZE_MAX",
];

pub const FUNCTIONS: &[PortSyncFunction] = &[
    PortSyncFunction {
        rust_name: "rs_dns_stub_listener_extra_new",
        c_name: "dns_stub_listener_extra_new",
        purpose: "Allocates a new extra stub listener configuration.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_stub_listener_extra_free",
        c_name: "dns_stub_listener_extra_free",
        purpose: "Frees an extra stub listener and its socket.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_stub_listener_extra_port",
        c_name: "dns_stub_listener_extra_port",
        purpose: "Returns the port of an extra stub listener.",
    },
    PortSyncFunction {
        rust_name: "rs_manager_dns_stub_stop",
        c_name: "manager_dns_stub_stop",
        purpose: "Stops all stub listener sockets.",
    },
    PortSyncFunction {
        rust_name: "rs_manager_dns_stub_start",
        c_name: "manager_dns_stub_start",
        purpose: "Starts stub listener sockets based on configuration.",
    },
];

pub const CONSTANTS: &[PortSyncConstant] = &[
    PortSyncConstant {
        name: "SOURCE_LINE_COUNT",
        value: "1464",
        purpose: "Tracks the synced C source line count for drift detection.",
    },
    PortSyncConstant {
        name: "ADVERTISE_DATAGRAM_SIZE_MAX",
        value: "65494",
        purpose: "Maximum advertised UDP datagram size for stub replies.",
    },
];

pub fn module_spec() -> PortSyncModule<'static> {
    PortSyncModule {
        rust_module: "resolved_dns_stub",
        source_path: SOURCE_PATH,
        summary: "DNS stub listener on 127.0.0.53/54 with UDP/TCP support.",
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
    fn function_lookup_finds_listener_new() {
        let f = function("rs_dns_stub_listener_extra_new").unwrap();
        assert_eq!(f.c_name, "dns_stub_listener_extra_new");
    }

    #[test]
    fn function_lookup_finds_start() {
        let f = function("rs_manager_dns_stub_start").unwrap();
        assert_eq!(f.c_name, "manager_dns_stub_start");
    }

    #[test]
    fn all_functions_have_nonempty_purpose() {
        for f in FUNCTIONS {
            assert!(!f.purpose.is_empty(), "purpose empty for {}", f.rust_name);
        }
    }

    #[test]
    fn constant_lookup_finds_line_count() {
        let c = constant("SOURCE_LINE_COUNT").unwrap();
        assert_eq!(c.name, "SOURCE_LINE_COUNT");
    }

    #[test]
    fn unknown_function_reports_requested_name() {
        assert_eq!(
            function("does_not_exist"),
            Err(PortSyncError::UnknownFunction("does_not_exist".to_owned())),
        );
    }

    #[test]
    fn advertise_datagram_size_is_sane() {
        const {
            assert!(ADVERTISE_DATAGRAM_SIZE_MAX > 0);
            assert!(ADVERTISE_DATAGRAM_SIZE_MAX < 65536);
        }
    }
}
