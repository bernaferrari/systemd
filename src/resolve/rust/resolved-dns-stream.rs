// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/resolve/resolved-dns-stream.c
//
// DNS TCP stream lifecycle, IO handling, and TLS integration.
//
// Manages DNS TCP stream ref-counting, read/write IO events, TLS
// handshakes via dnstls callbacks, TCP Fast Open support, and stream
// identification (local/peer address, interface index, TTL).

use crate::port_sync::{PortSyncConstant, PortSyncError, PortSyncFunction, PortSyncModule};

pub const DNS_STREAMS_MAX: usize = 128;
pub const DNS_QUERIES_PER_STREAM: usize = 32;

pub const SOURCE_PATH: &str = "src/resolve/resolved-dns-stream.c";

pub const INCLUDED_HEADERS: &[&str] = &[
    "unistd.h",
    "sd-event.h",
    "alloc-util.h",
    "dns-packet.h",
    "errno-util.h",
    "fd-util.h",
    "iovec-util.h",
    "log.h",
    "missing-network.h",
    "ordered-set.h",
    "resolved-dns-server.h",
    "resolved-dns-stream.h",
    "resolved-manager.h",
    "set.h",
    "time-util.h",
];

pub const LOCAL_DEFINES: &[&str] = &["DNS_STREAMS_MAX", "DNS_QUERIES_PER_STREAM"];

pub const FUNCTIONS: &[PortSyncFunction] = &[
    PortSyncFunction {
        rust_name: "rs_dns_stream_new",
        c_name: "dns_stream_new",
        purpose: "Creates a new DNS stream on the given fd.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_stream_unref",
        c_name: "dns_stream_unref",
        purpose: "Decrements the stream refcount and frees at zero.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_stream_ref",
        c_name: "dns_stream_ref",
        purpose: "Increments the stream refcount.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_stream_write_packet",
        c_name: "dns_stream_write_packet",
        purpose: "Queues a DNS packet for writing on the stream.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_stream_detach",
        c_name: "dns_stream_detach",
        purpose: "Detaches the stream from its manager.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_stream_disconnect_all",
        c_name: "dns_stream_disconnect_all",
        purpose: "Disconnects all streams associated with a manager.",
    },
];

pub const CONSTANTS: &[PortSyncConstant] = &[
    PortSyncConstant {
        name: "DNS_STREAMS_MAX",
        value: "128",
        purpose: "Maximum number of concurrent DNS streams.",
    },
    PortSyncConstant {
        name: "DNS_QUERIES_PER_STREAM",
        value: "32",
        purpose: "Maximum number of queries multiplexed per stream.",
    },
];

pub fn module_spec() -> PortSyncModule<'static> {
    PortSyncModule {
        rust_module: "resolved_dns_stream",
        source_path: SOURCE_PATH,
        summary: "DNS TCP stream lifecycle, IO handling, and TLS integration.",
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
        let f = function("rs_dns_stream_new").unwrap();
        assert_eq!(f.c_name, "dns_stream_new");
    }

    #[test]
    fn function_lookup_finds_disconnect_all() {
        let f = function("rs_dns_stream_disconnect_all").unwrap();
        assert_eq!(f.c_name, "dns_stream_disconnect_all");
    }

    #[test]
    fn all_functions_have_nonempty_purpose() {
        for f in FUNCTIONS {
            assert!(!f.purpose.is_empty(), "purpose empty for {}", f.rust_name);
        }
    }

    #[test]
    fn streams_max_is_positive() {
        const { assert!(DNS_STREAMS_MAX > 0) };
    }

    #[test]
    fn queries_per_stream_is_positive() {
        const { assert!(DNS_QUERIES_PER_STREAM > 0) };
    }

    #[test]
    fn unknown_function_reports_requested_name() {
        assert_eq!(
            function("does_not_exist"),
            Err(PortSyncError::UnknownFunction("does_not_exist".to_owned())),
        );
    }
}
