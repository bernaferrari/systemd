// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/resolve/resolved-dnstls.c
//
// DNS-over-TLS stream connection, I/O, and shutdown inventory.

use crate::port_sync::{PortSyncConstant, PortSyncError, PortSyncFunction, PortSyncModule};

pub const SOURCE_PATH: &str = "src/resolve/resolved-dnstls.c";

pub const DNSTLS_STREAM_CLOSED: i32 = 1;

pub const INCLUDED_HEADERS: &[&str] = &[
    "openssl/bio.h",
    "openssl/err.h",
    "openssl/x509v3.h",
    "alloc-util.h",
    "openssl-util.h",
    "log.h",
    "resolved-dns-server.h",
    "resolved-dns-stream.h",
    "resolved-dnstls.h",
    "resolved-manager.h",
];
pub const LOCAL_DEFINES: &[&str] = &["DNSTLS_ERROR_BUFSIZE", "DNSTLS_ERROR_STRING"];
pub const FUNCTIONS: &[PortSyncFunction] = &[
    PortSyncFunction {
        rust_name: "rs_dnstls_stream_connect_tls",
        c_name: "dnstls_stream_connect_tls",
        purpose: "Documents the dnstls stream connect tls entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dnstls_stream_free",
        c_name: "dnstls_stream_free",
        purpose: "Documents the dnstls stream free entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dnstls_stream_on_io",
        c_name: "dnstls_stream_on_io",
        purpose: "Documents the dnstls stream on io entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dnstls_stream_shutdown",
        c_name: "dnstls_stream_shutdown",
        purpose: "Documents the dnstls stream shutdown entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dnstls_stream_writev",
        c_name: "dnstls_stream_writev",
        purpose: "Documents the dnstls stream writev entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dnstls_stream_read",
        c_name: "dnstls_stream_read",
        purpose: "Documents the dnstls stream read entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dnstls_server_free",
        c_name: "dnstls_server_free",
        purpose: "Documents the dnstls server free entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dnstls_manager_init",
        c_name: "dnstls_manager_init",
        purpose: "Documents the dnstls manager init entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dnstls_manager_free",
        c_name: "dnstls_manager_free",
        purpose: "Documents the dnstls manager free entry point from the synced C module.",
    },
];
pub const CONSTANTS: &[PortSyncConstant] = &[PortSyncConstant {
    name: "DNSTLS_STREAM_CLOSED",
    value: "1",
    purpose: "Sentinel returned when a DNS-over-TLS stream is closed.",
}];

pub fn module_spec() -> PortSyncModule<'static> {
    PortSyncModule {
        rust_module: "resolved_dnstls",
        source_path: SOURCE_PATH,
        summary: "DNS-over-TLS stream connection, I/O, and shutdown inventory.",
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
        let function = function("rs_dnstls_stream_connect_tls").unwrap();
        assert_eq!(function.c_name, "dnstls_stream_connect_tls");
    }
    #[test]
    fn function_lookup_finds_tail_symbol() {
        let function = function("rs_dnstls_manager_free").unwrap();
        assert_eq!(function.rust_name, "rs_dnstls_manager_free");
    }
    #[test]
    fn constant_lookup_finds_documented_constant() {
        let constant = constant("DNSTLS_STREAM_CLOSED").unwrap();
        assert_eq!(constant.name, "DNSTLS_STREAM_CLOSED");
    }
    #[test]
    fn unknown_function_reports_requested_name() {
        assert_eq!(
            function("does_not_exist"),
            Err(PortSyncError::UnknownFunction("does_not_exist".to_owned())),
        );
    }
}
