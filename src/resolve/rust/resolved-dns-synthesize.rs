// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/resolve/resolved-dns-synthesize.c
//
// Synthetic DNS answer generation from local configuration.
//
// Determines address family and protocol from resolve flags, checks whether
// own-hostname synthesis is enabled, and builds synthesized DNS answers
// for localhost, the local hostname, and other well-known names.

use crate::port_sync::{PortSyncConstant, PortSyncError, PortSyncFunction, PortSyncModule};

pub const SOURCE_PATH: &str = "src/resolve/resolved-dns-synthesize.c";

pub const INCLUDED_HEADERS: &[&str] = &[
    "alloc-util.h",
    "dns-answer.h",
    "dns-domain.h",
    "dns-packet.h",
    "dns-question.h",
    "dns-rr.h",
    "dns-type.h",
    "env-util.h",
    "hostname-util.h",
    "local-addresses.h",
    "log.h",
    "missing-network.h",
    "resolved-def.h",
    "resolved-dns-synthesize.h",
    "resolved-manager.h",
    "socket-util.h",
];

pub const LOCAL_DEFINES: &[&str] = &[];

pub const FUNCTIONS: &[PortSyncFunction] = &[
    PortSyncFunction {
        rust_name: "rs_dns_synthesize_family",
        c_name: "dns_synthesize_family",
        purpose: "Determines address family from resolve protocol flags.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_synthesize_protocol",
        c_name: "dns_synthesize_protocol",
        purpose: "Determines DNS protocol from resolve flags.",
    },
    PortSyncFunction {
        rust_name: "rs_shall_synthesize_own_hostname_rrs",
        c_name: "shall_synthesize_own_hostname_rrs",
        purpose: "Checks whether own-hostname synthesis is enabled.",
    },
    PortSyncFunction {
        rust_name: "rs_dns_synthesize_answer",
        c_name: "dns_synthesize_answer",
        purpose: "Builds a synthesized DNS answer for the given question.",
    },
];

pub const CONSTANTS: &[PortSyncConstant] = &[];

pub fn module_spec() -> PortSyncModule<'static> {
    PortSyncModule {
        rust_module: "resolved_dns_synthesize",
        source_path: SOURCE_PATH,
        summary: "Synthetic DNS answer generation from local configuration.",
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
    fn function_lookup_finds_family() {
        let f = function("rs_dns_synthesize_family").unwrap();
        assert_eq!(f.c_name, "dns_synthesize_family");
    }

    #[test]
    fn function_lookup_finds_answer() {
        let f = function("rs_dns_synthesize_answer").unwrap();
        assert_eq!(f.c_name, "dns_synthesize_answer");
    }

    #[test]
    fn all_functions_have_nonempty_purpose() {
        for f in FUNCTIONS {
            assert!(!f.purpose.is_empty(), "purpose empty for {}", f.rust_name);
        }
    }

    #[test]
    fn constants_inventory_is_empty() {
        assert!(CONSTANTS.is_empty());
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
