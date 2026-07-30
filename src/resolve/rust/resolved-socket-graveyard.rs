// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/resolve/resolved-socket-graveyard.c
//
// Deferred socket closure for DNS stub listeners.
//
// Provides a graveyard mechanism to delay closing file descriptors that
// the kernel might still be referencing, preventing spurious accept()
// failures on recycled sockets.

use crate::port_sync::{PortSyncConstant, PortSyncError, PortSyncFunction, PortSyncModule};

// ── Constants ─────────────────────────────────────────────────────────────

/// Maximum time a socket stays in the graveyard before closure (microseconds).
pub const SOCKET_GRAVEYARD_USEC: u64 = 2_000_000;

/// Maximum number of sockets allowed in the graveyard at once.
pub const SOCKET_GRAVEYARD_MAX: usize = 4096;

// ── Module inventory ──────────────────────────────────────────────────────

pub const SOURCE_PATH: &str = "src/resolve/resolved-socket-graveyard.c";

pub const INCLUDED_HEADERS: &[&str] = &[
    "sd-event.h",
    "alloc-util.h",
    "assert-util.h",
    "log.h",
    "resolved-manager.h",
    "resolved-socket-graveyard.h",
    "time-util.h",
];

pub const LOCAL_DEFINES: &[&str] = &["SOCKET_GRAVEYARD_USEC", "SOCKET_GRAVEYARD_MAX"];

pub const FUNCTIONS: &[PortSyncFunction] = &[
    PortSyncFunction {
        rust_name: "rs_manager_socket_graveyard_process",
        c_name: "manager_socket_graveyard_process",
        purpose: "Closes graveyard sockets whose timer has expired.",
    },
    PortSyncFunction {
        rust_name: "rs_manager_socket_graveyard_clear",
        c_name: "manager_socket_graveyard_clear",
        purpose: "Immediately closes all sockets in the graveyard.",
    },
    PortSyncFunction {
        rust_name: "rs_manager_add_socket_to_graveyard",
        c_name: "manager_add_socket_to_graveyard",
        purpose: "Enqueues a file descriptor for deferred closure.",
    },
];

pub const CONSTANTS: &[PortSyncConstant] = &[
    PortSyncConstant {
        name: "SOCKET_GRAVEYARD_USEC",
        value: "2000000",
        purpose: "Maximum microseconds a socket remains in the graveyard.",
    },
    PortSyncConstant {
        name: "SOCKET_GRAVEYARD_MAX",
        value: "4096",
        purpose: "Maximum number of sockets allowed in the graveyard simultaneously.",
    },
];

// ── Helpers ───────────────────────────────────────────────────────────────

/// Returns the module specification for this PORT-SYNC inventory.
pub fn module_spec() -> PortSyncModule<'static> {
    PortSyncModule {
        rust_module: "resolved_socket_graveyard",
        source_path: SOURCE_PATH,
        summary: "Deferred socket closure for DNS stub listeners.",
        included_headers: INCLUDED_HEADERS,
        local_defines: LOCAL_DEFINES,
        functions: FUNCTIONS,
        constants: CONSTANTS,
    }
}

/// Look up a function descriptor by its Rust symbol name.
pub fn function(rust_name: &str) -> Result<&'static PortSyncFunction, PortSyncError> {
    module_spec().function(rust_name)
}

/// Look up a constant descriptor by name.
pub fn constant(name: &str) -> Result<&'static PortSyncConstant, PortSyncError> {
    module_spec().constant(name)
}

/// Validate the module inventory for internal consistency.
pub fn validate() -> Result<(), PortSyncError> {
    module_spec().validate()
}

// ── Tests ─────────────────────────────────────────────────────────────────

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
    fn function_lookup_finds_process() {
        let f = function("rs_manager_socket_graveyard_process").unwrap();
        assert_eq!(f.c_name, "manager_socket_graveyard_process");
    }

    #[test]
    fn function_lookup_finds_add() {
        let f = function("rs_manager_add_socket_to_graveyard").unwrap();
        assert_eq!(f.c_name, "manager_add_socket_to_graveyard");
    }

    #[test]
    fn constant_lookup_finds_graveyard_usec() {
        let c = constant("SOCKET_GRAVEYARD_USEC").unwrap();
        assert_eq!(c.value, "2000000");
    }

    #[test]
    fn constant_lookup_finds_graveyard_max() {
        let c = constant("SOCKET_GRAVEYARD_MAX").unwrap();
        assert_eq!(c.value, "4096");
    }

    #[test]
    fn all_functions_have_nonempty_purpose() {
        for f in FUNCTIONS {
            assert!(!f.purpose.is_empty(), "purpose empty for {}", f.rust_name);
        }
    }

    #[test]
    fn unknown_function_reports_requested_name() {
        assert_eq!(
            function("does_not_exist"),
            Err(PortSyncError::UnknownFunction("does_not_exist".to_owned())),
        );
    }

    #[test]
    fn graveyard_max_is_positive() {
        const { assert!(SOCKET_GRAVEYARD_MAX > 0) };
    }
}
