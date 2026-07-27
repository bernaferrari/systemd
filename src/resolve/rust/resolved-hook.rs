// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/resolve/resolved-hook.c
//
// Hook query lifecycle, filter acquisition, and connection reuse.
//
// Manages Hook objects that bind to UNIX sockets in /run/systemd/resolve.hook/,
// acquire filter parameters via Varlink, and dispatch DNS queries to matching
// hooks. Supports idle connection recycling, rate-limited reconnection, and
// garbage collection of stale hook entries.

use crate::port_sync::{PortSyncConstant, PortSyncError, PortSyncFunction, PortSyncModule};

// ── Constants ─────────────────────────────────────────────────────────────

/// Maximum number of idle Varlink connections kept per hook for reuse.
pub const HOOK_IDLE_CONNECTIONS_MAX: u32 = 4;

// ── Module inventory ──────────────────────────────────────────────────────

pub const SOURCE_PATH: &str = "src/resolve/resolved-hook.c";

pub const INCLUDED_HEADERS: &[&str] = &[
    "sd-event.h",
    "sd-varlink.h",
    "dirent-util.h",
    "dns-domain.h",
    "env-util.h",
    "errno-util.h",
    "fd-util.h",
    "hash-funcs.h",
    "iovec-util.h",
    "json-util.h",
    "ratelimit.h",
    "resolved-hook.h",
    "resolved-manager.h",
    "set.h",
    "stat-util.h",
    "varlink-util.h",
];

pub const LOCAL_DEFINES: &[&str] = &["HOOK_IDLE_CONNECTIONS_MAX"];

pub const FUNCTIONS: &[PortSyncFunction] = &[
    PortSyncFunction {
        rust_name: "rs_manager_hook_query",
        c_name: "manager_hook_query",
        purpose: "Dispatches a DNS question to all matching hooks.",
    },
    PortSyncFunction {
        rust_name: "rs_hook_query_free",
        c_name: "hook_query_free",
        purpose: "Frees a HookQuery and all associated candidates.",
    },
];

pub const CONSTANTS: &[PortSyncConstant] = &[PortSyncConstant {
    name: "HOOK_IDLE_CONNECTIONS_MAX",
    value: "4",
    purpose: "Maximum number of idle Varlink connections kept per hook.",
}];

// ── Helpers ───────────────────────────────────────────────────────────────

/// Returns the module specification for this PORT-SYNC inventory.
pub fn module_spec() -> PortSyncModule<'static> {
    PortSyncModule {
        rust_module: "resolved_hook",
        source_path: SOURCE_PATH,
        summary: "Hook query lifecycle, filter acquisition, and connection reuse.",
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
    fn function_lookup_finds_primary_symbol() {
        let f = function("rs_manager_hook_query").unwrap();
        assert_eq!(f.c_name, "manager_hook_query");
        assert!(!f.purpose.is_empty());
    }

    #[test]
    fn function_lookup_finds_secondary_symbol() {
        let f = function("rs_hook_query_free").unwrap();
        assert_eq!(f.c_name, "hook_query_free");
    }

    #[test]
    fn constant_lookup_finds_idle_max() {
        let c = constant("HOOK_IDLE_CONNECTIONS_MAX").unwrap();
        assert_eq!(c.value, "4");
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
    fn unknown_constant_reports_requested_name() {
        assert_eq!(
            constant("does_not_exist"),
            Err(PortSyncError::UnknownConstant("does_not_exist".to_owned())),
        );
    }

    #[test]
    fn hook_idle_connections_max_value() {
        assert_eq!(HOOK_IDLE_CONNECTIONS_MAX, 4);
    }
}
