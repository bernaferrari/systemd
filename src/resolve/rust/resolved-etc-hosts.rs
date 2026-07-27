// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/resolve/resolved-etc-hosts.c
//
// /etc/hosts parsing, lookup, and manager integration.
//
// Parses /etc/hosts into an EtcHosts structure, supports address-to-name
// and name-to-address lookups, and integrates with the manager for
// transparent synthesis of answers from local host entries.

use crate::port_sync::{PortSyncConstant, PortSyncError, PortSyncFunction, PortSyncModule};

pub const ETC_HOSTS_RECHECK_USEC: u64 = 2_000_000;

pub const SOURCE_PATH: &str = "src/resolve/resolved-etc-hosts.c";

pub const INCLUDED_HEADERS: &[&str] = &[
    "sys/stat.h",
    "sd-event.h",
    "alloc-util.h",
    "dns-answer.h",
    "dns-domain.h",
    "dns-question.h",
    "dns-rr.h",
    "extract-word.h",
    "fd-util.h",
    "fileio.h",
    "hostname-util.h",
    "log.h",
    "resolved-etc-hosts.h",
    "resolved-manager.h",
    "set.h",
    "socket-netlink.h",
    "stat-util.h",
    "string-util.h",
    "time-util.h",
];

pub const LOCAL_DEFINES: &[&str] = &["ETC_HOSTS_RECHECK_USEC"];

pub const FUNCTIONS: &[PortSyncFunction] = &[
    PortSyncFunction {
        rust_name: "rs_etc_hosts_parse",
        c_name: "etc_hosts_parse",
        purpose: "Parses /etc/hosts contents into the EtcHosts structure.",
    },
    PortSyncFunction {
        rust_name: "rs_etc_hosts_clear",
        c_name: "etc_hosts_clear",
        purpose: "Clears all parsed /etc/hosts entries.",
    },
    PortSyncFunction {
        rust_name: "rs_manager_etc_hosts_flush",
        c_name: "manager_etc_hosts_flush",
        purpose: "Reloads /etc/hosts from disk.",
    },
    PortSyncFunction {
        rust_name: "rs_manager_etc_hosts_lookup",
        c_name: "manager_etc_hosts_lookup",
        purpose: "Looks up /etc/hosts entries matching a DNS question.",
    },
];

pub const CONSTANTS: &[PortSyncConstant] = &[PortSyncConstant {
    name: "ETC_HOSTS_RECHECK_USEC",
    value: "2000000",
    purpose: "Minimum interval in microseconds between /etc/hosts rechecks.",
}];

pub fn module_spec() -> PortSyncModule<'static> {
    PortSyncModule {
        rust_module: "resolved_etc_hosts",
        source_path: SOURCE_PATH,
        summary: "/etc/hosts parsing, lookup, and manager integration.",
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
    fn function_lookup_finds_parse() {
        let f = function("rs_etc_hosts_parse").unwrap();
        assert_eq!(f.c_name, "etc_hosts_parse");
    }

    #[test]
    fn function_lookup_finds_lookup() {
        let f = function("rs_manager_etc_hosts_lookup").unwrap();
        assert_eq!(f.c_name, "manager_etc_hosts_lookup");
    }

    #[test]
    fn all_functions_have_nonempty_purpose() {
        for f in FUNCTIONS {
            assert!(!f.purpose.is_empty(), "purpose empty for {}", f.rust_name);
        }
    }

    #[test]
    fn constant_lookup_finds_recheck() {
        let c = constant("ETC_HOSTS_RECHECK_USEC").unwrap();
        assert_eq!(c.value, "2000000");
    }

    #[test]
    fn unknown_function_reports_requested_name() {
        assert_eq!(
            function("does_not_exist"),
            Err(PortSyncError::UnknownFunction("does_not_exist".to_owned())),
        );
    }

    #[test]
    fn recheck_interval_is_two_seconds() {
        assert_eq!(ETC_HOSTS_RECHECK_USEC, 2_000_000);
    }
}
