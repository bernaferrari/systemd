// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/resolve/resolved-dnssd.c
//
// DNS-SD service registration, TXT data, and conflict signalling inventory.

use crate::port_sync::{PortSyncConstant, PortSyncError, PortSyncFunction, PortSyncModule};

pub const SOURCE_PATH: &str = "src/resolve/resolved-dnssd.c";

pub const DNS_TXT_ITEM_TEXT: i32 = 0;
pub const DNS_TXT_ITEM_DATA: i32 = 1;

pub const INCLUDED_HEADERS: &[&str] = &[
    "sd-bus.h",
    "alloc-util.h",
    "conf-files.h",
    "conf-parser.h",
    "constants.h",
    "dns-domain.h",
    "dns-rr.h",
    "extract-word.h",
    "hashmap.h",
    "hexdecoct.h",
    "path-util.h",
    "resolved-conf.h",
    "resolved-dns-zone.h",
    "resolved-dnssd.h",
    "resolved-manager.h",
    "specifier.h",
    "string-util.h",
    "strv.h",
    "utf8.h",
];
pub const LOCAL_DEFINES: &[&str] = &["DNSSD_SERVICE_DIRS"];
pub const FUNCTIONS: &[PortSyncFunction] = &[
    PortSyncFunction {
        rust_name: "rs_dnssd_registered_service_free",
        c_name: "dnssd_registered_service_free",
        purpose: "Documents the dnssd registered service free entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dnssd_txtdata_free",
        c_name: "dnssd_txtdata_free",
        purpose: "Documents the dnssd txtdata free entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dnssd_txtdata_free_all",
        c_name: "dnssd_txtdata_free_all",
        purpose: "Documents the dnssd txtdata free all entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dnssd_registered_service_clear_on_reload",
        c_name: "dnssd_registered_service_clear_on_reload",
        purpose: "Documents the dnssd registered service clear on reload entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dnssd_render_instance_name",
        c_name: "dnssd_render_instance_name",
        purpose: "Documents the dnssd render instance name entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dnssd_load",
        c_name: "dnssd_load",
        purpose: "Documents the dnssd load entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dnssd_txt_item_new_from_string",
        c_name: "dnssd_txt_item_new_from_string",
        purpose: "Documents the dnssd txt item new from string entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dnssd_txt_item_new_from_data",
        c_name: "dnssd_txt_item_new_from_data",
        purpose: "Documents the dnssd txt item new from data entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dnssd_update_rrs",
        c_name: "dnssd_update_rrs",
        purpose: "Documents the dnssd update rrs entry point from the synced C module.",
    },
    PortSyncFunction {
        rust_name: "rs_dnssd_signal_conflict",
        c_name: "dnssd_signal_conflict",
        purpose: "Documents the dnssd signal conflict entry point from the synced C module.",
    },
];
pub const CONSTANTS: &[PortSyncConstant] = &[
    PortSyncConstant {
        name: "DNS_TXT_ITEM_TEXT",
        value: "0",
        purpose: "TXT item discriminator for string-backed values.",
    },
    PortSyncConstant {
        name: "DNS_TXT_ITEM_DATA",
        value: "1",
        purpose: "TXT item discriminator for binary-backed values.",
    },
];

pub fn module_spec() -> PortSyncModule<'static> {
    PortSyncModule {
        rust_module: "resolved_dnssd",
        source_path: SOURCE_PATH,
        summary: "DNS-SD service registration, TXT data, and conflict signalling inventory.",
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
        let function = function("rs_dnssd_registered_service_free").unwrap();
        assert_eq!(function.c_name, "dnssd_registered_service_free");
    }
    #[test]
    fn function_lookup_finds_tail_symbol() {
        let function = function("rs_dnssd_signal_conflict").unwrap();
        assert_eq!(function.rust_name, "rs_dnssd_signal_conflict");
    }
    #[test]
    fn constant_lookup_finds_documented_constant() {
        let constant = constant("DNS_TXT_ITEM_TEXT").unwrap();
        assert_eq!(constant.name, "DNS_TXT_ITEM_TEXT");
    }
    #[test]
    fn unknown_function_reports_requested_name() {
        assert_eq!(
            function("does_not_exist"),
            Err(PortSyncError::UnknownFunction("does_not_exist".to_owned())),
        );
    }
}
