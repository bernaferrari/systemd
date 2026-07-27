// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/udev/net/link-config.c
//
// Conservative Rust shadow for link config.
// This module records source metadata and exposes an explicit rs_ FFI stub
// until the behavioral port is implemented.

use crate::ffi::Errno;

pub const SOURCE_PATH: &str = "src/udev/net/link-config.c";
pub const SOURCE_LINE_COUNT: usize = 1422;
pub const INCLUDED_HEADERS: &[&str] = &[
    "alloc-util.h",
    "arphrd-util.h",
    "condition.h",
    "conf-files.h",
    "conf-parser.h",
    "creds-util.h",
    "device-private.h",
    "device-util.h",
    "escape.h",
    "ether-addr-util.h",
    "ethtool-util.h",
    "extract-word.h",
    "fd-util.h",
    "fileio.h",
    "hashmap.h",
    "link-config.h",
    "linux/netdevice.h",
    "log-link.h",
    "memory-util.h",
    "net-condition.h",
    "net/if_arp.h",
    "netif-naming-scheme.h",
    "netif-sriov.h",
    "netif-util.h",
    "netlink-util.h",
    "network-util.h",
    "parse-util.h",
    "path-util.h",
    "proc-cmdline.h",
    "random-util.h",
    "sd-device.h",
    "sd-netlink.h",
    "socket-util.h",
    "specifier.h",
    "stat-util.h",
    "string-table.h",
    "string-util.h",
    "strv.h",
    "udev-builtin.h",
    "unistd.h",
    "utf8.h"
];
pub const EXPORTED_C_FUNCTIONS: &[&str] = &[
    "link_config_free",
    "link_configs_free",
    "link_config_ctx_new",
    "link_parse_wol_password",
    "link_read_wol_password_from_file",
    "link_read_wol_password_from_cred",
    "link_adjust_wol_options",
    "link_load_one",
    "link_config_load",
    "link_config_should_reload",
    "link_free",
    "link_new",
    "link_get_config",
    "LIST_FOREACH",
    "link_apply_ethtool_settings",
    "hw_addr_is_valid",
    "link_generate_new_hw_addr",
    "link_apply_rtnl_settings",
    "enable_name_policy",
    "link_generate_new_name",
    "link_generate_alternative_names",
    "sr_iov_configure",
    "link_apply_sr_iov_config",
    "ORDERED_HASHMAP_FOREACH",
    "link_apply_rps_cpu_mask",
    "FOREACH_DEVICE_SYSATTR",
    "link_apply_udev_properties",
    "STRV_FOREACH",
    "link_apply_config",
    "config_parse_udev_property",
    "config_parse_udev_property_name",
    "config_parse_ifalias",
    "config_parse_rx_tx_queues",
    "config_parse_txqueuelen",
    "config_parse_wol_password",
    "config_parse_rps_cpu_mask"
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortSummary {
    pub source_path: &'static str,
    pub line_count: usize,
    pub include_count: usize,
    pub function_count: usize,
}

pub fn port_summary() -> PortSummary {
    PortSummary {
        source_path: SOURCE_PATH,
        line_count: SOURCE_LINE_COUNT,
        include_count: INCLUDED_HEADERS.len(),
        function_count: EXPORTED_C_FUNCTIONS.len(),
    }
}

pub fn port_status() -> Result<(), Errno> {
    Err(Errno::ENOSYS)
}

#[no_mangle]
pub extern "C" fn rs_net_link_config_port_stub() -> i32 {
    port_status().err().unwrap_or(Errno::EINVAL).to_neg_errno()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summary_references_expected_source() {
        let summary = port_summary();
        assert_eq!(summary.source_path, SOURCE_PATH);
        assert_eq!(summary.line_count, SOURCE_LINE_COUNT);
    }

    #[test]
    fn ffi_stub_reports_enosys() {
        assert_eq!(rs_net_link_config_port_stub(), Errno::ENOSYS.to_neg_errno());
    }

    #[test]
    fn extracted_metadata_is_stable() {
        assert!(SOURCE_LINE_COUNT > 0);
        assert!(SOURCE_PATH.ends_with(".c"));
    }
}
