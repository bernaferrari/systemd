// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/journal/journald-config.c
//
// journald configuration loading, parsing, and merging.

crate::journal_port_module!(
    "journald configuration loading, parsing, and merging.",
    "src/journal/journald-config.c",
    [
        "journal_config_done",
        "journal_config_set_defaults",
        "manager_merge_configs",
        "manager_load_config",
        "manager_dispatch_reload_signal",
        "config_parse_line_max",
        "config_parse_compress",
        "config_parse_forward_to_socket",
    ]
);
