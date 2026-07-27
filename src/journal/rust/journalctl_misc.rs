// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/journal/journalctl-misc.c
//
// journalctl miscellaneous actions (header, verify, disk-usage, list-boots, etc.).

crate::journal_port_module!(
    "journalctl miscellaneous actions (header, verify, disk-usage, list-boots, etc.).",
    "src/journal/journalctl-misc.c",
    [
        "action_print_header",
        "action_verify",
        "action_disk_usage",
        "action_list_boots",
        "action_list_fields",
        "action_list_field_names",
        "action_list_invocations",
        "action_list_namespaces",
    ]
);
