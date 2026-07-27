// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/journal/journald-audit.c
//
// journald audit socket processing and netlink message handling.

crate::journal_port_module!(
    "journald audit socket processing and netlink message handling.",
    "src/journal/journald-audit.c",
    [
        "process_audit_string",
        "manager_process_audit_message",
        "manager_open_audit",
        "manager_reset_kernel_audit",
    ]
);
