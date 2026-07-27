// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/journal/journald-syslog.c
//
// journald syslog socket handling and message processing.

crate::journal_port_module!(
    "journald syslog socket handling and message processing.",
    "src/journal/journald-syslog.c",
    [
        "manager_forward_syslog",
        "syslog_fixup_facility",
        "syslog_parse_identifier",
        "manager_process_syslog_message",
        "manager_open_syslog_socket",
        "manager_maybe_warn_forward_syslog_missed",
    ]
);
