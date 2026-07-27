// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/journal/journald-client.c
//
// journald client context log filter pattern matching.

crate::journal_port_module!(
    "journald client context log filter pattern matching.",
    "src/journal/journald-client.c",
    [
        "client_context_read_log_filter_patterns",
        "client_context_check_keep_log",
    ]
);
