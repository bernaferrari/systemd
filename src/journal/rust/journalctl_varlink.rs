// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/journal/journalctl-varlink.c
//
// journalctl varlink client for flush, relinquish, rotate, sync, vacuum.

crate::journal_port_module!(
    "journalctl varlink client for flush, relinquish, rotate, sync, vacuum.",
    "src/journal/journalctl-varlink.c",
    [
        "varlink_connect_journal",
        "action_flush_to_var",
        "action_relinquish_var",
        "action_rotate",
        "action_vacuum",
        "action_rotate_and_vacuum",
        "action_sync",
    ]
);
