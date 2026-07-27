// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/journal/journald-manager.c
//
// journald manager: core daemon state, journal file management, dispatch.

crate::journal_port_module!(
    "journald manager: core daemon state, journal file management, dispatch.",
    "src/journal/journald-manager.c",
    [
        "manager_new",
        "manager_set_namespace",
        "manager_init",
        "manager_vacuum",
        "manager_flush_to_var",
        "manager_full_sync",
        "manager_full_rotate",
        "manager_full_flush",
        "manager_relinquish_var",
        "manager_dispatch_message",
        "manager_process_datagram",
        "manager_start_or_stop_idle_timer",
        "manager_maybe_append_tags",
        "manager_reopen_journals",
        "manager_free",
    ]
);
