// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/journal/journald-sync.c
//
// journald synchronization request tracking for Varlink Synchronize method.

crate::journal_port_module!(
    "journald synchronization request tracking for Varlink Synchronize method.",
    "src/journal/journald-sync.c",
    [
        "stream_sync_req_free",
        "stream_sync_req_advance_revalidate",
        "sync_req_free",
        "sync_req_new",
        "manager_notify_stream",
        "sync_req_revalidate",
        "sync_req_revalidate_by_timestamp",
        "sync_req_varlink_reply",
    ]
);
