// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/journal/journald-varlink.c
//
// journald Varlink server: Synchronize, Rotate, FlushToVar, RelinquishVar.

crate::journal_port_module!(
    "journald Varlink server: Synchronize, Rotate, FlushToVar, RelinquishVar.",
    "src/journal/journald-varlink.c",
    ["sync_req_varlink_reply", "manager_open_varlink",]
);
