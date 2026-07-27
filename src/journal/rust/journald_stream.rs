// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/journal/journald-stream.c
//
// journald stdout stream processing with protocol negotiation and persistence.

crate::journal_port_module!(
    "journald stdout stream processing with protocol negotiation and persistence.",
    "src/journal/journald-stream.c",
    [
        "stdout_stream_free",
        "stdout_stream_terminate",
        "stdout_stream_install",
        "manager_restore_streams",
        "manager_open_stdout_socket",
        "stdout_stream_send_notify",
    ]
);
