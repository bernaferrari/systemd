// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/journal/journald-native.c
//
// journald native protocol message and file processing.

crate::journal_port_module!(
    "journald native protocol message and file processing.",
    "src/journal/journald-native.c",
    [
        "manager_process_native_message",
        "manager_process_native_file",
        "manager_open_native_socket",
    ]
);
