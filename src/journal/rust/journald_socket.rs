// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/journal/journald-socket.c
//
// journald forward-to-socket functionality.

crate::journal_port_module!(
    "journald forward-to-socket functionality.",
    "src/journal/journald-socket.c",
    ["manager_forward_socket", "manager_reload_forward_socket",]
);
