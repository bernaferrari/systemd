// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/journal/journalctl-varlink-server.c
//
// journalctl varlink server: GetEntries method.

crate::journal_port_module!(
    "journalctl varlink server: GetEntries method.",
    "src/journal/journalctl-varlink-server.c",
    ["vl_method_get_entries",]
);
