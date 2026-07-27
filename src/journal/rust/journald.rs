// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/journal/journald.c
//
// Main systemd-journald daemon entry point.

crate::journal_port_module!(
    "Main systemd-journald daemon entry point.",
    "src/journal/journald.c",
    ["run",]
);
