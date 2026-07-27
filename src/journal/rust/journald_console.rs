// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/journal/journald-console.c
//
// journald console message forwarding.

crate::journal_port_module!(
    "journald console message forwarding.",
    "src/journal/journald-console.c",
    ["manager_forward_console",]
);
