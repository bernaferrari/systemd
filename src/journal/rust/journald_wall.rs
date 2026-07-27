// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/journal/journald-wall.c
//
// journald wall message forwarding via wall(1).

crate::journal_port_module!(
    "journald wall message forwarding via wall(1).",
    "src/journal/journald-wall.c",
    ["manager_forward_wall",]
);
