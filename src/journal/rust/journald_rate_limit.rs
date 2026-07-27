// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/journal/journald-rate-limit.c
//
// Per-priority journal rate limiting with burst and interval.

crate::journal_port_module!(
    "Per-priority journal rate limiting with burst and interval.",
    "src/journal/journald-rate-limit.c",
    ["journal_ratelimit_test",]
);
