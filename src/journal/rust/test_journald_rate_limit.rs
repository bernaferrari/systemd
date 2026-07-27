// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/journal/test-journald-rate-limit.c
//
// Tests for journal rate limiting logic.

crate::journal_port_module!(
    "Tests for journal rate limiting logic.",
    "src/journal/test-journald-rate-limit.c",
    ["journal_ratelimit_test",]
);
