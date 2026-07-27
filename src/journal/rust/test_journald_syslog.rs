// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/journal/test-journald-syslog.c
//
// Tests for syslog identifier and priority parsing.

crate::journal_port_module!(
    "Tests for syslog identifier and priority parsing.",
    "src/journal/test-journald-syslog.c",
    ["syslog_parse_identifier", "syslog_parse_priority",]
);
