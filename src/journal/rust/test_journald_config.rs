// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/journal/test-journald-config.c
//
// Tests for journald config parsing (compress, forward_to_socket).

crate::journal_port_module!(
    "Tests for journald config parsing (compress, forward_to_socket).",
    "src/journal/test-journald-config.c",
    ["config_compress", "config_forward_to_socket",]
);
