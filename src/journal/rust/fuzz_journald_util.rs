// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/journal/fuzz-journald-util.c
//
// Fuzzer helper entry points for synthetic Manager setup.

crate::journal_port_module!(
    "Fuzzer helper entry points for synthetic Manager setup.",
    "src/journal/fuzz-journald-util.c",
    ["dummy_manager_new",]
);
