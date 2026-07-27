// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/journal/cat.c
//
// Journal cat: pipe stdout/stderr to the journal.

crate::journal_port_module!(
    "Journal cat: pipe stdout/stderr to the journal.",
    "src/journal/cat.c",
    ["help", "parse_argv", "run",]
);
