// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/journal/journalctl-util.c
//
// journalctl shared utilities (journal acquire, boot, invocation, etc.).

crate::journal_port_module!(
    "journalctl shared utilities (journal acquire, boot, invocation, etc.).",
    "src/journal/journalctl-util.c",
    [
        "format_timestamp_maybe_utc",
        "acquire_journal",
        "journal_boot_has_effect",
        "journal_acquire_boot",
        "get_possible_units",
        "acquire_unit",
        "journal_acquire_invocation",
    ]
);
