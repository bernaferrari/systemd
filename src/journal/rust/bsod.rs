// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/journal/bsod.c
//
// systemd-bsod: display emergency log message as QR code on a VT.

crate::journal_port_module!(
    "systemd-bsod: display emergency log message as QR code on a VT.",
    "src/journal/bsod.c",
    [
        "help",
        "acquire_first_emergency_log_message",
        "find_next_free_vt",
        "display_emergency_message_fullscreen",
        "parse_argv",
        "run",
    ]
);
