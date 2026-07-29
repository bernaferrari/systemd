/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* PORT-SYNC: scope=basic.signal-util; authority=src/basic/signal-util.c,src/basic/signal-util.h */
#pragma once

#include <stdbool.h>
#include <signal.h>

/*
 * Rust FFI declarations for shadow testing.
 * These mirror the C functions in signal-util.h with rs_ prefix.
 * Only used by shadow tests — production code uses the C originals.
 */

const char *rs_signal_to_string(int signo);
int rs_signal_from_string(const char *s);
int rs_parse_signo(const char *s, int *ret);
bool rs_signal_is_valid(int signo);
const char *rs_signal_to_string_with_check(int signo);
bool rs_si_code_from_process(int si_code);

/* Runtime signal-bound shims are private Rust imports supplied only by the
 * C shadow fixtures. They are deliberately not part of this public Rust ABI:
 * current systemd exposes SIGRTMIN/SIGRTMAX/_NSIG as target-specific macros,
 * not callable C functions. */
