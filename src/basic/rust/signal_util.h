/* SPDX-License-Identifier: LGPL-2.1-or-later */
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

/* C helpers for runtime signal constants.
 * SIGRTMIN/SIGRTMAX are function calls on glibc (__libc_current_sigrtmin/max).
 * _NSIG may vary between kernel configurations.
 * Definitions provided by test files (not inline — must be visible to linker). */
int rs_get_sigrtmin(void);
int rs_get_sigrtmax(void);
int rs_get_nsig(void);
