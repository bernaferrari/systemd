/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

/*
 * Rust FFI declarations for shadow testing.
 * These mirror the C functions in escape.h with rs_ prefix.
 * Only used by shadow tests — production code uses the C originals.
 */

int rs_cescape_char(char c, char *buf);
char* rs_cescape(const char *s);
char* rs_cescape_length(const char *s, size_t n);
int rs_cunescape_one(const char *p, size_t length, char32_t *ret, bool *eight_bit, bool accept_nul);
ssize_t rs_cunescape(const char *s, unsigned flags, char **ret);

/*
 * Exact C ABI shadows for escape.h's inline/public allocation helpers.
 * Every non-NULL result is a fresh malloc(3) allocation owned by the caller
 * and released with free(3). Inputs are borrowed for the call only.
 *
 * rs_octescape accepts NULL only when len == 0; SIZE_MAX means strlen(s).
 * rs_decescape has the same s/len rule and requires a non-NULL C string bad.
 * rs_shell_escape requires non-NULL NUL-terminated s and bad strings.
 * rs_cunescape_length_with_prefix requires non-NULL s and ret; prefix may be
 * NULL. Its explicit length may contain NUL bytes and successful output is
 * published to ret only after all fallible work succeeds.
 * rs_xescape_full accepts NULL bad exactly like escape.h; the remaining
 * string inputs and rs_shell_maybe_quote input are non-NULL C strings.
 * rs_quote_command_line requires a non-NULL NULL-terminated argv vector.
 */
char* rs_octescape(const char *s, size_t len);
char* rs_decescape(const char *s, size_t len, const char *bad);
char* rs_shell_escape(const char *s, const char *bad);
ssize_t rs_cunescape_length_with_prefix(const char *s, size_t length, const char *prefix, unsigned flags, char **ret);
char* rs_xescape_full(const char *s, const char *bad, size_t console_width, unsigned flags);
char* rs_shell_maybe_quote(const char *s, unsigned flags);
char* rs_quote_command_line(char * const *argv, unsigned flags);
