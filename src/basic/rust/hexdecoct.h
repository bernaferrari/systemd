/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

/*
 * Rust FFI declarations for shadow testing.
 * These mirror the C functions in hexdecoct.h with rs_ prefix.
 * Only used by shadow tests — production code uses the C originals.
 */

char rs_octchar(int x);
int rs_unoctchar(char c);

char rs_decchar(int x);
int rs_undecchar(char c);

char rs_hexchar(int x);
int rs_unhexchar(char c);

char* rs_hexmem(const void *p, size_t l);
int rs_unhexmem_full(const char *p, size_t l, bool secure, void **ret_data, size_t *ret_size);

char rs_base32hexchar(int x);
int rs_unbase32hexchar(char c);

char rs_base64char(int x);
char rs_urlsafe_base64char(int x);
int rs_unbase64char(char c);

char* rs_base32hexmem(const void *p, size_t l, bool padding);
int rs_unbase32hexmem(const char *p, size_t l, bool padding, void **mem, size_t *len);

ssize_t rs_base64mem_full(const void *p, size_t l, size_t line_break, char **ret);
int rs_unbase64mem_full(const char *p, size_t l, bool secure, void **ret_data, size_t *ret_size);

ssize_t rs_base64_append(char **prefix, size_t plen, const void *p, size_t l, size_t indent, size_t width);
