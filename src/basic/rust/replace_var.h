/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

/* PORT-SYNC: scope=basic.replace-var; authority=src/basic/replace-var.c,src/basic/replace-var.h */

#include <stddef.h>

typedef char *(*rs_replace_var_lookup_t)(const char *variable, void *userdata);

/*
 * text and lookup must be non-NULL, as asserted by replace_var().
 *
 * The variable passed to lookup is borrowed for that call. A non-NULL lookup
 * result must be allocated with the process C allocator; ownership transfers
 * to rs_replace_var(), which frees every callback result after copying it.
 * NULL reports lookup/allocation failure. On success, the caller owns the
 * returned C-allocator string and must free() it.
 *
 * All strings are treated as raw non-NUL bytes; no UTF-8 contract is imposed.
 */
char *rs_replace_var(const char *text, rs_replace_var_lookup_t lookup, void *userdata);
