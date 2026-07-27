/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

/*
 * Rust FFI declarations for shadow testing.
 * These mirror the C functions in string-table.h with rs_ prefix.
 * Only used by shadow tests — production code uses the C originals.
 */

const char* rs_string_table_lookup_to_string(const char * const *table, size_t len, ssize_t i);
ssize_t rs_string_table_lookup_from_string(const char * const *table, size_t len, const char *key);
ssize_t rs_string_table_lookup_from_string_with_boolean(const char * const *table, size_t len, const char *key, ssize_t yes);
int rs_string_table_lookup_to_string_fallback(const char * const *table, size_t len, ssize_t i, size_t max, char **ret);
ssize_t rs_string_table_lookup_from_string_fallback(const char * const *table, size_t len, const char *s, size_t max);
