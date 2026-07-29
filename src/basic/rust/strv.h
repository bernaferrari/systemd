/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* PORT-SYNC: scope=basic.strv; authority=src/basic/strv.c,src/basic/strv.h,src/fundamental/strv.h */
#pragma once

#include <stdbool.h>
#include <stddef.h>

/*
 * Rust FFI declarations for shadow testing.
 * These mirror the C functions in strv.h with rs_ prefix.
 * Only used by shadow tests — production code uses the C originals.
 */

size_t rs_strv_length(char * const *l);
char *rs_strv_find(char * const *l, const char *name);
char *rs_strv_find_case(char * const *l, const char *name);
char *rs_strv_find_prefix(char * const *l, const char *name);
char *rs_strv_find_startswith(char * const *l, const char *name);
bool rs_strv_is_uniq(char * const *l);
bool rs_strv_overlap(char * const *a, char * const *b);
int rs_strv_compare(char * const *a, char * const *b);
bool rs_strv_equal_ignore_order(char * const *a, char * const *b);
char **rs_strv_copy_n(char * const *l, size_t n);
char **rs_strv_remove(char **l, const char *s);
char **rs_strv_uniq(char **l);
char **rs_strv_sort(char **l);
char **rs_strv_reverse(char **l);
char **rs_strv_skip(char **l, size_t n);
char *rs_strv_find_closest_prefix(char * const *l, const char *name);
char *rs_strv_find_closest_by_levenshtein(char * const *l, const char *name);
/* Function-shaped equivalent of strv_free_and_replace(a, b): both arguments
 * name writable lvalues, and the function assigns NULL to *b after moving it. */
void rs_strv_free_and_replace(char ***a, char ***b);

/*
 * Registered strv ABI surface. Borrowed vectors and strings remain owned by
 * the caller. Functions named push/insert transfer their string only on
 * success; consume variants take ownership regardless of success. Newly
 * returned strings, entries, and pointer arrays use the C allocator and may be
 * released by free()/strv_free(). Every vector is NULL-terminated.
 */
char *rs_strv_find_closest(char * const *l, const char *name);
char *rs_startswith_strv_internal(const char *s, char * const *l);
char *rs_endswith_strv_internal(const char *s, char * const *l);
char *rs_strv_join_full(char * const *l, const char *separator, const char *prefix, bool escape_separator);
char **rs_strv_sort_uniq(char **l);
int rs_strv_push_pair(char ***l, char *a, char *b);
int rs_strv_insert(char ***l, size_t position, char *value);
int rs_strv_copy_unless_empty(char * const *l, char ***ret);
int rs_strv_extend_n(char ***l, const char *value, size_t n);
int rs_strv_extend_assignment(char ***l, const char *lhs, const char *rhs);
int rs_strv_consume_prepend(char ***l, char *value);
int rs_strv_prepend(char ***l, const char *value);
int rs_strv_extend(char ***l, const char *value);
int rs_strv_push_with_size(char ***l, size_t *n, char *value);
int rs_strv_consume_with_size(char ***l, size_t *n, char *value);
int rs_strv_consume(char ***l, char *value);
int rs_strv_split_full(char ***ret, const char *s, const char *separators, unsigned flags);
int rs_strv_split_newlines_full(char ***ret, const char *s, unsigned flags);
char **rs_strv_split_newlines(const char *s);
int rs_strv_rebreak_lines(char **l, size_t width, char ***ret);
char **rs_strv_split(const char *s, const char *separators);
int rs_strv_consume_pair(char ***l, char *a, char *b);
bool rs_strv_contains(char * const *l, const char *s);
int rs_strv_extend_strv_consume(char ***a, char **b, bool filter_duplicates);
int rs_strv_split_and_extend_full(char ***ret, const char *s, const char *separators, bool filter_duplicates, unsigned flags);
char **rs_strv_copy(char * const *l);
int rs_strv_push(char ***l, char *value);
int rs_strv_push_prepend(char ***l, char *value);
bool rs_strv_equal(char * const *a, char * const *b);
const char *rs_STRV_IFNOTNULL(const char *x);
bool rs_strv_isempty(char * const *l);
char *rs_strv_join(char * const *l, const char *separator);
bool rs_strv_fnmatch(char * const *patterns, const char *s);
bool rs_strv_fnmatch_or_empty(char * const *patterns, const char *s, int flags);

/* Exact Rust shadows for C-owned strv operations. Inputs are borrowed for the
 * call. rs_strv_shell_escape() replaces owned entries in-place and returns the
 * original array pointer on success; on allocation failure it retains any
 * changed prefix and returns NULL. */
char **rs_strv_shell_escape(char **l, const char *bad);
bool rs_strv_fnmatch_full(char * const *patterns, const char *s, int flags, size_t *ret_matched_pos);

/* Exact Rust shadows for allocating strv transforms. `rs_strv_filter_prefix()`
 * returns a fresh C-owned vector (or NULL). `rs_strv_extend_strv()` duplicates
 * source entries into `*a`; its source is borrowed and its destination remains
 * content-atomic if a later allocation fails. */
char **rs_strv_filter_prefix(char * const *l, const char *prefix);
int rs_strv_extend_strv(char ***a, char * const *b, bool filter_duplicates);
