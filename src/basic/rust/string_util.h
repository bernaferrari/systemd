/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

/*
 * Rust FFI declarations for shadow testing.
 * Each declaration below is a real `extern "C"` export from the basic Rust
 * static library. They cover only C APIs with a reviewed, parity-preserving
 * Rust implementation; production code continues to use the C originals.
 */

char rs_ascii_tolower(char x);
char rs_ascii_toupper(char x);
bool rs_char_is_cc(char p);
int rs_ascii_strcasecmp_n(const char *a, const char *b, size_t n);
int rs_ascii_strcasecmp_nn(const char *a, size_t n, const char *b, size_t m);
bool rs_chars_intersect(const char *a, const char *b);
bool rs_string_has_cc(const char *p, const char *ok);
int rs_strdup_to_full(char **ret, const char *src);
int rs_free_and_strdup(char **p, const char *s);
int rs_free_and_strndup(char **p, const char *s, size_t l);
int rs_make_cstring(const void *s, size_t n, int mode, char **ret);
int rs_split_pair(const char *s, const char *sep, char **ret_first, char **ret_second);
size_t rs_str_common_prefix(const char *a, const char *b);
size_t rs_strspn_from_end(const char *str, const char *accept);
bool rs_streq_skip_trailing_chars(const char *s1, const char *s2, const char *ok);
char* rs_strdupspn(const char *a, const char *accept);
char* rs_strdupcspn(const char *a, const char *reject);
char* rs_string_replace_char(char *str, char old_char, char new_char);
char* rs_strrep(const char *s, size_t n);
char* rs_strreplace(const char *text, const char *old_string, const char *new_string);
char* rs_json_underscorify(char *p);
char* rs_json_dashify(char *p);
bool rs_in_charset(const char *s, const char *charset);
int rs_strgrowpad0(char **s, size_t l);
char* rs_strshorten(char *s, size_t l);
char* rs_strrstr_internal(const char *haystack, const char *needle);
ssize_t rs_strlevenshtein(const char *x, const char *y);
bool rs_version_is_valid(const char *s, int flags);
char* rs_cellescape(char *buf, size_t len, const char *s);
char* rs_string_erase(char *x);
char* rs_strextendn(char **x, const char *s, size_t l);
char* rs_escape_non_printable_full(const char *str, size_t console_width, int flags);
int rs_strcmp_ptr(const char *a, const char *b);
int rs_strncmp_ptr(const char *a, const char *b, size_t n);
int rs_strcasecmp_ptr(const char *a, const char *b);
bool rs_streq_ptr(const char *a, const char *b);
bool rs_strneq_ptr(const char *a, const char *b, size_t n);
bool rs_strcaseeq_ptr(const char *a, const char *b);
size_t rs_strlen_ptr(const char *s);
bool rs_isempty(const char *s);
const char* rs_strempty(const char *s);
const char* rs_yes_no(bool value);
const char* rs_on_off(bool value);
const char* rs_comparison_operator(int result);
void* rs_memory_startswith(const void *p, size_t sz, const char *token);
bool rs_ascii_isdigit(char value);
bool rs_ascii_ishex(char value);
bool rs_ascii_isalpha(char value);

/*
 * Registered byte-string mutation and inline surface. Returned interior
 * pointers borrow their input. string_truncate/extract and strdup_to return
 * C-allocator ownership through their output parameters. In-place operations
 * never read or write beyond the caller-provided string/range contract.
 */
char *rs_strstr_ptr_internal(const char *haystack, const char *needle);
char *rs_strstrafter_internal(const char *haystack, const char *needle);
void *rs_memory_startswith_no_case(const void *p, size_t size, const char *token);
char *rs_skip_leading_chars(const char *s, const char *bad);
void rs_strncpy_exact(char *buffer, const char *source, size_t buffer_length);
char *rs_truncate_nl(char *s);
int rs_strdup_to(char **ret, const char *source);
int rs_string_contains_word(const char *string, const char *separators, const char *word);
const char *rs_empty_or_dash_to_null(const char *p);
char *rs_strstrip(char *s);
char *rs_delete_chars(char *s, const char *bad);
char *rs_delete_trailing_chars(char *s, const char *bad);
char *rs_truncate_nl_full(char *s, size_t *ret_length);
char *rs_ascii_strlower(char *s);
char *rs_ascii_strupper(char *s);
char *rs_ascii_strlower_n(char *s, size_t n);
char *rs_first_word(const char *s, const char *word);
int rs_string_truncate_lines(const char *s, size_t line_count, char **ret);
int rs_string_extract_line(const char *s, size_t index, char **ret);
char *rs_find_line_startswith_internal(const char *haystack, const char *needle);
char *rs_find_line_internal(const char *haystack, const char *needle);
char *rs_find_line_after_internal(const char *haystack, const char *needle);
int rs_string_contains_word_strv(const char *string, const char *separators, char * const *words, const char **ret_word);
