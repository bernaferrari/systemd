/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <uchar.h>

/*
 * Rust FFI declarations for shadow testing.
 * These mirror the C functions in utf8.h with rs_ prefix.
 * Only used by shadow tests — production code uses the C originals.
 */

bool rs_unichar_is_valid(char32_t c);
char* rs_utf8_is_valid_n(const char *str, size_t len_bytes);
char* rs_ascii_is_valid_n(const char *str, size_t len);
int rs_utf8_to_ascii(const char *str, char replacement_char, char **ret);
char* rs_utf8_escape_invalid(const char *s);
bool rs_utf8_is_printable_newline(const char* str, size_t length, bool allow_newline);
char* rs_utf8_escape_non_printable_full(const char *str, size_t console_width, bool force_ellipsis);
/* Mirrors the utf8.h inline helpers. Successful validation results borrow
 * their input; rs_utf8_escape_non_printable() returns malloc(3) storage. */
char* rs_utf8_is_valid(const char *str);
char* rs_ascii_is_valid(const char *str);
char* rs_utf8_escape_non_printable(const char *str);
bool rs_utf16_is_surrogate(char16_t c);
bool rs_utf16_is_trailing_surrogate(char16_t c);
char32_t rs_utf16_surrogate_pair_to_unichar(char16_t lead, char16_t trail);
size_t rs_utf8_encode_unichar(char *out_utf8, char32_t g);
size_t rs_utf16_encode_unichar(char16_t *out, char32_t c);
char* rs_utf16_to_utf8(const char16_t *s, size_t length);
char16_t *rs_utf8_to_utf16(const char *s, size_t length);
size_t rs_char16_strlen(const char16_t *s);
size_t rs_char16_strsize(const char16_t *s);
int rs_utf8_encoded_valid_unichar(const char *str, size_t length);
int rs_utf8_encoded_to_unichar(const char *str, char32_t *ret_unichar);
size_t rs_utf8_n_codepoints(const char *str);
int rs_utf8_char_console_width(const char *str);
size_t rs_utf8_console_width(const char *str);
size_t rs_utf8_last_length(const char *s, size_t n);
