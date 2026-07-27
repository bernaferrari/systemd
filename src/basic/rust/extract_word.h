/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
 * Rust FFI declarations for shadow testing.
 * These mirror the C functions in extract-word.h with rs_ prefix.
 * Only used by shadow tests — production code uses the C originals.
 */

int rs_extract_first_word(const char **p, char **ret, const char *separators, unsigned flags);
int rs_extract_first_word_and_warn(const char **p, char **ret, const char *separators, unsigned flags,
                                   const char *unit, const char *filename, unsigned line, const char *rvalue);
