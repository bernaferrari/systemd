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

/* PORT-SYNC: scope=basic.extract-word; authority=src/basic/extract-word.c,src/basic/extract-word.h */

int rs_extract_first_word(const char **p, char **ret, const char *separators, unsigned flags);
/* `extract_first_word_and_warn()` also owns systemd's syntax-logging contract
 * (severity, source location, and message formatting).  It intentionally has
 * no Rust ABI declaration until that externally observable contract can be
 * reproduced, rather than silently dropping diagnostics in a shadow facade. */
