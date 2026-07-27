/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdint.h>
#include <stddef.h>

/* Rust FFI declarations for sha256/hmac module.
 * PORT-SYNC: src/basic/sha256.c, src/basic/hmac.c */

bool rs_sha256_is_valid(const char *s);
int rs_parse_sha256(const char *s, uint8_t ret[static 32]);
void rs_hmac_sha256(const void *key, size_t key_size, const void *input, size_t input_size, uint8_t res[static 32]);
