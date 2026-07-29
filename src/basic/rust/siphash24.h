/* SPDX-License-Identifier: CC0-1.0 */
#pragma once

#include <stdint.h>
#include <stddef.h>

/* PORT-SYNC: scope=basic.siphash24; authority=src/basic/siphash24.c,src/basic/siphash24.h */

/*
 * Rust FFI declarations for shadow testing.
 * These mirror the C functions in siphash24.h with rs_ prefix.
 * Only used by shadow tests — production code uses the C originals.
 */

struct rs_siphash {
        uint64_t v0;
        uint64_t v1;
        uint64_t v2;
        uint64_t v3;
        uint64_t padding;
        size_t inlen;
};

void rs_siphash24_init(struct rs_siphash *state, const uint8_t k[static 16]);
void rs_siphash24_compress(const void *in, size_t inlen, struct rs_siphash *state);
void rs_siphash24_compress_string(const char *in, struct rs_siphash *state);
uint64_t rs_siphash24_finalize(struct rs_siphash *state);
uint64_t rs_siphash24(const void *in, size_t inlen, const uint8_t k[static 16]);
uint64_t rs_siphash24_string(const char *s, const uint8_t k[static 16]);
