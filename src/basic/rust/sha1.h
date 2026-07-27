/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stddef.h>
#include <stdint.h>

/* Shadow FFI for SHA-1 functions from src/fundamental/sha1.c */

#define RS_SHA1_DIGEST_SIZE 20

struct rs_sha1_ctx {
        uint32_t state[5];
        uint32_t count[2];
        uint8_t buffer[64];
};

void rs_sha1_init_ctx(struct rs_sha1_ctx *ctx);
void rs_sha1_process_bytes(const void *buffer, size_t size, struct rs_sha1_ctx *ctx);
void *rs_sha1_finish_ctx(struct rs_sha1_ctx *ctx, uint8_t result[RS_SHA1_DIGEST_SIZE]);
