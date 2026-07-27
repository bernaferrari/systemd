/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

struct rs_Mempool {
        void *first_pool;
        void *freelist;
        size_t tile_size;
        size_t at_least;
};

void rs_mempool_init(struct rs_Mempool *mp, size_t tile_size, size_t at_least);
void *rs_mempool_alloc_tile(struct rs_Mempool *mp);
void *rs_mempool_alloc0_tile(struct rs_Mempool *mp);
void *rs_mempool_free_tile(struct rs_Mempool *mp, void *p);
