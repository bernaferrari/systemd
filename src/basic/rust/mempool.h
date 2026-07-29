/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

/* PORT-SYNC: scope=basic.mempool; authority=src/basic/mempool.c,src/basic/mempool.h,src/basic/memory-util.c,src/basic/memory-util.h,src/fundamental/memory-util.h */

struct rs_Mempool {
        void *first_pool;
        void *freelist;
        size_t tile_size;
        size_t at_least;
};

void *rs_mempool_alloc_tile(struct rs_Mempool *mp);
void *rs_mempool_alloc0_tile(struct rs_Mempool *mp);
void *rs_mempool_free_tile(struct rs_Mempool *mp, void *p);
