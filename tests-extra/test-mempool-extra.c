/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "mempool.h"
#include "tests.h"

static struct mempool test_pool = {
        .tile_size = sizeof(void*),
        .at_least = 4,
};

TEST(mempool_alloc_tile_basic) {
        void *t;

        t = mempool_alloc_tile(&test_pool);
        assert_se(t != NULL);

        /* Second allocation should also succeed */
        void *t2 = mempool_alloc_tile(&test_pool);
        assert_se(t2 != NULL);
        assert_se(t != t2);

        mempool_free_tile(&test_pool, t);
        mempool_free_tile(&test_pool, t2);
        mempool_trim(&test_pool);
}

TEST(mempool_alloc0_tile) {
        unsigned char *t;

        t = mempool_alloc0_tile(&test_pool);
        assert_se(t != NULL);

        /* alloc0 should zero the tile */
        for (size_t i = 0; i < test_pool.tile_size; i++)
                assert_se(t[i] == 0);

        mempool_free_tile(&test_pool, t);
        mempool_trim(&test_pool);
}

TEST(mempool_free_tile_null) {
        /* Freeing NULL should be safe and return NULL */
        assert_se(mempool_free_tile(&test_pool, NULL) == NULL);
}

TEST(mempool_alloc_free_cycle) {
        void *tiles[16];

        /* Allocate many tiles */
        for (size_t i = 0; i < 16; i++) {
                tiles[i] = mempool_alloc_tile(&test_pool);
                assert_se(tiles[i] != NULL);
        }

        /* Free them all */
        for (size_t i = 0; i < 16; i++)
                mempool_free_tile(&test_pool, tiles[i]);

        /* After trim, pool should be cleaned up */
        mempool_trim(&test_pool);
}

TEST(mempool_reuse_freed_tile) {
        void *t1, *t2;

        t1 = mempool_alloc_tile(&test_pool);
        assert_se(t1 != NULL);

        /* Free it */
        mempool_free_tile(&test_pool, t1);

        /* Next alloc should reuse the freed tile */
        t2 = mempool_alloc_tile(&test_pool);
        assert_se(t2 == t1);

        mempool_free_tile(&test_pool, t2);
        mempool_trim(&test_pool);
}

TEST(mempool_trim_empty) {
        /* Trimming a pool with no allocations should be safe */
        struct mempool empty_pool = {
                .tile_size = sizeof(void*),
                .at_least = 1,
        };
        mempool_trim(&empty_pool);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
