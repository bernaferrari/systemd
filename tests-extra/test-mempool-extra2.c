/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "mempool.h"
#include "tests.h"

/* Use void* as tile type to guarantee tile_size >= sizeof(void*) */
DEFINE_MEMPOOL(test_pool, void*, 4);

TEST(mempool_alloc_free_tile) {
        void *t1, *t2, *t3;

        t1 = mempool_alloc_tile(&test_pool);
        assert_se(t1 != NULL);

        /* Write to verify tile is usable */
        memset(t1, 0xAB, sizeof(void*));

        t2 = mempool_alloc_tile(&test_pool);
        assert_se(t2 != NULL);
        assert_se(t2 != t1);

        /* Free t1 and reallocate — should reuse freelist */
        mempool_free_tile(&test_pool, t1);
        t3 = mempool_alloc_tile(&test_pool);
        assert_se(t3 == t1);

        /* Free both */
        mempool_free_tile(&test_pool, t2);
        mempool_free_tile(&test_pool, t3);

        /* Free NULL is safe */
        assert_se(mempool_free_tile(&test_pool, NULL) == NULL);
}

TEST(mempool_alloc0_tile) {
        DEFINE_MEMPOOL(zero_pool, void*, 2);

        void **t = mempool_alloc0_tile(&zero_pool);
        assert_se(t != NULL);
        assert_se(*t == NULL);

        /* Write and free */
        *t = (void*) 0x42;
        mempool_free_tile(&zero_pool, t);
}

TEST(mempool_trim) {
        DEFINE_MEMPOOL(trim_pool, void*, 2);
        void *t1, *t2;

        t1 = mempool_alloc_tile(&trim_pool);
        assert_se(t1);

        t2 = mempool_alloc_tile(&trim_pool);
        assert_se(t2);

        /* Free both and trim */
        mempool_free_tile(&trim_pool, t1);
        mempool_free_tile(&trim_pool, t2);
        mempool_trim(&trim_pool);

        /* Pool should still work after trim */
        t1 = mempool_alloc_tile(&trim_pool);
        assert_se(t1 != NULL);
        mempool_free_tile(&trim_pool, t1);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
