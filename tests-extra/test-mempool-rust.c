/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Shadow test: C mempool vs Rust rs_mempool */

#include <string.h>

#include "mempool.h"
#include "rust/mempool.h"

/* Use a simple tile size that fits a pointer */
#define TILE_SIZE 64

/* ── alloc/free basic ─────────────────────────────────────────────────── */

static void test_mempool_alloc_free(void) {
        struct mempool c = { .tile_size = TILE_SIZE, .at_least = 4 };
        struct rs_Mempool r;
        rs_mempool_init(&r, TILE_SIZE, 4);

        void *cp = mempool_alloc_tile(&c);
        void *rp = rs_mempool_alloc_tile(&r);
        assert_se(cp != NULL);
        assert_se(rp != NULL);

        assert_se(mempool_free_tile(&c, cp) == NULL);
        assert_se(rs_mempool_free_tile(&r, rp) == NULL);

        assert_se(mempool_free_tile(&c, NULL) == NULL);
        assert_se(rs_mempool_free_tile(&r, NULL) == NULL);
}

/* ── alloc0 zeroes memory ────────────────────────────────────────────── */

static void test_mempool_alloc0(void) {
        struct mempool c = { .tile_size = TILE_SIZE, .at_least = 4 };
        struct rs_Mempool r;
        rs_mempool_init(&r, TILE_SIZE, 4);

        void *cp = mempool_alloc0_tile(&c);
        void *rp = rs_mempool_alloc0_tile(&r);
        assert_se(cp != NULL);
        assert_se(rp != NULL);

        assert_se(memcmp(cp, rp, TILE_SIZE) == 0);
        unsigned char *bp = cp;
        for (int i = 0; i < TILE_SIZE; i++)
                assert_se(bp[i] == 0);

        mempool_free_tile(&c, cp);
        rs_mempool_free_tile(&r, rp);
}

/* ── freelist reuse ──────────────────────────────────────────────────── */

static void test_mempool_freelist(void) {
        struct mempool c = { .tile_size = TILE_SIZE, .at_least = 2 };
        struct rs_Mempool r;
        rs_mempool_init(&r, TILE_SIZE, 2);

        void *c1 = mempool_alloc_tile(&c);
        void *r1 = rs_mempool_alloc_tile(&r);
        assert_se(c1 && r1);

        memset(c1, 0xAA, TILE_SIZE);
        memset(r1, 0xAA, TILE_SIZE);

        mempool_free_tile(&c, c1);
        rs_mempool_free_tile(&r, r1);

        void *c2 = mempool_alloc_tile(&c);
        void *r2 = rs_mempool_alloc_tile(&r);
        assert_se(c2 == c1);  /* freelist reuse */
        assert_se(r2 == r1);

        mempool_free_tile(&c, c2);
        rs_mempool_free_tile(&r, r2);
}

/* ── multiple allocations (pool growth) ──────────────────────────────── */

static void test_mempool_growth(void) {
        struct mempool c = { .tile_size = TILE_SIZE, .at_least = 2 };
        struct rs_Mempool r;
        rs_mempool_init(&r, TILE_SIZE, 2);

        void *c_ptrs[10], *r_ptrs[10];
        for (int i = 0; i < 10; i++) {
                c_ptrs[i] = mempool_alloc_tile(&c);
                r_ptrs[i] = rs_mempool_alloc_tile(&r);
                assert_se(c_ptrs[i] != NULL);
                assert_se(r_ptrs[i] != NULL);
        }

        for (int i = 0; i < 10; i++) {
                mempool_free_tile(&c, c_ptrs[i]);
                rs_mempool_free_tile(&r, r_ptrs[i]);
        }
}

/* ── Main ─────────────────────────────────────────────────────────────── */

int main(int argc, char **argv) {
        test_mempool_alloc_free();
        test_mempool_alloc0();
        test_mempool_freelist();
        test_mempool_growth();

        return 0;
}
