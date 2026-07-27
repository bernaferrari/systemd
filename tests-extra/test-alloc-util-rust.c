/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Shadow test: C alloc-util vs Rust rs_alloc_util */

#include <string.h>

#include "alloc-util.h"
#include "rust/alloc_util.h"

/* ── memdup ───────────────────────────────────────────────────────────── */

static void test_memdup(void) {
        const char data[] = "hello world";

        /* Normal duplication */
        void *c = memdup(data, 12);
        void *r = rs_memdup(data, 12);
        assert_se(c != NULL);
        assert_se(r != NULL);
        assert_se(memcmp(c, data, 12) == 0);
        assert_se(memcmp(r, data, 12) == 0);
        assert_se(memcmp(c, r, 12) == 0);
        free(c);
        free(r);

        /* Zero-length: C allocates 1 byte */
        c = memdup(data, 0);
        r = rs_memdup(data, 0);
        assert_se(c != NULL);
        assert_se(r != NULL);
        free(c);
        free(r);
}

/* ── memdup_suffix0 ───────────────────────────────────────────────────── */

static void test_memdup_suffix0(void) {
        const char data[] = "hello";

        /* Normal: copy + NUL suffix */
        char *c = memdup_suffix0(data, 5);
        char *r = rs_memdup_suffix0(data, 5);
        assert_se(c != NULL);
        assert_se(r != NULL);
        assert_se(memcmp(c, data, 5) == 0);
        assert_se(memcmp(r, data, 5) == 0);
        assert_se(c[5] == '\0');
        assert_se(r[5] == '\0');
        free(c);
        free(r);

        /* Zero-length: copy 0 bytes + NUL suffix */
        c = memdup_suffix0(data, 0);
        r = rs_memdup_suffix0(data, 0);
        assert_se(c != NULL);
        assert_se(r != NULL);
        assert_se(c[0] == '\0');
        assert_se(r[0] == '\0');
        free(c);
        free(r);

        /* SIZE_MAX: overflow guard returns NULL */
        c = memdup_suffix0(data, SIZE_MAX);
        r = rs_memdup_suffix0(data, SIZE_MAX);
        assert_se(c == NULL);
        assert_se(r == NULL);
}

/* ── free_many ────────────────────────────────────────────────────────── */

static void test_free_many(void) {
        void *ptrs[3];

        ptrs[0] = strdup("hello");
        ptrs[1] = strdup("world");
        ptrs[2] = strdup("test");
        assert_se(ptrs[0] && ptrs[1] && ptrs[2]);

        /* C version */
        void *c_ptrs[3];
        c_ptrs[0] = strdup("hello");
        c_ptrs[1] = strdup("world");
        c_ptrs[2] = strdup("test");

        /* Rust version */
        void *r_ptrs[3];
        r_ptrs[0] = strdup("hello");
        r_ptrs[1] = strdup("world");
        r_ptrs[2] = strdup("test");

        free_many(c_ptrs, 3);
        rs_free_many(r_ptrs, 3);

        /* All should be NULL now */
        for (int i = 0; i < 3; i++) {
                assert_se(c_ptrs[i] == NULL);
                assert_se(r_ptrs[i] == NULL);
        }

        /* NULL array with n==0 is safe */
        free_many(NULL, 0);
        rs_free_many(NULL, 0);

        /* Cleanup the originals */
        free(ptrs[0]);
        free(ptrs[1]);
        free(ptrs[2]);
}

/* ── Main ─────────────────────────────────────────────────────────────── */

int main(int argc, char **argv) {
        test_memdup();
        test_memdup_suffix0();
        test_free_many();

        return 0;
}
