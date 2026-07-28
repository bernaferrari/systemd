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
        c = memdup(NULL, 0);
        r = rs_memdup(NULL, 0);
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
        c = memdup_suffix0(NULL, 0);
        r = rs_memdup_suffix0(NULL, 0);
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
        void *c_ptrs[] = { strdup("hello"), NULL, strdup("test") };
        void *r_ptrs[] = { strdup("hello"), NULL, strdup("test") };

        assert_se(c_ptrs[0] && c_ptrs[2]);
        assert_se(r_ptrs[0] && r_ptrs[2]);

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
}

/* ── Main ─────────────────────────────────────────────────────────────── */

int main(int argc, char **argv) {
        test_memdup();
        test_memdup_suffix0();
        test_free_many();

        return 0;
}
