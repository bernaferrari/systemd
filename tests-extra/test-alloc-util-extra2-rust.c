/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Shadow test: C alloc-util inline functions (malloc_multiply, memdup_multiply,
 * memdup_suffix0_multiply) vs Rust */

#include <assert.h>
#include <string.h>
#include <limits.h>
#include "tests.h"
#include "alloc-util.h"
#include "rust/alloc_util.h"

/* Keep overflow operands runtime-fed: GCC diagnoses alloc_size literals before
 * either C/Rust implementation can demonstrate its checked-overflow result. */

static void test_malloc_multiply(void) {
        void *c_r, *rs_r;
        volatile size_t size_max = SIZE_MAX;

        /* Normal multiplication */
        c_r = malloc_multiply(10, 4);
        rs_r = rs_malloc_multiply(10, 4);
        assert_se(c_r != NULL);
        assert_se(rs_r != NULL);
        free(c_r); free(rs_r);

        /* Zero need */
        c_r = malloc_multiply(0, 4);
        rs_r = rs_malloc_multiply(0, 4);
        assert_se(c_r != NULL);
        assert_se(rs_r != NULL);
        free(c_r); free(rs_r);

        /* Zero size */
        c_r = malloc_multiply(10, 0);
        rs_r = rs_malloc_multiply(10, 0);
        assert_se(c_r != NULL);
        assert_se(rs_r != NULL);
        free(c_r); free(rs_r);

        /* Overflow */
        c_r = malloc_multiply(size_max, 2);
        rs_r = rs_malloc_multiply(size_max, 2);
        assert_se(c_r == NULL);
        assert_se(rs_r == NULL);

        /* Large values causing overflow */
        c_r = malloc_multiply(size_max / 2 + 1, 2);
        rs_r = rs_malloc_multiply(size_max / 2 + 1, 2);
        assert_se(c_r == NULL);
        assert_se(rs_r == NULL);
}

static void test_memdup_multiply(void) {
        const char data[] = "hello world";
        volatile size_t size_max = SIZE_MAX;

        /* Normal duplication */
        void *c_r = memdup_multiply(data, 2, 6);
        void *rs_r = rs_memdup_multiply(data, 2, 6);
        assert_se(c_r != NULL);
        assert_se(rs_r != NULL);
        assert_se(memcmp(c_r, rs_r, 12) == 0);
        free(c_r); free(rs_r);

        /* Single copy */
        c_r = memdup_multiply(data, 1, 12);
        rs_r = rs_memdup_multiply(data, 1, 12);
        assert_se(c_r != NULL);
        assert_se(rs_r != NULL);
        assert_se(memcmp(c_r, rs_r, 12) == 0);
        assert_se(memcmp(c_r, data, 12) == 0);
        free(c_r); free(rs_r);

        /* Zero need */
        c_r = memdup_multiply(data, 0, 12);
        rs_r = rs_memdup_multiply(data, 0, 12);
        assert_se(c_r != NULL);
        assert_se(rs_r != NULL);
        free(c_r); free(rs_r);

        /* Overflow */
        c_r = memdup_multiply(data, size_max, 2);
        rs_r = rs_memdup_multiply(data, size_max, 2);
        assert_se(c_r == NULL);
        assert_se(rs_r == NULL);
}

static void test_memdup_suffix0_multiply(void) {
        const char data[] = "hello";
        volatile size_t size_max = SIZE_MAX;

        /* Normal duplication with NUL suffix */
        char *c_r = memdup_suffix0_multiply(data, 2, 3);
        char *rs_r = rs_memdup_suffix0_multiply(data, 2, 3);
        assert_se(c_r != NULL);
        assert_se(rs_r != NULL);
        assert_se(memcmp(c_r, rs_r, 6) == 0);
        assert_se(c_r[6] == '\0');
        assert_se(rs_r[6] == '\0');
        free(c_r); free(rs_r);

        /* Zero need */
        c_r = memdup_suffix0_multiply(data, 0, 5);
        rs_r = rs_memdup_suffix0_multiply(data, 0, 5);
        assert_se(c_r != NULL);
        assert_se(rs_r != NULL);
        assert_se(c_r[0] == '\0');
        assert_se(rs_r[0] == '\0');
        free(c_r); free(rs_r);

        /* Overflow */
        c_r = memdup_suffix0_multiply(data, size_max, 2);
        rs_r = rs_memdup_suffix0_multiply(data, size_max, 2);
        assert_se(c_r == NULL);
        assert_se(rs_r == NULL);
}

int main(int argc, char **argv) {
        test_malloc_multiply();
        test_memdup_multiply();
        test_memdup_suffix0_multiply();
        return 0;
}
