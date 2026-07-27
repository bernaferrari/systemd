/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "tests.h"

TEST(greedy_alloc_round_up) {
        assert_se(GREEDY_ALLOC_ROUND_UP(0) == 2);  /* minimum is 2 */
        assert_se(GREEDY_ALLOC_ROUND_UP(1) == 2);
        assert_se(GREEDY_ALLOC_ROUND_UP(2) == 2);
        assert_se(GREEDY_ALLOC_ROUND_UP(3) >= 3);
        assert_se(GREEDY_ALLOC_ROUND_UP(100) >= 100);
}

TEST(malloc_multiply_basic) {
        _cleanup_free_ void *p = malloc_multiply(10, 20);
        assert_se(p != NULL);

        /* Overflow → NULL */
        assert_se(malloc_multiply(2, (size_t) -1) == NULL);
}

TEST(memdup_multiply_basic) {
        const char data[] = "hello";
        _cleanup_free_ char *p = memdup_multiply(data, 5, sizeof(char));
        assert_se(p != NULL);
        assert_se(memcmp(p, data, 5) == 0);

        /* Overflow → NULL */
        assert_se(memdup_multiply(data, 2, (size_t) -1) == NULL);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
