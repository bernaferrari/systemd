/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "prioq.h"
#include "tests.h"

static int compare_int(const void *a, const void *b) {
        return CMP(*(const int *)a, *(const int *)b);
}

TEST(prioq_basics) {
        _cleanup_(prioq_freep) Prioq *q = NULL;

        q = prioq_new(compare_int);
        ASSERT_NOT_NULL(q);
        ASSERT_TRUE(prioq_isempty(q));
        ASSERT_EQ(prioq_size(q), 0u);
        ASSERT_NULL(prioq_peek(q));

        /* Insert - pass NULL for index since we don't track positions */
        int v1 = 5, v2 = 3, v3 = 8;
        ASSERT_OK(prioq_put(q, &v1, NULL));
        ASSERT_OK(prioq_put(q, &v2, NULL));
        ASSERT_OK(prioq_put(q, &v3, NULL));
        ASSERT_EQ(prioq_size(q), 3u);
        ASSERT_FALSE(prioq_isempty(q));

        /* Peek should return smallest (3) */
        int *top = prioq_peek(q);
        ASSERT_NOT_NULL(top);
        ASSERT_EQ(*top, 3);

        /* Remove */
        ASSERT_OK(prioq_remove(q, &v2, NULL));
        ASSERT_EQ(prioq_size(q), 2u);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
