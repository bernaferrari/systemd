/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "prioq.h"
#include "tests.h"

static int compare_int(const void *a, const void *b) {
        return CMP(*(const int*)a, *(const int*)b);
}

TEST(prioq_basic_ops) {
        _cleanup_(prioq_freep) Prioq *q = NULL;
        q = prioq_new(compare_int);
        assert_se(q);

        int v1 = 1, v2 = 2, v3 = 3;

        assert_se(prioq_put(q, &v1, NULL) >= 0);
        assert_se(prioq_put(q, &v3, NULL) >= 0);
        assert_se(prioq_put(q, &v2, NULL) >= 0);

        assert_se(prioq_size(q) == 3);

        /* Should pop in sorted order */
        int *top;
        assert_se(top = prioq_peek(q));
        assert_se(*top == 1);

        assert_se(top = prioq_pop(q));
        assert_se(*top == 1);

        assert_se(top = prioq_pop(q));
        assert_se(*top == 2);

        assert_se(top = prioq_pop(q));
        assert_se(*top == 3);

        assert_se(prioq_isempty(q));
        assert_se(prioq_peek(q) == NULL);
        assert_se(prioq_pop(q) == NULL);
}

TEST(prioq_remove) {
        _cleanup_(prioq_freep) Prioq *q = NULL;
        q = prioq_new(compare_int);
        assert_se(q);

        unsigned idx1 = 0, idx2 = 0;
        int v1 = 10, v2 = 20;
        assert_se(prioq_put(q, &v1, &idx1) >= 0);
        assert_se(prioq_put(q, &v2, &idx2) >= 0);

        assert_se(prioq_remove(q, &v1, &idx1));
        assert_se(prioq_size(q) == 1);

        int *top;
        assert_se(top = prioq_peek(q));
        assert_se(*top == 20);
}

TEST(prioq_reshuffle) {
        _cleanup_(prioq_freep) Prioq *q = NULL;
        q = prioq_new(compare_int);
        assert_se(q);

        unsigned idx1 = 0, idx2 = 0;
        int v1 = 5, v2 = 10;
        assert_se(prioq_put(q, &v1, &idx1) >= 0);
        assert_se(prioq_put(q, &v2, &idx2) >= 0);

        /* Change value and reshuffle */
        v1 = 15;
        prioq_reshuffle(q, &v1, &idx1);

        /* Now v2 (10) should be on top */
        int *top;
        assert_se(top = prioq_peek(q));
        assert_se(*top == 10);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
