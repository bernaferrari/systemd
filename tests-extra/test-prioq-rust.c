/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Shadow test: C prioq vs Rust rs_prioq */

#include <stdlib.h>
#include <string.h>

#include "prioq.h"
#include "rust/prioq.h"

/* Comparator: compare int values stored as void* */
static int int_compare(const void *a, const void *b) {
        return CMP(*(const int*) a, *(const int*) b);
}

static void test_prioq_new_free(void) {
        Prioq *c = prioq_new(int_compare);
        struct rs_Prioq *r = rs_prioq_new(int_compare);

        assert_se(c != NULL);
        assert_se(r != NULL);
        assert_se(prioq_isempty(c));
        assert_se(rs_prioq_isempty(r));
        assert_se(prioq_size(c) == 0);
        assert_se(rs_prioq_size(r) == 0);

        assert_se(prioq_free(c) == NULL);
        assert_se(rs_prioq_free(r) == NULL);

        /* NULL input */
        assert_se(prioq_free(NULL) == NULL);
        assert_se(rs_prioq_free(NULL) == NULL);
}

static void test_prioq_put_pop(void) {
        Prioq *c = prioq_new(int_compare);
        struct rs_Prioq *r = rs_prioq_new(int_compare);

        int vals[] = { 5, 3, 7, 1, 4 };
        for (int i = 0; i < 5; i++) {
                assert_se(prioq_put(c, &vals[i], NULL) == 0);
                assert_se(rs_prioq_put(r, &vals[i], NULL) == 0);
        }

        assert_se(prioq_size(c) == 5);
        assert_se(rs_prioq_size(r) == 5);

        /* Pop in sorted order (min-heap) */
        int expected[] = { 1, 3, 4, 5, 7 };
        for (int i = 0; i < 5; i++) {
                void *cv = prioq_pop(c);
                void *rv = rs_prioq_pop(r);
                assert_se(*(int*) cv == expected[i]);
                assert_se(*(int*) rv == expected[i]);
        }

        assert_se(prioq_isempty(c));
        assert_se(rs_prioq_isempty(r));
        assert_se(prioq_pop(c) == NULL);
        assert_se(rs_prioq_pop(r) == NULL);

        prioq_free(c);
        rs_prioq_free(r);
}

static void test_prioq_remove(void) {
        Prioq *c = prioq_new(int_compare);
        struct rs_Prioq *r = rs_prioq_new(int_compare);

        int vals[] = { 5, 3, 7, 1, 4 };
        for (int i = 0; i < 5; i++) {
                prioq_put(c, &vals[i], NULL);
                rs_prioq_put(r, &vals[i], NULL);
        }

        /* Remove middle element */
        assert_se(prioq_remove(c, &vals[2], NULL) == 1);  /* 7 */
        assert_se(rs_prioq_remove(r, &vals[2], NULL) == 1);

        assert_se(prioq_size(c) == 4);
        assert_se(rs_prioq_size(r) == 4);

        /* Remove again — should be no-op */
        assert_se(prioq_remove(c, &vals[2], NULL) == 0);
        assert_se(rs_prioq_remove(r, &vals[2], NULL) == 0);

        /* Pop remaining in order */
        int expected[] = { 1, 3, 4, 5 };
        for (int i = 0; i < 4; i++) {
                assert_se(*(int*) prioq_pop(c) == expected[i]);
                assert_se(*(int*) rs_prioq_pop(r) == expected[i]);
        }

        prioq_free(c);
        rs_prioq_free(r);
}

static void test_prioq_peek(void) {
        Prioq *c = prioq_new(int_compare);
        struct rs_Prioq *r = rs_prioq_new(int_compare);

        int v = 42;
        prioq_put(c, &v, NULL);
        rs_prioq_put(r, &v, NULL);

        assert_se(prioq_peek_by_index(c, 0) == &v);
        assert_se(rs_prioq_peek_by_index(r, 0) == &v);

        prioq_free(c);
        rs_prioq_free(r);
}

/* ── Main ─────────────────────────────────────────────────────────────── */

int main(int argc, char **argv) {
        test_prioq_new_free();
        test_prioq_put_pop();
        test_prioq_remove();
        test_prioq_peek();

        return 0;
}
