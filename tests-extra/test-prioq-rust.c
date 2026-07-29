/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Shadow test: C prioq vs Rust rs_prioq */
/* RUST-CONTRACT: prioq-lifecycle */
/* RUST-CONTRACT: prioq-index-tracking */

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

static void test_prioq_indices(void) {
        Prioq *c = prioq_new(int_compare);
        struct rs_Prioq *r = rs_prioq_new(int_compare);
        int c_values[] = { 5, 1, 3 };
        int r_values[] = { 5, 1, 3 };
        unsigned c_indices[] = { PRIOQ_IDX_NULL, PRIOQ_IDX_NULL, PRIOQ_IDX_NULL };
        unsigned r_indices[] = { PRIOQ_IDX_NULL, PRIOQ_IDX_NULL, PRIOQ_IDX_NULL };

        for (size_t i = 0; i < 3; i++) {
                assert_se(prioq_put(c, &c_values[i], &c_indices[i]) == 0);
                assert_se(rs_prioq_put(r, &r_values[i], &r_indices[i]) == 0);
        }

        for (size_t i = 0; i < 3; i++) {
                assert_se(c_indices[i] == r_indices[i]);
                assert_se(prioq_peek_by_index(c, c_indices[i]) == &c_values[i]);
                assert_se(rs_prioq_peek_by_index(r, r_indices[i]) == &r_values[i]);
        }

        c_values[0] = 0;
        r_values[0] = 0;
        prioq_reshuffle(c, &c_values[0], &c_indices[0]);
        rs_prioq_reshuffle(r, &r_values[0], &r_indices[0]);
        assert_se(*(int*) prioq_peek_by_index(c, 0) == *(int*) rs_prioq_peek_by_index(r, 0));

        assert_se(*(int*) prioq_pop(c) == *(int*) rs_prioq_pop(r));
        /* The reshuffled value at slot 0 became the heap root, so pop()
         * invalidates its own caller-provided index—not whichever item happened
         * to have been inserted second. */
        assert_se(c_indices[0] == PRIOQ_IDX_NULL);
        assert_se(r_indices[0] == PRIOQ_IDX_NULL);

        prioq_free(c);
        rs_prioq_free(r);
        for (size_t i = 0; i < 3; i++)
                assert_se(c_indices[i] == r_indices[i]);
}

/* ── Main ─────────────────────────────────────────────────────────────── */

int main(int argc, char **argv) {
        test_prioq_new_free();
        test_prioq_put_pop();
        test_prioq_remove();
        test_prioq_peek();
        test_prioq_indices();

        return 0;
}
