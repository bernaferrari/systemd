/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Shadow test: strv_extend_n, strv_extend_assignment, strv_consume_prepend, strv_prepend,
 *              strv_extend, strv_push_with_size, strv_consume, strv_consume_with_size */

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include "tests.h"
#include "strv.h"
#include "rust/strv.h"

static void test_strv_extend_n(void) {
        char **c_r = NULL, **rs_r = NULL;
        int c_ret, rs_ret;

        /* Add 3 copies */
        c_ret = strv_extend_n(&c_r, "x", 3);
        rs_ret = rs_strv_extend_n(&rs_r, "x", 3);
        assert_se(c_ret == rs_ret);
        assert_se(c_ret == 0);
        assert_se(c_r != NULL);
        assert_se(rs_r != NULL);
        assert_se(strv_length(c_r) == 3);
        assert_se(strv_length(rs_r) == 3);
        assert_se(streq(c_r[0], "x"));
        assert_se(streq(c_r[1], "x"));
        assert_se(streq(c_r[2], "x"));
        for (size_t i = 0; c_r[i] && rs_r[i]; i++)
                assert_se(streq(c_r[i], rs_r[i]));
        strv_free(c_r); c_r = NULL;
        strv_free(rs_r); rs_r = NULL;

        /* Add 0 copies — noop */
        c_ret = strv_extend_n(&c_r, "x", 0);
        rs_ret = rs_strv_extend_n(&rs_r, "x", 0);
        assert_se(c_ret == rs_ret);
        assert_se(c_ret == 0);
        assert_se(c_r == NULL);
        assert_se(rs_r == NULL);

        /* NULL value — noop */
        c_ret = strv_extend_n(&c_r, NULL, 5);
        rs_ret = rs_strv_extend_n(&rs_r, NULL, 5);
        assert_se(c_ret == rs_ret);
        assert_se(c_ret == 0);

        /* Extend existing */
        c_ret = strv_extend_n(&c_r, "a", 2);
        rs_ret = rs_strv_extend_n(&rs_r, "a", 2);
        assert_se(c_ret == rs_ret);
        assert_se(strv_length(c_r) == 2);
        assert_se(streq(c_r[0], "a"));
        strv_free(c_r); c_r = NULL;
        strv_free(rs_r); rs_r = NULL;
}

static void test_strv_extend_assignment(void) {
        char **c_r = NULL, **rs_r = NULL;
        int c_ret, rs_ret;

        /* Normal case */
        c_ret = strv_extend_assignment(&c_r, "KEY", "value");
        rs_ret = rs_strv_extend_assignment(&rs_r, "KEY", "value");
        assert_se(c_ret == rs_ret);
        assert_se(c_ret == 0);
        assert_se(c_r != NULL);
        assert_se(rs_r != NULL);
        assert_se(streq(c_r[0], rs_r[0]));
        assert_se(streq(c_r[0], "KEY=value"));
        strv_free(c_r); c_r = NULL;
        strv_free(rs_r); rs_r = NULL;

        /* NULL rhs — noop */
        c_ret = strv_extend_assignment(&c_r, "KEY", NULL);
        rs_ret = rs_strv_extend_assignment(&rs_r, "KEY", NULL);
        assert_se(c_ret == rs_ret);
        assert_se(c_ret == 0);
        assert_se(c_r == NULL);
        assert_se(rs_r == NULL);

        /* Empty rhs */
        c_ret = strv_extend_assignment(&c_r, "KEY", "");
        rs_ret = rs_strv_extend_assignment(&rs_r, "KEY", "");
        assert_se(c_ret == rs_ret);
        assert_se(streq(c_r[0], "KEY="));
        strv_free(c_r); c_r = NULL;
        strv_free(rs_r); rs_r = NULL;
}

static void test_strv_consume_prepend(void) {
        char **c_r = NULL, **rs_r = NULL;
        int c_ret, rs_ret;

        /* Prepend to empty */
        c_ret = strv_consume_prepend(&c_r, strdup("first"));
        rs_ret = rs_strv_consume_prepend(&rs_r, strdup("first"));
        assert_se(c_ret == rs_ret);
        assert_se(c_ret == 0);
        assert_se(streq(c_r[0], "first"));

        /* Prepend again */
        c_ret = strv_consume_prepend(&c_r, strdup("zero"));
        rs_ret = rs_strv_consume_prepend(&rs_r, strdup("zero"));
        assert_se(c_ret == rs_ret);
        assert_se(streq(c_r[0], "zero"));
        assert_se(streq(c_r[1], "first"));
        for (size_t i = 0; c_r[i] && rs_r[i]; i++)
                assert_se(streq(c_r[i], rs_r[i]));
        strv_free(c_r); c_r = NULL;
        strv_free(rs_r); rs_r = NULL;

        /* NULL value — noop */
        c_ret = strv_consume_prepend(&c_r, NULL);
        rs_ret = rs_strv_consume_prepend(&rs_r, NULL);
        assert_se(c_ret == rs_ret);
        assert_se(c_ret == 0);
}

static void test_strv_prepend(void) {
        char **c_r = NULL, **rs_r = NULL;
        int c_ret, rs_ret;

        /* Prepend to empty */
        c_ret = strv_prepend(&c_r, "first");
        rs_ret = rs_strv_prepend(&rs_r, "first");
        assert_se(c_ret == rs_ret);
        assert_se(c_ret == 0);
        assert_se(streq(c_r[0], "first"));

        /* Prepend again */
        c_ret = strv_prepend(&c_r, "zero");
        rs_ret = rs_strv_prepend(&rs_r, "zero");
        assert_se(c_ret == rs_ret);
        assert_se(streq(c_r[0], "zero"));
        assert_se(streq(c_r[1], "first"));
        for (size_t i = 0; c_r[i] && rs_r[i]; i++)
                assert_se(streq(c_r[i], rs_r[i]));
        strv_free(c_r); c_r = NULL;
        strv_free(rs_r); rs_r = NULL;

        /* NULL value — noop */
        c_ret = strv_prepend(&c_r, NULL);
        rs_ret = rs_strv_prepend(&rs_r, NULL);
        assert_se(c_ret == rs_ret);
        assert_se(c_ret == 0);
}

static void test_strv_extend_and_consume(void) {
        char **c_r = NULL, **rs_r = NULL;
        int c_ret, rs_ret;

        /* strv_extend: strdup + push */
        c_ret = strv_extend(&c_r, "hello");
        rs_ret = rs_strv_extend(&rs_r, "hello");
        assert_se(c_ret == rs_ret);
        assert_se(c_ret == 0);
        c_ret = strv_extend(&c_r, "world");
        rs_ret = rs_strv_extend(&rs_r, "world");
        assert_se(c_ret == rs_ret);
        assert_se(strv_length(c_r) == 2);
        assert_se(streq(c_r[0], "hello"));
        assert_se(streq(c_r[1], "world"));
        for (size_t i = 0; c_r[i] && rs_r[i]; i++)
                assert_se(streq(c_r[i], rs_r[i]));
        strv_free(c_r); c_r = NULL;
        strv_free(rs_r); rs_r = NULL;

        /* strv_consume: takes ownership */
        c_ret = strv_consume(&c_r, strdup("owned"));
        rs_ret = rs_strv_consume(&rs_r, strdup("owned"));
        assert_se(c_ret == rs_ret);
        assert_se(c_ret == 0);
        assert_se(streq(c_r[0], "owned"));
        strv_free(c_r); c_r = NULL;
        strv_free(rs_r); rs_r = NULL;

        /* strv_extend NULL — noop */
        c_ret = strv_extend(&c_r, NULL);
        rs_ret = rs_strv_extend(&rs_r, NULL);
        assert_se(c_ret == rs_ret);
        assert_se(c_ret == 0);
}

static void test_strv_push_with_size(void) {
        char **c_r = NULL, **rs_r = NULL;
        int c_ret, rs_ret;
        size_t cn = 0, rsn = 0;

        /* Push with size tracking */
        c_ret = strv_push_with_size(&c_r, &cn, strdup("a"));
        rs_ret = rs_strv_push_with_size(&rs_r, &rsn, strdup("a"));
        assert_se(c_ret == rs_ret);
        assert_se(c_ret == 0);
        assert_se(cn == rsn);
        assert_se(cn == 1);

        c_ret = strv_push_with_size(&c_r, &cn, strdup("b"));
        rs_ret = rs_strv_push_with_size(&rs_r, &rsn, strdup("b"));
        assert_se(c_ret == rs_ret);
        assert_se(cn == 2);
        for (size_t i = 0; c_r[i] && rs_r[i]; i++)
                assert_se(streq(c_r[i], rs_r[i]));
        strv_free(c_r); c_r = NULL;
        strv_free(rs_r); rs_r = NULL;

        /* NULL value — noop */
        cn = 0; rsn = 0;
        c_ret = strv_push_with_size(&c_r, &cn, NULL);
        rs_ret = rs_strv_push_with_size(&rs_r, &rsn, NULL);
        assert_se(c_ret == rs_ret);
        assert_se(c_ret == 0);

        /* Consume with size tracking: ownership transfers even on failure. */
        c_ret = strv_consume_with_size(&c_r, &cn, strdup("owned"));
        rs_ret = rs_strv_consume_with_size(&rs_r, &rsn, strdup("owned"));
        assert_se(c_ret == rs_ret);
        assert_se(c_ret == 0);
        assert_se(cn == rsn);
        assert_se(cn == 1);
        assert_se(streq(c_r[0], rs_r[0]));
        strv_free(c_r); c_r = NULL;
        strv_free(rs_r); rs_r = NULL;
}

int main(int argc, char **argv) {
        test_strv_extend_n();
        test_strv_extend_assignment();
        test_strv_consume_prepend();
        test_strv_prepend();
        test_strv_extend_and_consume();
        test_strv_push_with_size();
        return 0;
}
