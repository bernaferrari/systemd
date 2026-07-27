/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "strv.h"
#include "tests.h"

/* strv_extend, strv_push, strv_new, strv_consume, strv_prepend */
TEST(strv_extend_basic) {
        _cleanup_strv_free_ char **v = NULL;

        assert_se(strv_extend(&v, "hello") >= 0);
        assert_se(strv_extend(&v, "world") >= 0);
        assert_se(strv_length(v) == 2);
        assert_se(streq(v[0], "hello"));
        assert_se(streq(v[1], "world"));
}

TEST(strv_prepend_basic) {
        _cleanup_strv_free_ char **v = NULL;

        assert_se(strv_extend(&v, "world") >= 0);
        assert_se(strv_prepend(&v, "hello") >= 0);
        assert_se(strv_length(v) == 2);
        assert_se(streq(v[0], "hello"));
        assert_se(streq(v[1], "world"));
}

TEST(strv_consume_basic) {
        _cleanup_strv_free_ char **v = NULL;
        char *s = strdup("consumed");
        assert_se(s);

        assert_se(strv_consume(&v, s) >= 0);
        assert_se(strv_length(v) == 1);
        assert_se(streq(v[0], "consumed"));
}

TEST(strv_push_basic) {
        _cleanup_strv_free_ char **v = NULL;
        char *s = strdup("dynamic");
        assert_se(s);

        assert_se(strv_push(&v, s) >= 0);
        assert_se(strv_length(v) == 1);
        assert_se(streq(v[0], "dynamic"));
}

TEST(strv_new_basic) {
        _cleanup_strv_free_ char **v = strv_new((char*)"a", (char*)"b", (char*)"c");
        assert_se(v);
        assert_se(strv_length(v) == 3);
        assert_se(streq(v[0], "a"));
        assert_se(streq(v[1], "b"));
        assert_se(streq(v[2], "c"));
}

TEST(strv_extend_strv_basic) {
        _cleanup_strv_free_ char **a = NULL;
        _cleanup_strv_free_ char **b = strv_new((char*)"x", (char*)"y");

        assert_se(strv_extend(&a, "a") >= 0);
        assert_se(strv_extend_strv(&a, b, false) >= 0);
        assert_se(strv_length(a) == 3);
        assert_se(streq(a[0], "a"));
        assert_se(streq(a[1], "x"));
        assert_se(streq(a[2], "y"));
}

TEST(strv_extend_strv_concat_basic) {
        _cleanup_strv_free_ char **a = NULL;

        assert_se(strv_extend(&a, "a") >= 0);
        assert_se(strv_extend(&a, "b") >= 0);
        assert_se(strv_length(a) == 2);
}

TEST(strv_remove_basic) {
        _cleanup_strv_free_ char **v = strv_new((char*)"a", (char*)"b", (char*)"c", (char*)"b");
        assert_se(v);

        strv_remove(v, "b");
        assert_se(strv_length(v) == 2);
        assert_se(streq(v[0], "a"));
        assert_se(streq(v[1], "c"));
}

TEST(strv_uniq_basic) {
        _cleanup_strv_free_ char **v = strv_new((char*)"a", (char*)"b", (char*)"a", (char*)"c", (char*)"b");
        assert_se(v);

        strv_uniq(v);
        assert_se(strv_length(v) == 3);
        assert_se(streq(v[0], "a"));
        assert_se(streq(v[1], "b"));
        assert_se(streq(v[2], "c"));
}

TEST(strv_reverse_basic) {
        _cleanup_strv_free_ char **v = strv_new((char*)"a", (char*)"b", (char*)"c");
        assert_se(v);

        strv_reverse(v);
        assert_se(strv_length(v) == 3);
        assert_se(streq(v[0], "c"));
        assert_se(streq(v[1], "b"));
        assert_se(streq(v[2], "a"));
}

TEST(strv_make_null_basic) {
        _cleanup_strv_free_ char **v = strv_new((char*)"a");
        assert_se(v);
        v = strv_free_erase(v);
        assert_se(v == NULL);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
