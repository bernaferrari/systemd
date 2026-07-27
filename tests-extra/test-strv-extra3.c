/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "strv.h"
#include "tests.h"

TEST(strv_find_basic) {
        char *v[] = { (char*)"foo", (char*)"bar", (char*)"baz", NULL };

        assert_se(streq(strv_find(v, "foo"), "foo"));
        assert_se(streq(strv_find(v, "bar"), "bar"));
        assert_se(strv_find(v, "qux") == NULL);
        assert_se(strv_find(NULL, "foo") == NULL);
}

TEST(strv_find_case_basic) {
        char *v[] = { (char*)"Foo", (char*)"Bar", NULL };

        assert_se(streq(strv_find_case(v, "foo"), "Foo"));
        assert_se(streq(strv_find_case(v, "BAR"), "Bar"));
        assert_se(strv_find_case(v, "baz") == NULL);
}

TEST(strv_find_startswith_basic) {
        char *v[] = { (char*)"prefix:one", (char*)"prefix:two", (char*)"other", NULL };

        const char *r = strv_find_startswith(v, "prefix:");
        assert_se(r != NULL);
        assert_se(streq(r, "one"));

        assert_se(strv_find_startswith(v, "nonexistent:") == NULL);
}

TEST(strv_contains_basic) {
        char *v[] = { (char*)"foo", (char*)"bar", NULL };

        assert_se(strv_contains(v, "foo"));
        assert_se(strv_contains(v, "bar"));
        assert_se(!strv_contains(v, "baz"));
        assert_se(!strv_contains(NULL, "foo"));
}

TEST(strv_contains_case_basic) {
        char *v[] = { (char*)"Foo", (char*)"Bar", NULL };

        assert_se(strv_contains_case(v, "foo"));
        assert_se(strv_contains_case(v, "BAR"));
        assert_se(!strv_contains_case(v, "baz"));
}

TEST(strv_length_basic) {
        char *v[] = { (char*)"a", (char*)"b", (char*)"c", NULL };
        char *empty[] = { NULL };

        assert_se(strv_length(v) == 3);
        assert_se(strv_length(empty) == 0);
        assert_se(strv_length(NULL) == 0);
}

TEST(strv_is_uniq_basic) {
        char *uniq[] = { (char*)"a", (char*)"b", (char*)"c", NULL };
        char *dup[] = { (char*)"a", (char*)"b", (char*)"a", NULL };

        assert_se(strv_is_uniq(uniq));
        assert_se(!strv_is_uniq(dup));
        assert_se(strv_is_uniq(NULL));
}

TEST(strv_compare_basic) {
        char *a[] = { (char*)"a", (char*)"b", NULL };
        char *b[] = { (char*)"a", (char*)"c", NULL };
        char *c[] = { (char*)"a", NULL };

        assert_se(strv_compare(a, a) == 0);
        assert_se(strv_compare(a, b) < 0);
        assert_se(strv_compare(b, a) > 0);
        assert_se(strv_compare(c, a) < 0);
}

TEST(strv_equal_ignore_order_basic) {
        char *a[] = { (char*)"foo", (char*)"bar", NULL };
        char *b[] = { (char*)"bar", (char*)"foo", NULL };
        char *c[] = { (char*)"foo", (char*)"baz", NULL };

        assert_se(strv_equal_ignore_order(a, b));
        assert_se(!strv_equal_ignore_order(a, c));
        assert_se(strv_equal_ignore_order(NULL, NULL));
}

TEST(strv_join_basic) {
        char *v[] = { (char*)"foo", (char*)"bar", (char*)"baz", NULL };
        _cleanup_free_ char *s = NULL;

        s = strv_join(v, ", ");
        assert_se(s);
        assert_se(streq(s, "foo, bar, baz"));
}

TEST(strv_join_empty) {
        char *v[] = { NULL };
        _cleanup_free_ char *s = NULL;

        s = strv_join(v, ", ");
        assert_se(s);
        assert_se(streq(s, ""));

        s = strv_join(NULL, ", ");
        assert_se(s);
        assert_se(streq(s, ""));
}

TEST(strv_split_basic) {
        _cleanup_strv_free_ char **v = NULL;

        v = strv_split("foo bar baz", " ");
        assert_se(v);
        assert_se(strv_length(v) == 3);
        assert_se(streq(v[0], "foo"));
        assert_se(streq(v[1], "bar"));
        assert_se(streq(v[2], "baz"));
}

TEST(strv_copy_basic) {
        char *orig[] = { (char*)"foo", (char*)"bar", NULL };
        _cleanup_strv_free_ char **copy = NULL;

        copy = strv_copy(orig);
        assert_se(copy);
        assert_se(strv_length(copy) == 2);
        assert_se(streq(copy[0], "foo"));
        assert_se(streq(copy[1], "bar"));
}

TEST(strv_sort_basic) {
        _cleanup_strv_free_ char **v = NULL;

        v = strv_split("cherry apple banana", " ");
        assert_se(v);
        strv_sort(v);
        assert_se(streq(v[0], "apple"));
        assert_se(streq(v[1], "banana"));
        assert_se(streq(v[2], "cherry"));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
