/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "strv.h"
#include "tests.h"

TEST(strv_find) {
        char *l[] = { (char*)"foo", (char*)"bar", (char*)"baz", NULL };
        ASSERT_NOT_NULL(strv_find(l, "foo"));
        ASSERT_NOT_NULL(strv_find(l, "bar"));
        ASSERT_NOT_NULL(strv_find(l, "baz"));
        ASSERT_NULL(strv_find(l, "qux"));
        ASSERT_NULL(strv_find(l, ""));
        ASSERT_NULL(strv_find((char* const*)NULL, "foo"));
}

TEST(strv_find_case) {
        char *l[] = { (char*)"Foo", (char*)"Bar", (char*)"baz", NULL };
        ASSERT_NOT_NULL(strv_find_case(l, "foo"));
        ASSERT_NOT_NULL(strv_find_case(l, "FOO"));
        ASSERT_NOT_NULL(strv_find_case(l, "Bar"));
        ASSERT_NOT_NULL(strv_find_case(l, "BAR"));
        ASSERT_NOT_NULL(strv_find_case(l, "baz"));
        ASSERT_NULL(strv_find_case(l, "qux"));
}

TEST(strv_find_prefix) {
        char *l[] = { (char*)"/usr/bin", (char*)"/usr/lib", (char*)"/var/log", NULL };
        ASSERT_NOT_NULL(strv_find_prefix(l, "/usr/"));
        ASSERT_NOT_NULL(strv_find_prefix(l, "/var/"));
        ASSERT_NOT_NULL(strv_find_prefix(l, "/usr")); /* matches /usr/bin */
        ASSERT_NULL(strv_find_prefix(l, "/tmp/"));
}

TEST(strv_find_startswith) {
        char *l[] = { (char*)"prefix_one", (char*)"prefix_two", (char*)"other", NULL };
        char *suffix;

        suffix = strv_find_startswith(l, "prefix_");
        ASSERT_NOT_NULL(suffix);
        ASSERT_STREQ(suffix, "one");

        ASSERT_NULL(strv_find_startswith(l, "xyz"));
        /* "prefix" itself matches "prefix_one" since it's a prefix */
        suffix = strv_find_startswith(l, "prefix");
        ASSERT_NOT_NULL(suffix);
        ASSERT_STREQ(suffix, "_one");
}

TEST(strv_contains) {
        char *l[] = { (char*)"foo", (char*)"bar", NULL };
        ASSERT_TRUE(strv_contains(l, "foo"));
        ASSERT_TRUE(strv_contains(l, "bar"));
        ASSERT_FALSE(strv_contains(l, "baz"));
        ASSERT_FALSE(strv_contains((char* const*)NULL, "foo"));
}

TEST(strv_join) {
        _cleanup_free_ char *s = NULL;
        char *l[] = { (char*)"one", (char*)"two", (char*)"three", NULL };

        s = strv_join(l, ",");
        ASSERT_STREQ(s, "one,two,three");

        s = mfree(s);
        s = strv_join(l, " ");
        ASSERT_STREQ(s, "one two three");

        /* Empty list returns empty string */
        s = mfree(s);
        char *empty[] = { NULL };
        s = strv_join(empty, ",");
        ASSERT_STREQ(s, "");

        /* NULL list also returns empty string */
        s = mfree(s);
        s = strv_join(NULL, ",");
        ASSERT_STREQ(s, "");
}

TEST(strv_join_full) {
        _cleanup_free_ char *s = NULL;
        char *l[] = { (char*)"one", (char*)"two", NULL };

        s = strv_join_full(l, ",", "P:", false);
        ASSERT_STREQ(s, "P:one,P:two");

        s = mfree(s);
        s = strv_join_full(l, ",", NULL, false);
        ASSERT_STREQ(s, "one,two");
}

DEFINE_TEST_MAIN(LOG_DEBUG);
