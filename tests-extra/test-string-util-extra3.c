/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "string-util.h"
#include "tests.h"

TEST(ascii_strcasecmp_n) {
        ASSERT_EQ(ascii_strcasecmp_n("hello", "HELLO", 5), 0);
        ASSERT_LT(ascii_strcasecmp_n("hello", "WORLD", 5), 0); /* 'h' < 'w' */
        ASSERT_EQ(ascii_strcasecmp_n("Hello", "hello", 5), 0);
        ASSERT_EQ(ascii_strcasecmp_n("abc", "ab", 2), 0);
}

TEST(ascii_strcasecmp_nn) {
        ASSERT_EQ(ascii_strcasecmp_nn("hello", 5, "HELLO", 5), 0);
        ASSERT_EQ(ascii_strcasecmp_nn("abc", 3, "ABC", 3), 0);
        ASSERT_LT(ascii_strcasecmp_nn("abc", 2, "ABC", 3), 0); /* n < m */
        ASSERT_LT(ascii_strcasecmp_nn("abc", 3, "ABD", 3), 0); /* 'c' < 'd' */
}

TEST(chars_intersect) {
        ASSERT_TRUE(chars_intersect("abc", "cde"));
        ASSERT_TRUE(chars_intersect("hello", "world"));
        ASSERT_FALSE(chars_intersect("abc", "def"));
        ASSERT_FALSE(chars_intersect("", "abc"));
        ASSERT_FALSE(chars_intersect("abc", ""));
}

TEST(string_has_cc) {
        /* No allowed control chars */
        ASSERT_TRUE(string_has_cc("hello\x01world", NULL));
        ASSERT_TRUE(string_has_cc("hello\nworld", NULL));
        ASSERT_TRUE(string_has_cc("hello\tworld", NULL));
        ASSERT_FALSE(string_has_cc("hello world", NULL));
        ASSERT_FALSE(string_has_cc("", NULL));

        /* Allow newline and tab */
        ASSERT_FALSE(string_has_cc("hello\nworld", "\n"));
        ASSERT_FALSE(string_has_cc("hello\tworld", "\t"));
        ASSERT_TRUE(string_has_cc("hello\x01world", "\n\t")); /* \x01 not allowed */
}

TEST(split_pair) {
        _cleanup_free_ char *a = NULL;
        _cleanup_free_ char *b = NULL;

        ASSERT_OK(split_pair("key=value", "=", &a, &b));
        ASSERT_STREQ(a, "key");
        ASSERT_STREQ(b, "value");

        a = mfree(a);
        b = mfree(b);
        /* Separator at end — empty value */
        ASSERT_OK(split_pair("key=", "=", &a, &b));
        ASSERT_STREQ(a, "key");
        ASSERT_STREQ(b, "");

        a = mfree(a);
        b = mfree(b);
        /* No separator */
        ASSERT_LT(split_pair("noequal", "=", &a, &b), 0);

        /* Empty */
        ASSERT_LT(split_pair("", "=", &a, &b), 0);
}

TEST(streq_skip_trailing_chars) {
        /* Same strings */
        ASSERT_TRUE(streq_skip_trailing_chars("hello", "hello", ""));

        /* Skip trailing slashes */
        ASSERT_TRUE(streq_skip_trailing_chars("hello/", "hello", "/"));
        ASSERT_TRUE(streq_skip_trailing_chars("hello//", "hello", "/"));

        /* Different */
        ASSERT_FALSE(streq_skip_trailing_chars("hello/", "world", "/"));
}

TEST(make_cstring) {
        _cleanup_free_ char *s = NULL;

        ASSERT_OK(make_cstring("hello", 5, MAKE_CSTRING_ALLOW_TRAILING_NUL, &s));
        ASSERT_STREQ(s, "hello");

        s = mfree(s);
        ASSERT_OK(make_cstring("", 0, MAKE_CSTRING_ALLOW_TRAILING_NUL, &s));
        ASSERT_STREQ(s, "");
}

TEST(strlevenshtein) {
        /* Same strings */
        ASSERT_EQ(strlevenshtein("hello", "hello"), 0);

        /* One substitution */
        ASSERT_EQ(strlevenshtein("hello", "hallo"), 1);

        /* One insertion */
        ASSERT_EQ(strlevenshtein("hello", "hell"), 1);

        /* One deletion */
        ASSERT_EQ(strlevenshtein("hello", "helo"), 1);

        /* Completely different */
        ASSERT_EQ(strlevenshtein("abc", "xyz"), 3);

        /* Empty strings */
        ASSERT_EQ(strlevenshtein("", ""), 0);
        ASSERT_EQ(strlevenshtein("", "abc"), 3);
        ASSERT_EQ(strlevenshtein("abc", ""), 3);
}

TEST(str_common_prefix) {
        /* Returns SIZE_MAX when strings are fully identical */
        ASSERT_EQ(str_common_prefix("hello", "hello"), SIZE_MAX);
        ASSERT_EQ(str_common_prefix("hello", "help"), 3u);
        ASSERT_EQ(str_common_prefix("abc", "xyz"), 0u);
        ASSERT_EQ(str_common_prefix("", "abc"), 0u);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
