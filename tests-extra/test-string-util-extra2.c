/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "string-util.h"
#include "tests.h"

TEST(ascii_strlower) {
        char buf[64] = "Hello World 123";
        ascii_strlower(buf);
        ASSERT_STREQ(buf, "hello world 123");
        strncpy(buf, "", sizeof(buf));
        ascii_strlower(buf);
        ASSERT_STREQ(buf, "");
}

TEST(ascii_strupper) {
        char buf[64] = "Hello World 123";
        ascii_strupper(buf);
        ASSERT_STREQ(buf, "HELLO WORLD 123");
}

TEST(streq_ptr) {
        ASSERT_TRUE(streq_ptr("foo", "foo"));
        ASSERT_TRUE(streq_ptr(NULL, NULL));
        ASSERT_FALSE(streq_ptr("foo", "bar"));
        ASSERT_FALSE(streq_ptr(NULL, "bar"));
        ASSERT_FALSE(streq_ptr("foo", NULL));
}

TEST(string_has_cc) {
        ASSERT_TRUE(string_has_cc("hello\tworld", NULL));
        ASSERT_FALSE(string_has_cc("hello world", NULL));
        ASSERT_TRUE(string_has_cc("line1\nline2", NULL));
        ASSERT_FALSE(string_has_cc("hello\tworld", "\t"));
}

TEST(startswith) {
        ASSERT_TRUE(startswith("hello world", "hello"));
        ASSERT_FALSE(startswith("hello world", "world"));
        ASSERT_FALSE(startswith("hello", "hello world"));
}

TEST(endswith) {
        ASSERT_TRUE(endswith("hello world", "world"));
        ASSERT_FALSE(endswith("hello world", "hello"));
        ASSERT_FALSE(endswith("world", "hello world"));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
