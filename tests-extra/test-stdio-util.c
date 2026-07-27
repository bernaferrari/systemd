/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdlib.h>

#include "stdio-util.h"
#include "string-util.h"
#include "tests.h"

TEST(asprintf_safe_basic) {
        _cleanup_free_ char *s = NULL;

        s = asprintf_safe("hello %s", "world");
        ASSERT_NOT_NULL(s);
        ASSERT_STREQ(s, "hello world");
}

TEST(asprintf_safe_numbers) {
        _cleanup_free_ char *s = NULL;

        s = asprintf_safe("%d %u %ld", -42, 42U, (long)123456789L);
        ASSERT_NOT_NULL(s);
        ASSERT_STREQ(s, "-42 42 123456789");
}

TEST(asprintf_safe_empty_string) {
        _cleanup_free_ char *s = NULL;

        s = asprintf_safe("%s", "");
        ASSERT_NOT_NULL(s);
        ASSERT_STREQ(s, "");
}

TEST(asprintf_safe_long_string) {
        _cleanup_free_ char *s = NULL;

        s = asprintf_safe("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                          "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                          "cccccccccccccccccccccccccccccccccccccccccccccccccc");
        ASSERT_NOT_NULL(s);
        ASSERT_EQ(strlen(s), 150u);
}

TEST(asprintf_safe_hex) {
        _cleanup_free_ char *s = NULL;

        s = asprintf_safe("%u %u %02u", 255u, 255u, 15u);
        ASSERT_NOT_NULL(s);
        ASSERT_STREQ(s, "255 255 15");
}

DEFINE_TEST_MAIN(LOG_DEBUG);
