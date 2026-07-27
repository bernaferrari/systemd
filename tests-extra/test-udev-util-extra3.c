/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "string-util.h"
#include "tests.h"
#include "udev-util.h"

TEST(udev_replace_whitespace_basic) {
        char buf[256];

        /* No whitespace → identity */
        assert_se(udev_replace_whitespace("hello", buf, sizeof(buf)) == 5);
        assert_se(streq(buf, "hello"));

        /* Leading/trailing whitespace stripped */
        assert_se(udev_replace_whitespace("  hello  ", buf, sizeof(buf)) == 5);
        assert_se(streq(buf, "hello"));

        /* Multiple internal spaces → single underscore */
        assert_se(udev_replace_whitespace("hello   world", buf, sizeof(buf)) == 11);
        assert_se(streq(buf, "hello_world"));

        /* Tab is also whitespace */
        assert_se(udev_replace_whitespace("hello\tworld", buf, sizeof(buf)) == 11);
        assert_se(streq(buf, "hello_world"));

        /* Mixed whitespace types */
        assert_se(udev_replace_whitespace("  hello  \t  world  ", buf, sizeof(buf)) == 11);
        assert_se(streq(buf, "hello_world"));

        /* Empty string */
        assert_se(udev_replace_whitespace("", buf, sizeof(buf)) == 0);
        assert_se(streq(buf, ""));

        /* Only whitespace */
        assert_se(udev_replace_whitespace("   ", buf, sizeof(buf)) == 0);
        assert_se(streq(buf, ""));
}

TEST(udev_replace_whitespace_truncation) {
        char buf[10];

        /* String too long for buffer */
        size_t n = udev_replace_whitespace("hello world", buf, 5);
        assert_se(n <= 5);
        assert_se(buf[n] == '\0');
}

TEST(udev_replace_whitespace_multiple_words) {
        char buf[256];

        /* Three words with varying spaces: "one  two   three" → "one_two_three" = 13 chars */
        assert_se(udev_replace_whitespace("one  two   three", buf, sizeof(buf)) == 13);
        assert_se(streq(buf, "one_two_three"));
}

TEST(udev_replace_chars_basic) {
        char buf[256];

        /* ASCII chars are left alone */
        strcpy(buf, "hello");
        assert_se(udev_replace_chars(buf, NULL) == 0);
        assert_se(streq(buf, "hello"));

        /* Special chars → underscore */
        strcpy(buf, "hello*world");
        size_t replaced = udev_replace_chars(buf, NULL);
        assert_se(replaced > 0);
        assert_se(streq(buf, "hello_world"));

        /* With allow list */
        strcpy(buf, "hello*world");
        replaced = udev_replace_chars(buf, "*");
        assert_se(replaced == 0);
        assert_se(streq(buf, "hello*world"));
}

TEST(udev_replace_chars_multiple_special) {
        char buf[256];

        /* Multiple special chars */
        strcpy(buf, "a*b?c|d");
        size_t replaced = udev_replace_chars(buf, NULL);
        assert_se(replaced == 3);
        assert_se(streq(buf, "a_b_c_d"));
}

TEST(reset_cached_udev_availability) {
        /* Should not crash */
        reset_cached_udev_availability();
        reset_cached_udev_availability();
}

DEFINE_TEST_MAIN(LOG_DEBUG);
