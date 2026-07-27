/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "udev-util.h"
#include "tests.h"

TEST(udev_replace_whitespace_basic) {
        char buf[64];

        /* No whitespace */
        assert_se(udev_replace_whitespace("hello", buf, sizeof(buf)) == 5);
        assert_se(streq(buf, "hello"));

        /* Single space in the middle */
        assert_se(udev_replace_whitespace("hello world", buf, sizeof(buf)) == 11);
        assert_se(streq(buf, "hello_world"));

        /* Leading and trailing whitespace */
        assert_se(udev_replace_whitespace("  hello  ", buf, sizeof(buf)) == 5);
        assert_se(streq(buf, "hello"));

        /* Multiple spaces */
        assert_se(udev_replace_whitespace("a   b", buf, sizeof(buf)) == 3);
        assert_se(streq(buf, "a_b"));

        /* Tab and newline treated as whitespace too */
        assert_se(udev_replace_whitespace("a\tb", buf, sizeof(buf)) == 3);
        assert_se(streq(buf, "a_b"));

        /* Empty string */
        assert_se(udev_replace_whitespace("", buf, sizeof(buf)) == 0);
        assert_se(streq(buf, ""));
}

TEST(udev_replace_chars_basic) {
        char buf[64];

        /* Plain ASCII is kept */
        strcpy(buf, "hello");
        udev_replace_chars(buf, NULL);
        assert_se(streq(buf, "hello"));

        /* Allowlist chars are kept */
        strcpy(buf, "hello");
        udev_replace_chars(buf, "helo");
        assert_se(streq(buf, "hello"));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
