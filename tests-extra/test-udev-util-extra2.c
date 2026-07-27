/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <string.h>

#include "string-util.h"
#include "tests.h"
#include "udev-util.h"

TEST(udev_replace_whitespace_in_place) {
        char buf[256];

        /* In-place replacement (str == to) */
        strcpy(buf, "hello   world");
        udev_replace_whitespace(buf, buf, sizeof(buf));
        assert_se(streq(buf, "hello_world"));

        /* In-place: leading and trailing */
        strcpy(buf, "  foo bar  ");
        udev_replace_whitespace(buf, buf, sizeof(buf));
        assert_se(streq(buf, "foo_bar"));
}

TEST(udev_replace_whitespace_truncated) {
        char buf[8];

        /* Truncation when buffer is smaller than input */
        udev_replace_whitespace("hello world", buf, sizeof(buf) - 1);
        /* Should be truncated */
        assert_se(strlen(buf) < 12);
}

TEST(udev_replace_chars_hex) {
        char buf[64];

        /* Hex-encoded chars are preserved */
        strcpy(buf, "hello\\x20world");
        udev_replace_chars(buf, NULL);
        assert_se(strstr(buf, "\\x") != NULL);
}

TEST(udev_replace_chars_utf8) {
        char buf[64];

        /* Valid UTF-8 is kept unchanged */
        strcpy(buf, "héllo");
        size_t r = udev_replace_chars(buf, NULL);
        assert_se(r == 0);
        assert_se(streq(buf, "héllo"));
}

TEST(udev_replace_chars_whitespace_with_allow) {
        char buf[64];

        /* Whitespace with space in allow list → space */
        strcpy(buf, "hello\tworld");
        size_t r = udev_replace_chars(buf, " ");
        assert_se(r >= 1);
        assert_se(buf[5] == ' ');

        /* Whitespace without space in allow list → underscore */
        strcpy(buf, "hello\tworld");
        r = udev_replace_chars(buf, NULL);
        assert_se(r >= 1);
        assert_se(buf[5] == '_');
}

TEST(udev_replace_chars_special) {
        char buf[64];

        /* Chars not in default allow list (#  +  -  .  :  =  @  _) → underscore */
        strcpy(buf, "a$b%c");
        size_t r = udev_replace_chars(buf, NULL);
        assert_se(r == 2);
        assert_se(buf[1] == '_');
        assert_se(buf[3] == '_');

        /* Chars in default allow list are kept */
        strcpy(buf, "a#b@c");
        r = udev_replace_chars(buf, NULL);
        assert_se(r == 0);
        assert_se(streq(buf, "a#b@c"));
}

TEST(udev_replace_chars_empty) {
        char buf[64];

        /* Empty string */
        strcpy(buf, "");
        size_t r = udev_replace_chars(buf, NULL);
        assert_se(r == 0);
        assert_se(streq(buf, ""));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
