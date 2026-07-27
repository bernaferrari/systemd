/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Shadow test: C udev-util string transforms vs Rust */

#include <assert.h>
#include <string.h>
#include "tests.h"
#include "string-util.h"
#include "rust/udev_util.h"

/* C headers */
#include "udev-util.h"

/* -- udev_replace_whitespace ----------------------------------------------- */

static void test_udev_replace_whitespace(void) {
        char buf[256];
        size_t r;

        /* Basic: trim leading/trailing, collapse internal */
        memset(buf, 0, sizeof(buf));
        r = udev_replace_whitespace("  hello  world  ", buf, sizeof(buf));
        assert_se(r == rs_udev_replace_whitespace("  hello  world  ", buf, sizeof(buf)));
        assert_se(r == 11);
        assert_se(streq(buf, "hello_world"));

        /* No whitespace */
        memset(buf, 0, sizeof(buf));
        r = udev_replace_whitespace("hello", buf, sizeof(buf));
        assert_se(r == rs_udev_replace_whitespace("hello", buf, sizeof(buf)));
        assert_se(r == 5);
        assert_se(streq(buf, "hello"));

        /* All whitespace → empty */
        memset(buf, 0, sizeof(buf));
        r = udev_replace_whitespace("   ", buf, sizeof(buf));
        assert_se(r == rs_udev_replace_whitespace("   ", buf, sizeof(buf)));
        assert_se(r == 0);
        assert_se(streq(buf, ""));

        /* Empty string */
        memset(buf, 0, sizeof(buf));
        r = udev_replace_whitespace("", buf, sizeof(buf));
        assert_se(r == rs_udev_replace_whitespace("", buf, sizeof(buf)));
        assert_se(r == 0);
        assert_se(streq(buf, ""));

        /* Tabs and newlines */
        memset(buf, 0, sizeof(buf));
        r = udev_replace_whitespace("\thello\nworld\r", buf, sizeof(buf));
        assert_se(r == rs_udev_replace_whitespace("\thello\nworld\r", buf, sizeof(buf)));
        assert_se(r == 11);
        assert_se(streq(buf, "hello_world"));

        /* In-place replacement */
        strcpy(buf, "  hello  world  ");
        r = udev_replace_whitespace(buf, buf, sizeof(buf));
        assert_se(r == 11);
        assert_se(streq(buf, "hello_world"));

        strcpy(buf, "  hello  world  ");
        assert_se(rs_udev_replace_whitespace(buf, buf, sizeof(buf)) == 11);
        assert_se(streq(buf, "hello_world"));

        /* Length limit: reads at most len chars from str */
        memset(buf, 0, sizeof(buf));
        r = udev_replace_whitespace("abcdef", buf, 4);
        assert_se(r == rs_udev_replace_whitespace("abcdef", buf, 4));
        assert_se(r == 4);
        assert_se(streq(buf, "abcd"));

        /* C uses WHITESPACE only for the initial scan, but isspace() while
         * collapsing later bytes: VT is normalized, not stripped. */
        memset(buf, 0, sizeof(buf));
        r = udev_replace_whitespace("\vhello", buf, 6);
        assert_se(r == rs_udev_replace_whitespace("\vhello", buf, 6));
        assert_se(r == 6);
        assert_se(streq(buf, "_hello"));
}

/* -- udev_replace_chars --------------------------------------------------- */

static void test_udev_replace_chars(void) {
        char buf[256];
        size_t r;

        /* Simple allowed chars */
        strcpy(buf, "sda1");
        r = udev_replace_chars(buf, NULL);
        assert_se(r == 0);
        strcpy(buf, "sda1");
        assert_se(rs_udev_replace_chars(buf, NULL) == 0);
        assert_se(streq(buf, "sda1"));

        /* Replace space */
        strcpy(buf, "my disk");
        r = udev_replace_chars(buf, NULL);
        assert_se(r == 1);
        strcpy(buf, "my disk");
        assert_se(rs_udev_replace_chars(buf, NULL) == 1);
        assert_se(streq(buf, "my_disk"));

        /* Replace multiple spaces */
        strcpy(buf, "a b c");
        r = udev_replace_chars(buf, NULL);
        assert_se(r == 2);
        strcpy(buf, "a b c");
        assert_se(rs_udev_replace_chars(buf, NULL) == 2);
        assert_se(streq(buf, "a_b_c"));

        /* Hex escape preserved */
        strcpy(buf, "test\\x20name");
        r = udev_replace_chars(buf, NULL);
        assert_se(r == rs_udev_replace_chars(buf, NULL));
        assert_se(r == 0);
        assert_se(streq(buf, "test\\x20name"));

        /* The current C contract preserves every \\x prefix, including a
         * malformed escape; it does not validate the following hex digits. */
        strcpy(buf, "test\\xGG");
        r = udev_replace_chars(buf, NULL);
        assert_se(r == rs_udev_replace_chars(buf, NULL));
        assert_se(r == 0);
        assert_se(streq(buf, "test\\xGG"));

        /* Space allowed: space is in allow list via allow_listed_char_for_devnode, so not replaced */
        strcpy(buf, "my disk");
        r = udev_replace_chars(buf, " ");
        assert_se(r == rs_udev_replace_chars(buf, " "));
        assert_se(r == 0);
        assert_se(streq(buf, "my disk"));

        /* Special chars replaced */
        strcpy(buf, "test!@#$");
        r = udev_replace_chars(buf, "#$@");
        {
                char buf2[256];
                strcpy(buf2, "test!@#$");
                assert_se(r == rs_udev_replace_chars(buf2, "#$@"));
                assert_se(streq(buf, buf2));
        }
        assert_se(r == 1); /* only '!' replaced */
        assert_se(streq(buf, "test_@#$"));

        /* A valid UTF-8 scalar is retained even when followed by an invalid
         * byte; C validates one scalar at a time. */
        {
                char c_buf[] = { 'a', (char) 0xc3, (char) 0xa9, (char) 0xff, 'b', 0 };
                char r_buf[] = { 'a', (char) 0xc3, (char) 0xa9, (char) 0xff, 'b', 0 };

                r = udev_replace_chars(c_buf, NULL);
                assert_se(r == rs_udev_replace_chars(r_buf, NULL));
                assert_se(r == 1);
                assert_se(memcmp(c_buf, r_buf, sizeof(c_buf)) == 0);
                assert_se(memcmp(c_buf, "a\xc3\xa9_b", sizeof(c_buf)) == 0);
        }

        /* When space is allowed, non-space C whitespace is normalized to a
         * literal space and still contributes to the replacement count. */
        strcpy(buf, "a\tb");
        r = udev_replace_chars(buf, " ");
        {
                char buf2[256];
                strcpy(buf2, "a\tb");
                assert_se(r == rs_udev_replace_chars(buf2, " "));
                assert_se(streq(buf, buf2));
        }
        assert_se(r == 1);
        assert_se(streq(buf, "a b"));

        /* Empty string */
        strcpy(buf, "");
        r = udev_replace_chars(buf, NULL);
        assert_se(r == rs_udev_replace_chars(buf, NULL));
        assert_se(r == 0);
}

int main(int argc, char **argv) {
        test_udev_replace_whitespace();
        test_udev_replace_chars();
        return 0;
}
