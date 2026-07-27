/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "strxcpyx.h"
#include "tests.h"

TEST(strscpy_basic) {
        char buf[32];
        size_t r;

        r = strscpy(buf, sizeof(buf), "hello");
        assert_se(r > 0); /* returns remaining size (including NUL space) */
        assert_se(streq(buf, "hello"));

        r = strscpy(buf, sizeof(buf), "");
        assert_se(r == sizeof(buf)); /* empty: remaining = full size, NUL written at pos 0 */
        assert_se(streq(buf, ""));

        /* Truncation: string longer than buffer */
        r = strscpy(buf, 5, "hello world!");
        assert_se(r == 0); /* truncated → returns 0 */
}

TEST(strpcpy_basic) {
        char buf[32];
        size_t size = sizeof(buf);
        char *p = buf;

        size = strpcpy(&p, size, "hello");
        assert_se(streq(buf, "hello"));
        assert_se(size < sizeof(buf));

        size = strpcpy(&p, size, " world");
        assert_se(streq(buf, "hello world"));
}

TEST(strscpyl_basic) {
        char buf[32];
        size_t r;

        r = strscpyl(buf, sizeof(buf), "hello", " ", "world", NULL);
        assert_se(r > 0);
        assert_se(streq(buf, "hello world"));

        /* Truncation */
        r = strscpyl(buf, 5, "hello", " ", "world", NULL);
        assert_se(r == 0);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
