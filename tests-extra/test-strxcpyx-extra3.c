/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "string-util.h"
#include "strxcpyx.h"
#include "tests.h"

TEST(strscpy_basic) {
        char buf[10];
        size_t r;

        /* Normal copy */
        r = strscpy(buf, sizeof(buf), "hello");
        assert_se(r > 0);
        assert_se(streq(buf, "hello"));

        /* Truncation */
        r = strscpy(buf, sizeof(buf), "hello world!");
        assert_se(r == 0);  /* returns 0 on truncation */
        assert_se(buf[sizeof(buf) - 1] == '\0');

        /* Empty string */
        r = strscpy(buf, sizeof(buf), "");
        assert_se(r > 0);
        assert_se(streq(buf, ""));
}

TEST(strscpyl_basic) {
        char buf[32];
        size_t r;

        r = strscpyl(buf, sizeof(buf), "hello", " ", "world", NULL);
        assert_se(r > 0);
        assert_se(streq(buf, "hello world"));
}

TEST(strpcpy_basic) {
        char buf[16];
        char *p = buf;
        size_t left = sizeof(buf);

        left = strpcpy(&p, left, "hello");
        assert_se(left > 0);
        assert_se(streq(buf, "hello"));

        left = strpcpy(&p, left, " world");
        assert_se(left >= 0);
        assert_se(streq(buf, "hello world"));
}

TEST(strscpy_full_truncated) {
        char buf[5];
        bool truncated = false;

        /* Exact fit */
        size_t r = strscpy_full(buf, sizeof(buf), "abcd", &truncated);
        assert_se(!truncated);
        assert_se(streq(buf, "abcd"));

        /* Truncation */
        r = strscpy_full(buf, sizeof(buf), "abcdefgh", &truncated);
        assert_se(truncated);
        assert_se(buf[sizeof(buf) - 1] == '\0');
}

DEFINE_TEST_MAIN(LOG_DEBUG);
