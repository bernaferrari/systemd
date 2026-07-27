/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "parse-util.h"
#include "tests.h"

TEST(parse_tristate) {
        int r;

        ASSERT_OK(parse_tristate("1", &r));
        ASSERT_EQ(r, 1);
        ASSERT_OK(parse_tristate("yes", &r));
        ASSERT_EQ(r, 1);
        ASSERT_OK(parse_tristate("true", &r));
        ASSERT_EQ(r, 1);
        ASSERT_OK(parse_tristate("on", &r));
        ASSERT_EQ(r, 1);

        ASSERT_OK(parse_tristate("0", &r));
        ASSERT_EQ(r, 0);
        ASSERT_OK(parse_tristate("no", &r));
        ASSERT_EQ(r, 0);
        ASSERT_OK(parse_tristate("false", &r));
        ASSERT_EQ(r, 0);
        ASSERT_OK(parse_tristate("off", &r));
        ASSERT_EQ(r, 0);

        ASSERT_EQ(parse_tristate("2", &r), -EINVAL);
}

TEST(parse_tristate_full) {
        int r;

        /* Custom third value maps to -1 */
        ASSERT_OK(parse_tristate_full("gentle", "gentle", &r));
        ASSERT_EQ(r, -1);

        /* Empty string also maps to third state */
        ASSERT_OK(parse_tristate_full("", "gentle", &r));
        ASSERT_EQ(r, -1);

        ASSERT_OK(parse_tristate_full("1", "gentle", &r));
        ASSERT_EQ(r, 1);

        ASSERT_OK(parse_tristate_full("0", "gentle", &r));
        ASSERT_EQ(r, 0);

        ASSERT_EQ(parse_tristate_full("invalid", "gentle", &r), -EINVAL);
}

TEST(parse_range) {
        unsigned lower, upper;

        ASSERT_OK(parse_range("10-20", &lower, &upper));
        ASSERT_EQ(lower, 10u);
        ASSERT_EQ(upper, 20u);

        ASSERT_OK(parse_range("5", &lower, &upper));
        ASSERT_EQ(lower, 5u);
        ASSERT_EQ(upper, 5u);

        ASSERT_EQ(parse_range("", &lower, &upper), -EINVAL);
        ASSERT_EQ(parse_range("10-5", &lower, &upper), 0); /* reversed range is ok */
        ASSERT_EQ(parse_range("abc", &lower, &upper), -EINVAL);
}

TEST(parse_fd) {
        ASSERT_EQ(parse_fd("0"), 0);
        ASSERT_EQ(parse_fd("42"), 42);
        ASSERT_EQ(parse_fd("-1"), -EBADF);
        ASSERT_EQ(parse_fd("abc"), -EINVAL);
}

TEST(parse_nice) {
        int n;

        ASSERT_OK(parse_nice("0", &n));
        ASSERT_EQ(n, 0);
        ASSERT_OK(parse_nice("5", &n));
        ASSERT_EQ(n, 5);
        ASSERT_OK(parse_nice("-5", &n));
        ASSERT_EQ(n, -5);
        ASSERT_EQ(parse_nice("20", &n), -ERANGE);
        ASSERT_EQ(parse_nice("-21", &n), -ERANGE);
        ASSERT_EQ(parse_nice("abc", &n), -EINVAL);
}

TEST(parse_oom_score_adjust) {
        int s;

        ASSERT_OK(parse_oom_score_adjust("0", &s));
        ASSERT_EQ(s, 0);
        ASSERT_OK(parse_oom_score_adjust("500", &s));
        ASSERT_EQ(s, 500);
        ASSERT_OK(parse_oom_score_adjust("-1000", &s));
        ASSERT_EQ(s, -1000);
        ASSERT_EQ(parse_oom_score_adjust("1001", &s), -ERANGE);
        ASSERT_EQ(parse_oom_score_adjust("-1001", &s), -ERANGE);
        ASSERT_EQ(parse_oom_score_adjust("abc", &s), -EINVAL);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
