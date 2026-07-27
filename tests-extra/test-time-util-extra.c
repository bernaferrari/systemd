/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "time-util.h"
#include "tests.h"

TEST(parse_sec) {
        usec_t u;
        ASSERT_OK(parse_sec("0", &u));
        ASSERT_EQ(u, 0);
        ASSERT_OK(parse_sec("30", &u));
        ASSERT_EQ(u, 30 * USEC_PER_SEC);
        ASSERT_OK(parse_sec("60s", &u));
        ASSERT_EQ(u, 60 * USEC_PER_SEC);
        ASSERT_OK(parse_sec("5min", &u));
        ASSERT_EQ(u, 5 * 60 * USEC_PER_SEC);
        ASSERT_OK(parse_sec("1h", &u));
        ASSERT_EQ(u, 60 * 60 * USEC_PER_SEC);
        ASSERT_OK(parse_sec("1d", &u));
        ASSERT_EQ(u, 24 * 60 * 60 * USEC_PER_SEC);
        ASSERT_OK(parse_sec("0.5", &u));
        ASSERT_EQ(u, 500 * USEC_PER_MSEC);
}

TEST(format_timespan) {
        char buf[FORMAT_TIMESPAN_MAX];
        /* t <= 0 returns "0" (no suffix) */
        ASSERT_NOT_NULL(format_timespan(buf, sizeof(buf), 0, USEC_PER_SEC));
        ASSERT_STREQ(buf, "0");
        ASSERT_NOT_NULL(format_timespan(buf, sizeof(buf), 500 * USEC_PER_MSEC, USEC_PER_SEC));
        ASSERT_STREQ(buf, "500ms");
        ASSERT_NOT_NULL(format_timespan(buf, sizeof(buf), 5 * USEC_PER_SEC, USEC_PER_SEC));
        ASSERT_STREQ(buf, "5s");
        ASSERT_NOT_NULL(format_timespan(buf, sizeof(buf), 90 * USEC_PER_SEC, USEC_PER_SEC));
        ASSERT_STREQ(buf, "1min 30s");
}

DEFINE_TEST_MAIN(LOG_DEBUG);
