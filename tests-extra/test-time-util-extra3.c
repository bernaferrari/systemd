/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/time.h>

#include "time-util.h"
#include "tests.h"

TEST(parse_sec_basic) {
        usec_t val;

        assert_se(parse_sec("5", &val) >= 0);
        assert_se(val == 5 * USEC_PER_SEC);

        assert_se(parse_sec("5s", &val) >= 0);
        assert_se(val == 5 * USEC_PER_SEC);

        assert_se(parse_sec("1min", &val) >= 0);
        assert_se(val == USEC_PER_MINUTE);

        assert_se(parse_sec("1h", &val) >= 0);
        assert_se(val == USEC_PER_HOUR);

        assert_se(parse_sec("1d", &val) >= 0);
        assert_se(val == USEC_PER_DAY);

        assert_se(parse_sec("1w", &val) >= 0);
        assert_se(val == USEC_PER_WEEK);

        assert_se(parse_sec("1ms", &val) >= 0);
        assert_se(val == USEC_PER_MSEC);

        assert_se(parse_sec("100us", &val) >= 0);
        assert_se(val == 100);

        assert_se(parse_sec("infinity", &val) >= 0);
        assert_se(val == USEC_INFINITY);

        assert_se(parse_sec("0", &val) >= 0);
        assert_se(val == 0);
}

TEST(parse_sec_invalid) {
        usec_t val;

        assert_se(parse_sec("", &val) < 0);
        assert_se(parse_sec("garbage", &val) < 0);
        assert_se(parse_sec("-5", &val) < 0);
}

TEST(parse_sec_combined) {
        usec_t val;

        assert_se(parse_sec("1min 30s", &val) >= 0);
        assert_se(val == 90 * USEC_PER_SEC);

        assert_se(parse_sec("1h 1min 1s", &val) >= 0);
        assert_se(val == USEC_PER_HOUR + USEC_PER_MINUTE + USEC_PER_SEC);
}

TEST(parse_time_default_unit) {
        usec_t val;

        /* Default unit: seconds */
        assert_se(parse_time("100", &val, USEC_PER_SEC) >= 0);
        assert_se(val == 100 * USEC_PER_SEC);

        /* Default unit: milliseconds */
        assert_se(parse_time("100", &val, USEC_PER_MSEC) >= 0);
        assert_se(val == 100 * USEC_PER_MSEC);
}

TEST(format_timespan_basic) {
        char buf[FORMAT_TIMESPAN_MAX];

        assert_se(format_timespan(buf, sizeof(buf), 0, 0));
        assert_se(streq(buf, "0"));

        assert_se(format_timespan(buf, sizeof(buf), USEC_PER_SEC, 0));
        assert_se(strstr(buf, "s") != NULL);

        assert_se(format_timespan(buf, sizeof(buf), USEC_PER_MINUTE, 0));
        assert_se(strstr(buf, "min") != NULL);

        assert_se(format_timespan(buf, sizeof(buf), USEC_PER_HOUR, 0));
        assert_se(strstr(buf, "h") != NULL);

        assert_se(format_timespan(buf, sizeof(buf), USEC_PER_DAY, 0));
        assert_se(strstr(buf, "d") != NULL);
}

TEST(usec_add_basic) {
        assert_se(usec_add(100, 200) == 300);
        assert_se(usec_add(0, 0) == 0);
        assert_se(usec_add(USEC_INFINITY, 1) == USEC_INFINITY);
        assert_se(usec_add(1, USEC_INFINITY) == USEC_INFINITY);
}

TEST(usec_sub_unsigned_basic) {
        assert_se(usec_sub_unsigned(500, 200) == 300);
        assert_se(usec_sub_unsigned(100, 0) == 100);
        assert_se(usec_sub_unsigned(0, 0) == 0);
        assert_se(usec_sub_unsigned(USEC_INFINITY, 100) == USEC_INFINITY);
        assert_se(usec_sub_unsigned(100, USEC_INFINITY) == 0);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
