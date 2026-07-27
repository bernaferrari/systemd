/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>

#include "time-util.h"
#include "tests.h"

TEST(usec_to_jiffies_basic) {
        usec_t us = USEC_PER_SEC;
        uint64_t j = usec_to_jiffies(us);
        assert_se(j > 0);
        log_debug("usec_to_jiffies(1s): %" PRIu64, j);
}

TEST(jiffies_to_usec_basic) {
        uint64_t j = 1000;
        usec_t us = jiffies_to_usec(j);
        assert_se(us > 0);
        log_debug("jiffies_to_usec(1000): %" PRIu64, us);
}

TEST(timezone_is_valid_basic) {
        assert_se(timezone_is_valid("UTC", LOG_DEBUG));
        assert_se(timezone_is_valid("America/New_York", LOG_DEBUG));
        assert_se(timezone_is_valid("Europe/London", LOG_DEBUG));
        assert_se(!timezone_is_valid("Invalid/Zone", LOG_DEBUG));
        assert_se(!timezone_is_valid("", LOG_DEBUG));
}

TEST(in_utc_timezone_basic) {
        (void) in_utc_timezone();
        log_debug("in_utc_timezone: %s", in_utc_timezone() ? "yes" : "no");
}

TEST(parse_gmtoff_basic) {
        long gmtoff = 0;
        int r;

        r = parse_gmtoff("+0000", &gmtoff);
        assert_se(r >= 0);
        assert_se(gmtoff == 0);

        r = parse_gmtoff("+0100", &gmtoff);
        assert_se(r >= 0);
        assert_se(gmtoff == 3600);

        r = parse_gmtoff("-0500", &gmtoff);
        assert_se(r >= 0);
        assert_se(gmtoff == -18000);

        r = parse_gmtoff("+0530", &gmtoff);
        assert_se(r >= 0);
        assert_se(gmtoff == 19800);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
