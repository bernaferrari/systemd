/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "ratelimit.h"
#include "time-util.h"
#include "tests.h"

TEST(ratelimit_below_basic) {
        RateLimit r = { .interval = 100 * USEC_PER_SEC, .burst = 5 };
        assert_se(ratelimit_below(&r) != 0);
        assert_se(ratelimit_below(&r) != 0);
        assert_se(ratelimit_below(&r) != 0);
        assert_se(ratelimit_below(&r) != 0);
        assert_se(ratelimit_below(&r) != 0);
}

TEST(ratelimit_off) {
        RateLimit r = RATELIMIT_OFF;
        assert_se(ratelimit_below(&r) != 0);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
