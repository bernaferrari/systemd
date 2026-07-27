/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "ratelimit.h"
#include "tests.h"
#include "time-util.h"

TEST(ratelimit_configured_basic) {
        /* RATELIMIT_OFF has interval=USEC_INFINITY, burst=UINT_MAX — that IS configured */
        RateLimit rl = RATELIMIT_OFF;
        assert_se(ratelimit_configured(&rl));

        /* interval=0 or burst=0 → not configured */
        rl = (RateLimit) { .interval = 0, .burst = 5 };
        assert_se(!ratelimit_configured(&rl));

        rl = (RateLimit) { .interval = USEC_PER_SEC, .burst = 0 };
        assert_se(!ratelimit_configured(&rl));

        /* Both set → configured */
        rl = (RateLimit) { .interval = USEC_PER_SEC, .burst = 5 };
        assert_se(ratelimit_configured(&rl));
}

TEST(ratelimit_reset_basic) {
        RateLimit rl = { .interval = 1000, .burst = 5, .num = 10, .begin = 100 };
        ratelimit_reset(&rl);
        assert_se(rl.num == 0);
        assert_se(rl.begin == 0);
}

TEST(ratelimit_below_basic) {
        RateLimit rl = { .interval = USEC_PER_SEC, .burst = 3, .num = 0, .begin = 0 };
        assert_se(ratelimit_below(&rl));
        assert_se(ratelimit_below(&rl));
        assert_se(ratelimit_below(&rl));
        assert_se(!ratelimit_below(&rl));
}

TEST(ratelimit_num_dropped_basic) {
        RateLimit rl = { .interval = USEC_PER_SEC, .burst = 1, .num = 0, .begin = 0 };
        ratelimit_below(&rl);
        ratelimit_below(&rl);
        assert_se(ratelimit_num_dropped(&rl) >= 1);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
