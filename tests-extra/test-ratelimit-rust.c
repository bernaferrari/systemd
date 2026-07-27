/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <string.h>

#include "tests.h"
#include "ratelimit.h"

/* Rust FFI */
#include "rust/ratelimit.h"

/* ── ratelimit_num_dropped ──────────────────────────────────────────── */

TEST(ratelimit_num_dropped_zero) {
        RateLimit c = { .interval = 1000000, .burst = 10, .num = 5, .begin = 1000000 };
        RateLimit r = { .interval = 1000000, .burst = 10, .num = 5, .begin = 1000000 };

        assert_se(ratelimit_num_dropped(&c) == rs_ratelimit_num_dropped(&r));
        assert_se(ratelimit_num_dropped(&c) == 0);
}

TEST(ratelimit_num_dropped_some) {
        RateLimit c = { .interval = 1000000, .burst = 10, .num = 15, .begin = 1000000 };
        RateLimit r = { .interval = 1000000, .burst = 10, .num = 15, .begin = 1000000 };

        assert_se(ratelimit_num_dropped(&c) == rs_ratelimit_num_dropped(&r));
        assert_se(ratelimit_num_dropped(&c) == 5);
}

TEST(ratelimit_num_dropped_overflow) {
        RateLimit c = { .interval = 1000000, .burst = 10, .num = UINT_MAX, .begin = 1000000 };
        RateLimit r = { .interval = 1000000, .burst = 10, .num = UINT_MAX, .begin = 1000000 };

        assert_se(ratelimit_num_dropped(&c) == rs_ratelimit_num_dropped(&r));
        assert_se(ratelimit_num_dropped(&c) == UINT_MAX);
}

/* ── ratelimit_end ──────────────────────────────────────────────────── */

TEST(ratelimit_end_basic) {
        RateLimit c = { .interval = 5000000, .burst = 10, .num = 3, .begin = 1000000 };
        RateLimit r = { .interval = 5000000, .burst = 10, .num = 3, .begin = 1000000 };

        assert_se(ratelimit_end(&c) == rs_ratelimit_end(&r));
        assert_se(ratelimit_end(&c) == 6000000);
}

TEST(ratelimit_end_zero_begin) {
        RateLimit c = { .interval = 5000000, .burst = 10, .num = 0, .begin = 0 };
        RateLimit r = { .interval = 5000000, .burst = 10, .num = 0, .begin = 0 };

        assert_se(ratelimit_end(&c) == rs_ratelimit_end(&r));
        assert_se(ratelimit_end(&c) == 0);
}

TEST(ratelimit_end_infinity_interval) {
        RateLimit c = { .interval = USEC_INFINITY, .burst = 10, .num = 3, .begin = 1000000 };
        RateLimit r = { .interval = USEC_INFINITY, .burst = 10, .num = 3, .begin = 1000000 };

        assert_se(ratelimit_end(&c) == rs_ratelimit_end(&r));
        assert_se(ratelimit_end(&c) == USEC_INFINITY);
}

/* ── ratelimit_left ─────────────────────────────────────────────────── */

TEST(ratelimit_left_zero_begin) {
        RateLimit c = { .interval = 5000000, .burst = 10, .num = 0, .begin = 0 };
        RateLimit r = { .interval = 5000000, .burst = 10, .num = 0, .begin = 0 };

        usec_t cl = ratelimit_left(&c);
        usec_t rl = rs_ratelimit_left(&r);
        assert_se(cl == rl);
        assert_se(cl == 0);
}

/* ── ratelimit_below (configured) ────────────────────────────────────── */

TEST(ratelimit_below_configured) {
        RateLimit c = { .interval = USEC_INFINITY, .burst = UINT_MAX, .num = 0, .begin = 0 };
        RateLimit r = { .interval = USEC_INFINITY, .burst = UINT_MAX, .num = 0, .begin = 0 };

        bool cb = ratelimit_below(&c);
        bool rb = rs_ratelimit_below(&r);

        assert_se(cb == rb);
        assert_se(cb);
        assert_se(c.num == r.num);
        assert_se(c.num == 1);
}

TEST(ratelimit_below_not_configured_zero_interval) {
        RateLimit c = { .interval = 0, .burst = 10, .num = 0, .begin = 0 };
        RateLimit r = { .interval = 0, .burst = 10, .num = 0, .begin = 0 };

        bool cb = ratelimit_below(&c);
        bool rb = rs_ratelimit_below(&r);

        assert_se(cb == rb);
        assert_se(cb);
}

TEST(ratelimit_below_not_configured_zero_burst) {
        RateLimit c = { .interval = 1000000, .burst = 0, .num = 0, .begin = 0 };
        RateLimit r = { .interval = 1000000, .burst = 0, .num = 0, .begin = 0 };

        bool cb = ratelimit_below(&c);
        bool rb = rs_ratelimit_below(&r);

        assert_se(cb == rb);
        assert_se(cb);
}

/* ── ratelimit_below burst exhaustion ────────────────────────────────── */

TEST(ratelimit_below_burst_exhaust) {
        RateLimit c = { .interval = USEC_INFINITY, .burst = 3, .num = 0, .begin = 0 };
        RateLimit r = { .interval = USEC_INFINITY, .burst = 3, .num = 0, .begin = 0 };

        for (int i = 0; i < 3; i++) {
                bool cb = ratelimit_below(&c);
                bool rb = rs_ratelimit_below(&r);
                assert_se(cb == rb);
                assert_se(cb);
                assert_se(c.num == r.num);
        }

        bool cb = ratelimit_below(&c);
        bool rb = rs_ratelimit_below(&r);
        assert_se(cb == rb);
        assert_se(!cb);
}

/* ── main ────────────────────────────────────────────────────────────── */

DEFINE_TEST_MAIN(LOG_INFO);
