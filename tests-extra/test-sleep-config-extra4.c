/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "sleep-config.h"
#include "string-util.h"
#include "strv.h"
#include "tests.h"

TEST(sleep_needs_mem_sleep_basic) {
        /* Empty config → false */
        SleepConfig sc = {};
        assert_se(!sleep_needs_mem_sleep(&sc, SLEEP_SUSPEND));

        /* State contains "mem" → true */
        sc = (SleepConfig) {};
        sc.states[SLEEP_SUSPEND] = strv_new("mem", "freeze");
        assert_se(sc.states[SLEEP_SUSPEND]);
        assert_se(sleep_needs_mem_sleep(&sc, SLEEP_SUSPEND));
        sc = (SleepConfig) {};

        /* Mode contains "suspend" → true */
        sc = (SleepConfig) {};
        sc.modes[SLEEP_HYBRID_SLEEP] = strv_new("suspend", "shutdown");
        assert_se(sc.modes[SLEEP_HYBRID_SLEEP]);
        assert_se(sleep_needs_mem_sleep(&sc, SLEEP_HYBRID_SLEEP));
        sc = (SleepConfig) {};

        /* Neither → false */
        sc = (SleepConfig) {};
        sc.states[SLEEP_SUSPEND] = strv_new("freeze");
        sc.modes[SLEEP_SUSPEND] = strv_new("platform");
        assert_se(!sleep_needs_mem_sleep(&sc, SLEEP_SUSPEND));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
