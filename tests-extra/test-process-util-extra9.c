/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sched.h>

#include "process-util.h"
#include "tests.h"

TEST(pid_compare_func_basic) {
        assert_se(pid_compare_func((const pid_t[]) { 1 }, (const pid_t[]) { 2 }) < 0);
        assert_se(pid_compare_func((const pid_t[]) { 2 }, (const pid_t[]) { 1 }) > 0);
        assert_se(pid_compare_func((const pid_t[]) { 42 }, (const pid_t[]) { 42 }) == 0);
}

TEST(nice_is_valid_basic) {
        assert_se(nice_is_valid(0));
        assert_se(nice_is_valid(19));
        assert_se(nice_is_valid(-20));
        assert_se(!nice_is_valid(20));
        assert_se(!nice_is_valid(-21));
        assert_se(!nice_is_valid(100));
}

TEST(sched_policy_is_valid_basic) {
        assert_se(sched_policy_is_valid(SCHED_OTHER));
        assert_se(sched_policy_is_valid(SCHED_FIFO));
        assert_se(sched_policy_is_valid(SCHED_RR));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
