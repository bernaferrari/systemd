/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "process-util.h"
#include "tests.h"
#include <sched.h>

TEST(nice_is_valid) {
        ASSERT_TRUE(nice_is_valid(0));
        ASSERT_TRUE(nice_is_valid(-20));
        ASSERT_TRUE(nice_is_valid(19));
        ASSERT_FALSE(nice_is_valid(-21));
        ASSERT_FALSE(nice_is_valid(20));
        ASSERT_FALSE(nice_is_valid(100));
        ASSERT_FALSE(nice_is_valid(-100));
}

TEST(oom_score_adjust_is_valid) {
        ASSERT_TRUE(oom_score_adjust_is_valid(0));
        ASSERT_TRUE(oom_score_adjust_is_valid(-1000));
        ASSERT_TRUE(oom_score_adjust_is_valid(1000));
        ASSERT_FALSE(oom_score_adjust_is_valid(-1001));
        ASSERT_FALSE(oom_score_adjust_is_valid(1001));
}

TEST(pid_compare_func) {
        pid_t a = 1, b = 2, c = 1;
        ASSERT_LT(pid_compare_func(&a, &b), 0);
        ASSERT_GT(pid_compare_func(&b, &a), 0);
        ASSERT_EQ(pid_compare_func(&a, &c), 0);
}

TEST(sched_policy_is_valid) {
        ASSERT_TRUE(sched_policy_is_valid(SCHED_OTHER));
        ASSERT_TRUE(sched_policy_is_valid(SCHED_BATCH));
        ASSERT_TRUE(sched_policy_is_valid(SCHED_IDLE));
        ASSERT_TRUE(sched_policy_is_valid(SCHED_FIFO));
        ASSERT_TRUE(sched_policy_is_valid(SCHED_RR));
        ASSERT_FALSE(sched_policy_is_valid(-1));
        ASSERT_FALSE(sched_policy_is_valid(999));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
