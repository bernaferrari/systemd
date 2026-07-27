/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/oom.h>
#include <sched.h>
#include <sys/personality.h>
#include <sys/resource.h>

#include "architecture.h"
#include "process-util.h"
#include "string-util.h"
#include "tests.h"

TEST(nice_is_valid_basic) {
        assert_se(nice_is_valid(0));
        assert_se(nice_is_valid(19));
        assert_se(nice_is_valid(-20));

        assert_se(!nice_is_valid(-21));
        assert_se(!nice_is_valid(20));
        assert_se(!nice_is_valid(PRIO_MIN - 1));
        assert_se(!nice_is_valid(PRIO_MAX));
}

TEST(sched_policy_is_valid_basic) {
        assert_se(sched_policy_is_valid(SCHED_OTHER));
        assert_se(sched_policy_is_valid(SCHED_FIFO));
        assert_se(sched_policy_is_valid(SCHED_RR));
        assert_se(sched_policy_is_valid(SCHED_BATCH));
        assert_se(sched_policy_is_valid(SCHED_IDLE));

        assert_se(!sched_policy_is_valid(-1));
        assert_se(!sched_policy_is_valid(999));
}

TEST(oom_score_adjust_is_valid_basic) {
        assert_se(oom_score_adjust_is_valid(0));
        assert_se(oom_score_adjust_is_valid(1000));
        assert_se(oom_score_adjust_is_valid(-1000));

        assert_se(!oom_score_adjust_is_valid(-1001));
        assert_se(!oom_score_adjust_is_valid(1001));
}

TEST(pid_compare_func_basic) {
        pid_t a = 1, b = 2, c = 1;
        assert_se(pid_compare_func(&a, &b) < 0);
        assert_se(pid_compare_func(&b, &a) > 0);
        assert_se(pid_compare_func(&a, &c) == 0);
}

TEST(personality_from_string_basic) {
        /* Native architecture should map to PER_LINUX */
        assert_se(personality_from_string(architecture_to_string(native_architecture())) == PER_LINUX);

        /* Invalid */
        assert_se(personality_from_string("invalid") == PERSONALITY_INVALID);
        assert_se(personality_from_string(NULL) == PERSONALITY_INVALID);
}

TEST(personality_to_string_basic) {
        /* PER_LINUX maps to native architecture string */
        const char *s = personality_to_string(PER_LINUX);
        assert_se(s != NULL);
}

TEST(pid_is_valid_basic) {
        assert_se(pid_is_valid(1));
        assert_se(pid_is_valid(100));
        assert_se(pid_is_valid(INT32_MAX));

        assert_se(!pid_is_valid(0));
        assert_se(!pid_is_valid(-1));
}

TEST(pid_is_automatic_basic) {
        assert_se(pid_is_automatic(PID_AUTOMATIC));
        assert_se(!pid_is_automatic(0));
        assert_se(!pid_is_automatic(1));
}

TEST(ptr_to_pid_roundtrip) {
        assert_se(PTR_TO_PID(PID_TO_PTR(1)) == 1);
        assert_se(PTR_TO_PID(PID_TO_PTR(100)) == 100);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
