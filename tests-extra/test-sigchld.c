/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sched.h>
#include <stdlib.h>
#include <sys/wait.h>

#include "process-util.h"
#include "tests.h"

TEST(sigchld_code_to_string) {
        ASSERT_STREQ(sigchld_code_to_string(CLD_EXITED), "exited");
        ASSERT_STREQ(sigchld_code_to_string(CLD_KILLED), "killed");
        ASSERT_STREQ(sigchld_code_to_string(CLD_DUMPED), "dumped");
        ASSERT_STREQ(sigchld_code_to_string(CLD_TRAPPED), "trapped");
        ASSERT_STREQ(sigchld_code_to_string(CLD_STOPPED), "stopped");
        ASSERT_STREQ(sigchld_code_to_string(CLD_CONTINUED), "continued");
}

TEST(sigchld_code_from_string) {
        ASSERT_EQ(sigchld_code_from_string("exited"), CLD_EXITED);
        ASSERT_EQ(sigchld_code_from_string("killed"), CLD_KILLED);
        ASSERT_EQ(sigchld_code_from_string("dumped"), CLD_DUMPED);
        ASSERT_EQ(sigchld_code_from_string("trapped"), CLD_TRAPPED);
        ASSERT_EQ(sigchld_code_from_string("stopped"), CLD_STOPPED);
        ASSERT_EQ(sigchld_code_from_string("continued"), CLD_CONTINUED);
        ASSERT_EQ(sigchld_code_from_string("invalid"), -EINVAL);
}

TEST(sched_policy_to_string) {
        _cleanup_free_ char *s = NULL;

        ASSERT_OK(sched_policy_to_string_alloc(SCHED_OTHER, &s));
        ASSERT_STREQ(s, "other");

        s = mfree(s);
        ASSERT_OK(sched_policy_to_string_alloc(SCHED_BATCH, &s));
        ASSERT_STREQ(s, "batch");

        s = mfree(s);
        ASSERT_OK(sched_policy_to_string_alloc(SCHED_IDLE, &s));
        ASSERT_STREQ(s, "idle");

        s = mfree(s);
        ASSERT_OK(sched_policy_to_string_alloc(SCHED_FIFO, &s));
        ASSERT_STREQ(s, "fifo");

        s = mfree(s);
        ASSERT_OK(sched_policy_to_string_alloc(SCHED_RR, &s));
        ASSERT_STREQ(s, "rr");
}

TEST(sched_policy_from_string) {
        ASSERT_EQ(sched_policy_from_string("other"), SCHED_OTHER);
        ASSERT_EQ(sched_policy_from_string("batch"), SCHED_BATCH);
        ASSERT_EQ(sched_policy_from_string("idle"), SCHED_IDLE);
        ASSERT_EQ(sched_policy_from_string("fifo"), SCHED_FIFO);
        ASSERT_EQ(sched_policy_from_string("rr"), SCHED_RR);
        /* Fallback: unknown non-numeric string should return -EINVAL */
        ASSERT_EQ(sched_policy_from_string("invalid"), -EINVAL);
        /* Numeric fallback: "7" should be parsed as 7 */
        ASSERT_EQ(sched_policy_from_string("7"), 7);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
