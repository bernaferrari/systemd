/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "process-util.h"
#include "tests.h"
#include <sched.h>
#include <sys/wait.h>

TEST(sigchld_code_to_from_string) {
        assert_se(streq(sigchld_code_to_string(CLD_EXITED), "exited"));
        assert_se(streq(sigchld_code_to_string(CLD_KILLED), "killed"));
        assert_se(streq(sigchld_code_to_string(CLD_DUMPED), "dumped"));
        assert_se(streq(sigchld_code_to_string(CLD_STOPPED), "stopped"));
        assert_se(streq(sigchld_code_to_string(CLD_CONTINUED), "continued"));

        assert_se(sigchld_code_from_string("exited") == CLD_EXITED);
        assert_se(sigchld_code_from_string("killed") == CLD_KILLED);
        assert_se(sigchld_code_from_string("dumped") == CLD_DUMPED);
        assert_se(sigchld_code_from_string("stopped") == CLD_STOPPED);
        assert_se(sigchld_code_from_string("continued") == CLD_CONTINUED);
        assert_se(sigchld_code_from_string("invalid") < 0);
}

TEST(sched_policy_from_string) {
        /* WITH_FALLBACK: generates to_string_alloc (not to_string) and from_string with fallback */
        assert_se(sched_policy_from_string("other") == SCHED_OTHER);
        assert_se(sched_policy_from_string("batch") == SCHED_BATCH);
        assert_se(sched_policy_from_string("idle") == SCHED_IDLE);
        assert_se(sched_policy_from_string("fifo") == SCHED_FIFO);
        assert_se(sched_policy_from_string("rr") == SCHED_RR);

        /* Fallback accepts numeric strings */
        assert_se(sched_policy_from_string("0") == SCHED_OTHER);
        assert_se(sched_policy_from_string("invalid") < 0);
}

TEST(sched_policy_to_string_alloc) {
        _cleanup_free_ char *s = NULL;
        assert_se(sched_policy_to_string_alloc(SCHED_OTHER, &s) >= 0);
        assert_se(streq(s, "other"));
        s = mfree(s);

        assert_se(sched_policy_to_string_alloc(SCHED_FIFO, &s) >= 0);
        assert_se(streq(s, "fifo"));
        s = mfree(s);

        assert_se(sched_policy_to_string_alloc(SCHED_RR, &s) >= 0);
        assert_se(streq(s, "rr"));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
