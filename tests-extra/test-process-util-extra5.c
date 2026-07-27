/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sched.h>
#include <sys/wait.h>

#include "alloc-util.h"
#include "parse-util.h"
#include "process-util.h"
#include "string-util.h"
#include "tests.h"

TEST(sigchld_code_to_string_basic) {
        assert_se(streq(sigchld_code_to_string(CLD_EXITED), "exited"));
        assert_se(streq(sigchld_code_to_string(CLD_KILLED), "killed"));
        assert_se(streq(sigchld_code_to_string(CLD_DUMPED), "dumped"));
        assert_se(streq(sigchld_code_to_string(CLD_TRAPPED), "trapped"));
        assert_se(streq(sigchld_code_to_string(CLD_STOPPED), "stopped"));
        assert_se(streq(sigchld_code_to_string(CLD_CONTINUED), "continued"));

        /* Reverse */
        assert_se(sigchld_code_from_string("exited") == CLD_EXITED);
        assert_se(sigchld_code_from_string("killed") == CLD_KILLED);
        assert_se(sigchld_code_from_string("dumped") == CLD_DUMPED);
        assert_se(sigchld_code_from_string("invalid") < 0);
}

TEST(sched_policy_from_string_basic) {
        assert_se(sched_policy_from_string("other") == SCHED_OTHER);
        assert_se(sched_policy_from_string("fifo") == SCHED_FIFO);
        assert_se(sched_policy_from_string("rr") == SCHED_RR);
        assert_se(sched_policy_from_string("batch") == SCHED_BATCH);
        assert_se(sched_policy_from_string("idle") == SCHED_IDLE);
        assert_se(sched_policy_from_string("invalid") < 0);

        /* Numeric fallback */
        assert_se(sched_policy_from_string("0") == SCHED_OTHER);
        assert_se(sched_policy_from_string("1") == SCHED_FIFO);
}

TEST(sched_policy_to_string_basic) {
        _cleanup_free_ char *s = NULL;
        assert_se(sched_policy_to_string_alloc(SCHED_OTHER, &s) >= 0);
        assert_se(streq(s, "other"));
}

TEST(parse_pid_basic) {
        pid_t pid;
        int r;

        r = parse_pid("1", &pid);
        assert_se(r >= 0);
        assert_se(pid == 1);

        /* 0 is not a valid PID (pid_is_valid requires p > 0) */
        assert_se(parse_pid("0", &pid) < 0);

        r = parse_pid("65535", &pid);
        assert_se(r >= 0);
        assert_se(pid == 65535);

        /* Invalid */
        assert_se(parse_pid("", &pid) < 0);
        assert_se(parse_pid("abc", &pid) < 0);
        assert_se(parse_pid("-1", &pid) < 0);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
