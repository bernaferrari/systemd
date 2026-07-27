/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/wait.h>

#include "process-util.h"
#include "tests.h"

TEST(pid_is_valid_basic) {
        assert_se(pid_is_valid(1));
        assert_se(pid_is_valid(100));
        assert_se(pid_is_valid(INT_MAX));
        assert_se(!pid_is_valid(0));
        assert_se(!pid_is_valid(-1));
        assert_se(!pid_is_valid(-100));
}

TEST(pid_is_automatic_basic) {
        assert_se(pid_is_automatic(PID_AUTOMATIC));
        assert_se(!pid_is_automatic(1));
        assert_se(!pid_is_automatic(0));
        assert_se(!pid_is_automatic(-1));
}

TEST(pid_ptr_roundtrip) {
        assert_se(PTR_TO_PID(PID_TO_PTR(1)) == 1);
        assert_se(PTR_TO_PID(PID_TO_PTR(1234)) == 1234);
        assert_se(PTR_TO_PID(PID_TO_PTR(0)) == 0);
}

TEST(siginfo_code_is_dead) {
        assert_se(SIGINFO_CODE_IS_DEAD(CLD_EXITED));
        assert_se(SIGINFO_CODE_IS_DEAD(CLD_KILLED));
        assert_se(SIGINFO_CODE_IS_DEAD(CLD_DUMPED));
        assert_se(!SIGINFO_CODE_IS_DEAD(CLD_TRAPPED));
        assert_se(!SIGINFO_CODE_IS_DEAD(CLD_STOPPED));
        assert_se(!SIGINFO_CODE_IS_DEAD(CLD_CONTINUED));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
