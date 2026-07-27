/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "signal-util.h"
#include "tests.h"

TEST(signal_valid_basic) {
        assert_se(SIGNAL_VALID(SIGTERM));
        assert_se(SIGNAL_VALID(SIGKILL));
        assert_se(SIGNAL_VALID(SIGINT));
        assert_se(!SIGNAL_VALID(0));
        assert_se(!SIGNAL_VALID(-1));
        assert_se(!SIGNAL_VALID(_NSIG));
}

TEST(signal_to_string_with_check_basic) {
        const char *s = signal_to_string_with_check(SIGTERM);
        assert_se(s && streq(s, "TERM"));

        s = signal_to_string_with_check(SIGKILL);
        assert_se(s && streq(s, "KILL"));

        s = signal_to_string_with_check(0);
        assert_se(s == NULL);

        s = signal_to_string_with_check(-1);
        assert_se(s == NULL);
}

TEST(parse_signo_basic) {
        int signo;
        assert_se(parse_signo("15", &signo) >= 0);
        assert_se(signo == SIGTERM);

        assert_se(parse_signo("9", &signo) >= 0);
        assert_se(signo == SIGKILL);

        assert_se(parse_signo("0", &signo) < 0);

        assert_se(parse_signo("invalid", &signo) < 0);
}

TEST(si_code_from_process_basic) {
        assert_se(si_code_from_process(SI_USER));
        assert_se(si_code_from_process(SI_QUEUE));
        assert_se(!si_code_from_process(SI_KERNEL));
}

TEST(block_signals_reset_basic) {
        sigset_t *ss = NULL;
        block_signals_reset(&ss);
        assert_se(ss == NULL);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
