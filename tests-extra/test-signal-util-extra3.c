/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "signal-util.h"
#include "string-util.h"
#include "tests.h"

TEST(signal_from_string_basic) {
        assert_se(signal_from_string("TERM") == SIGTERM);
        assert_se(signal_from_string("KILL") == SIGKILL);
        assert_se(signal_from_string("INT") == SIGINT);
        assert_se(signal_from_string("15") == SIGTERM);
        assert_se(signal_from_string("9") == SIGKILL);
        assert_se(signal_from_string("invalid") < 0);
}

TEST(signal_to_string_basic) {
        const char *s = signal_to_string(SIGTERM);
        assert_se(s && streq(s, "TERM"));

        s = signal_to_string(SIGKILL);
        assert_se(s && streq(s, "KILL"));
}

TEST(sigset_add_many_basic) {
        sigset_t ss;
        assert_se(sigemptyset(&ss) == 0);
        assert_se(sigset_add_many(&ss, SIGTERM, SIGINT, -1) >= 0);
        assert_se(sigismember(&ss, SIGTERM));
        assert_se(sigismember(&ss, SIGINT));
        assert_se(!sigismember(&ss, SIGKILL));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
