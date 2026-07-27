/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "signal-util.h"
#include "tests.h"

TEST(signal_to_string) {
        ASSERT_STREQ(signal_to_string(SIGTERM), "TERM");
        ASSERT_STREQ(signal_to_string(SIGKILL), "KILL");
        ASSERT_STREQ(signal_to_string(SIGUSR1), "USR1");
        ASSERT_STREQ(signal_to_string(SIGUSR2), "USR2");
        ASSERT_STREQ(signal_to_string(SIGINT), "INT");
        ASSERT_STREQ(signal_to_string(SIGHUP), "HUP");

        /* Unknown signal returns numeric string */
        ASSERT_TRUE(signal_to_string(0)[0] != '\0');
}

TEST(signal_from_string) {
        int sig;

        /* By name */
        sig = signal_from_string("TERM");
        ASSERT_EQ(sig, SIGTERM);

        sig = signal_from_string("KILL");
        ASSERT_EQ(sig, SIGKILL);

        /* With SIG prefix */
        sig = signal_from_string("SIGTERM");
        ASSERT_EQ(sig, SIGTERM);

        /* By number */
        sig = signal_from_string("15");
        ASSERT_EQ(sig, SIGTERM);

        /* RTMIN */
        sig = signal_from_string("RTMIN");
        ASSERT_EQ(sig, SIGRTMIN);

        /* Invalid */
        ASSERT_LT(signal_from_string("BOGUS"), 0);
        ASSERT_LT(signal_from_string(""), 0);

        /* Out of range number */
        ASSERT_LT(signal_from_string("99999"), 0);
}

TEST(parse_signo) {
        int sig;

        ASSERT_OK(parse_signo("15", &sig));
        ASSERT_EQ(sig, SIGTERM);

        ASSERT_OK(parse_signo("9", &sig));
        ASSERT_EQ(sig, SIGKILL);

        /* Invalid */
        ASSERT_LT(parse_signo("abc", &sig), 0);

        /* Out of range */
        ASSERT_LT(parse_signo("99999", &sig), 0);

        /* NULL ret is ok (just validates) */
        ASSERT_OK(parse_signo("15", NULL));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
