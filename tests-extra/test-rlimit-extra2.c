/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "rlimit-util.h"
#include "tests.h"

TEST(rlimit_to_from_string) {
        const char *s;

        s = rlimit_to_string(RLIMIT_NOFILE);
        ASSERT_NOT_NULL(s);
        ASSERT_STREQ(s, "NOFILE");

        s = rlimit_to_string(RLIMIT_CPU);
        ASSERT_NOT_NULL(s);
        ASSERT_STREQ(s, "CPU");

        s = rlimit_to_string(RLIMIT_NICE);
        ASSERT_NOT_NULL(s);
        ASSERT_STREQ(s, "NICE");

        /* From string - uses short names without RLIMIT_ prefix */
        ASSERT_EQ(rlimit_from_string("NOFILE"), RLIMIT_NOFILE);
        ASSERT_EQ(rlimit_from_string("CPU"), RLIMIT_CPU);
        ASSERT_EQ(rlimit_from_string("NICE"), RLIMIT_NICE);

        /* Invalid */
        ASSERT_LT(rlimit_from_string("invalid"), 0);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
