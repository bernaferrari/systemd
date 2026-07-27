/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/resource.h>

#include "rlimit-util.h"
#include "tests.h"

TEST(rlimit_to_string) {
        ASSERT_STREQ(rlimit_to_string(RLIMIT_AS), "AS");
        ASSERT_STREQ(rlimit_to_string(RLIMIT_CORE), "CORE");
        ASSERT_STREQ(rlimit_to_string(RLIMIT_CPU), "CPU");
        ASSERT_STREQ(rlimit_to_string(RLIMIT_DATA), "DATA");
        ASSERT_STREQ(rlimit_to_string(RLIMIT_FSIZE), "FSIZE");
        ASSERT_STREQ(rlimit_to_string(RLIMIT_NOFILE), "NOFILE");
        ASSERT_STREQ(rlimit_to_string(RLIMIT_NPROC), "NPROC");

#ifdef RLIMIT_MEMLOCK
        ASSERT_STREQ(rlimit_to_string(RLIMIT_MEMLOCK), "MEMLOCK");
#endif

#ifdef RLIMIT_RSS
        ASSERT_STREQ(rlimit_to_string(RLIMIT_RSS), "RSS");
#endif

        ASSERT_STREQ(rlimit_to_string(RLIMIT_STACK), "STACK");
}

TEST(rlimit_from_string) {
        ASSERT_EQ(rlimit_from_string("AS"), RLIMIT_AS);
        ASSERT_EQ(rlimit_from_string("CORE"), RLIMIT_CORE);
        ASSERT_EQ(rlimit_from_string("CPU"), RLIMIT_CPU);
        ASSERT_EQ(rlimit_from_string("DATA"), RLIMIT_DATA);
        ASSERT_EQ(rlimit_from_string("FSIZE"), RLIMIT_FSIZE);
        ASSERT_EQ(rlimit_from_string("NOFILE"), RLIMIT_NOFILE);
        ASSERT_EQ(rlimit_from_string("NPROC"), RLIMIT_NPROC);
        ASSERT_EQ(rlimit_from_string("STACK"), RLIMIT_STACK);
        ASSERT_EQ(rlimit_from_string("invalid"), -EINVAL);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
