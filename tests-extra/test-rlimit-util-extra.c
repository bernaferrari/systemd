/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "rlimit-util.h"
#include "tests.h"

TEST(rlimit_parse_one_nofile) {
        rlim_t val;

        /* RLIMIT_NOFILE uses u64 parser */
        ASSERT_OK(rlimit_parse_one(RLIMIT_NOFILE, "1024", &val));
        ASSERT_EQ((uint64_t) val, 1024u);

        ASSERT_OK(rlimit_parse_one(RLIMIT_NOFILE, "infinity", &val));
        ASSERT_EQ(val, RLIM_INFINITY);

        /* Invalid */
        ASSERT_LT(rlimit_parse_one(RLIMIT_NOFILE, "abc", &val), 0);

        /* Invalid resource */
        ASSERT_LT(rlimit_parse_one(-1, "1024", &val), 0);
        ASSERT_LT(rlimit_parse_one(9999, "1024", &val), 0);
}

TEST(rlimit_parse_one_fsize) {
        rlim_t val;

        /* RLIMIT_FSIZE uses size parser */
        ASSERT_OK(rlimit_parse_one(RLIMIT_FSIZE, "1024", &val));
        ASSERT_EQ((uint64_t) val, 1024u);

        ASSERT_OK(rlimit_parse_one(RLIMIT_FSIZE, "1K", &val));
        ASSERT_EQ((uint64_t) val, 1024u);

        ASSERT_OK(rlimit_parse_one(RLIMIT_FSIZE, "infinity", &val));
        ASSERT_EQ(val, RLIM_INFINITY);
}

TEST(rlimit_parse_one_cpu) {
        rlim_t val;

        /* RLIMIT_CPU uses sec parser */
        ASSERT_OK(rlimit_parse_one(RLIMIT_CPU, "60", &val));
        ASSERT_EQ((uint64_t) val, 60u);

        ASSERT_OK(rlimit_parse_one(RLIMIT_CPU, "1min", &val));
        ASSERT_EQ((uint64_t) val, 60u);

        ASSERT_OK(rlimit_parse_one(RLIMIT_CPU, "infinity", &val));
        ASSERT_EQ(val, RLIM_INFINITY);
}

TEST(rlimit_parse_one_rttimer) {
        rlim_t val;

        /* RLIMIT_RTTIME uses usec parser */
        ASSERT_OK(rlimit_parse_one(RLIMIT_RTTIME, "500ms", &val));
        ASSERT_EQ((uint64_t) val, 500000u);
}

TEST(rlimit_parse_one_nice) {
        rlim_t val;

        /* Nice with + prefix: positive nice value */
        ASSERT_OK(rlimit_parse_one(RLIMIT_NICE, "+0", &val));
        ASSERT_EQ((uint64_t) val, 20u);

        ASSERT_OK(rlimit_parse_one(RLIMIT_NICE, "+19", &val));
        ASSERT_EQ((uint64_t) val, 1u);

        /* Nice with - prefix: negative nice value */
        ASSERT_OK(rlimit_parse_one(RLIMIT_NICE, "-20", &val));
        ASSERT_EQ((uint64_t) val, 40u);

        /* Raw resource limit value */
        ASSERT_OK(rlimit_parse_one(RLIMIT_NICE, "0", &val));
        ASSERT_EQ((uint64_t) val, 0u);
}

TEST(rlimit_parse) {
        struct rlimit rl;

        /* soft:hard format */
        ASSERT_OK(rlimit_parse(RLIMIT_NOFILE, "1024:2048", &rl));
        ASSERT_EQ((uint64_t) rl.rlim_cur, 1024u);
        ASSERT_EQ((uint64_t) rl.rlim_max, 2048u);

        /* Just soft limit */
        ASSERT_OK(rlimit_parse(RLIMIT_NOFILE, "512", &rl));
        ASSERT_EQ((uint64_t) rl.rlim_cur, 512u);
        /* Hard limit should be set to same as soft when only one value */
        ASSERT_EQ((uint64_t) rl.rlim_max, 512u);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
