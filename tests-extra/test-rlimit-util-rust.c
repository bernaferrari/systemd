/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Shadow test: C rlimit-util vs Rust rs_rlimit_util */

#include "rlimit-util.h"
#include "rust/rlimit_util.h"
#include "string-util.h"
#include "tests.h"

/* ── rlimit_to_string ─────────────────────────────────────────────────── */

TEST(rlimit_to_string_c_vs_rs) {
        static const int rlimits[] = {
                RLIMIT_CPU, RLIMIT_FSIZE, RLIMIT_DATA, RLIMIT_STACK, RLIMIT_CORE,
                RLIMIT_RSS, RLIMIT_NPROC, RLIMIT_NOFILE, RLIMIT_MEMLOCK, RLIMIT_AS,
                RLIMIT_LOCKS, RLIMIT_SIGPENDING, RLIMIT_MSGQUEUE, RLIMIT_NICE,
                RLIMIT_RTPRIO, RLIMIT_RTTIME,
        };

        for (size_t i = 0; i < ELEMENTSOF(rlimits); i++) {
                const char *c_str = rlimit_to_string(rlimits[i]);
                const char *rs_str = rs_rlimit_to_string(rlimits[i]);
                assert_se(c_str != NULL);
                assert_se(rs_str != NULL);
                assert_se(streq(c_str, rs_str));
        }

        /* Invalid indices */
        assert_se(rlimit_to_string(999) == NULL);
        assert_se(rs_rlimit_to_string(999) == NULL);
        assert_se(rlimit_to_string(-1) == NULL);
        assert_se(rs_rlimit_to_string(-1) == NULL);
}

/* ── rlimit_from_string ───────────────────────────────────────────────── */

TEST(rlimit_from_string_c_vs_rs) {
        static const char *names[] = {
                "CPU", "FSIZE", "DATA", "STACK", "CORE", "RSS", "NPROC",
                "NOFILE", "MEMLOCK", "AS", "LOCKS", "SIGPENDING", "MSGQUEUE",
                "NICE", "RTPRIO", "RTTIME", NULL
        };

        for (const char **p = names; *p; p++) {
                int c_val = rlimit_from_string(*p);
                int rs_val = rs_rlimit_from_string(*p);
                ASSERT_EQ(c_val, rs_val);
                assert_se(c_val >= 0);
        }

        /* Invalid */
        ASSERT_EQ(rlimit_from_string("bogus"), rs_rlimit_from_string("bogus"));
        ASSERT_LT(rlimit_from_string("bogus"), 0);

        ASSERT_EQ(rlimit_from_string(""), rs_rlimit_from_string(""));
        ASSERT_LT(rlimit_from_string(""), 0);

        /* Case sensitive */
        ASSERT_EQ(rlimit_from_string("cpu"), rs_rlimit_from_string("cpu"));
        ASSERT_LT(rlimit_from_string("cpu"), 0);
}

/* ── rlimit_from_string_harder ────────────────────────────────────────── */

TEST(rlimit_from_string_harder_c_vs_rs) {
        /* RLIMIT_ prefix */
        ASSERT_EQ(rlimit_from_string_harder("RLIMIT_CPU"), rs_rlimit_from_string_harder("RLIMIT_CPU"));
        assert_se(rlimit_from_string_harder("RLIMIT_CPU") == RLIMIT_CPU);

        /* Limit prefix */
        ASSERT_EQ(rlimit_from_string_harder("LimitNOFILE"), rs_rlimit_from_string_harder("LimitNOFILE"));
        assert_se(rlimit_from_string_harder("LimitNOFILE") == RLIMIT_NOFILE);

        /* No prefix */
        ASSERT_EQ(rlimit_from_string_harder("CPU"), rs_rlimit_from_string_harder("CPU"));
        assert_se(rlimit_from_string_harder("CPU") == RLIMIT_CPU);

        /* Case sensitive: lowercase should fail */
        ASSERT_EQ(rlimit_from_string_harder("cpu"), rs_rlimit_from_string_harder("cpu"));
        ASSERT_LT(rlimit_from_string_harder("cpu"), 0);

        /* Invalid */
        ASSERT_EQ(rlimit_from_string_harder("bogus"), rs_rlimit_from_string_harder("bogus"));
        ASSERT_LT(rlimit_from_string_harder("bogus"), 0);

        /* RLIMIT_ prefix with invalid suffix */
        ASSERT_EQ(rlimit_from_string_harder("RLIMIT_BOGUS"), rs_rlimit_from_string_harder("RLIMIT_BOGUS"));
        ASSERT_LT(rlimit_from_string_harder("RLIMIT_BOGUS"), 0);
}

DEFINE_TEST_MAIN(LOG_INFO);
