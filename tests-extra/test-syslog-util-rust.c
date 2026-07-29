/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* RUST-CONTRACT: syslog-facility-parser */
/* RUST-CONTRACT: syslog-facility-validator */
/* RUST-CONTRACT: syslog-facility-renderer */
/* RUST-CONTRACT: syslog-level-parser */
/* RUST-CONTRACT: syslog-level-validator */
/* RUST-CONTRACT: syslog-level-renderer */
/* RUST-CONTRACT: syslog-priority-parser */
/* Shadow test: C syslog-util vs Rust rs_syslog_util */

#include <syslog.h>

#include "syslog-util.h"
#include "rust/syslog_util.h"
#include "memory-util.h"
#include "tests.h"

/* ── log_facility_unshifted_is_valid ──────────────────────────────────── */

TEST(log_facility_is_valid_c_vs_rs) {
        for (int i = -1; i <= 130; i++)
                ASSERT_EQ(log_facility_unshifted_is_valid(i), rs_log_facility_unshifted_is_valid(i));
}

/* ── log_facility_unshifted_from_string ───────────────────────────────── */

TEST(log_facility_from_string_c_vs_rs) {
        const char *names[] = {
                "kern", "user", "mail", "daemon", "auth", "syslog",
                "lpr", "news", "uucp", "cron", "authpriv", "ftp",
                "local0", "local1", "local2", "local3",
                "local4", "local5", "local6", "local7",
                NULL
        };

        for (const char **p = names; *p; p++) {
                int c_val = log_facility_unshifted_from_string(*p);
                int rs_val = rs_log_facility_unshifted_from_string(*p);
                ASSERT_EQ(c_val, rs_val);
                assert_se(c_val >= 0);
        }

        /* Invalid */
        ASSERT_EQ(log_facility_unshifted_from_string("bogus"),
                  rs_log_facility_unshifted_from_string("bogus"));
        ASSERT_LT(log_facility_unshifted_from_string("bogus"), 0);

        /* Numeric fallback */
        ASSERT_EQ(log_facility_unshifted_from_string("0"), rs_log_facility_unshifted_from_string("0"));
        ASSERT_EQ(log_facility_unshifted_from_string("23"), rs_log_facility_unshifted_from_string("23"));
        ASSERT_EQ(log_facility_unshifted_from_string("127"), rs_log_facility_unshifted_from_string("127"));
        ASSERT_EQ(log_facility_unshifted_from_string("128"), rs_log_facility_unshifted_from_string("128"));

        /* The fallback is safe_atou(), not decimal-only parsing. */
        ASSERT_EQ(log_facility_unshifted_from_string(" 15"), rs_log_facility_unshifted_from_string(" 15"));
        ASSERT_EQ(log_facility_unshifted_from_string("+15"), rs_log_facility_unshifted_from_string("+15"));
        ASSERT_EQ(log_facility_unshifted_from_string("0xf"), rs_log_facility_unshifted_from_string("0xf"));
        ASSERT_EQ(log_facility_unshifted_from_string("0b1111"), rs_log_facility_unshifted_from_string("0b1111"));
        ASSERT_EQ(log_facility_unshifted_from_string("0o17"), rs_log_facility_unshifted_from_string("0o17"));
}

/* ── log_facility_unshifted_to_string ─────────────────────────────────── */

TEST(log_facility_to_string_c_vs_rs) {
        _cleanup_free_ char *c_str = NULL;
        _cleanup_free_ char *rs_str = NULL;

        /* Known facility */
        assert_se(log_facility_unshifted_to_string_alloc(0, &c_str) >= 0);
        assert_se(rs_log_facility_unshifted_to_string_alloc(0, &rs_str) >= 0);
        ASSERT_STREQ(c_str, rs_str);

        c_str = mfree(c_str);
        rs_str = mfree(rs_str);

        assert_se(log_facility_unshifted_to_string_alloc(16, &c_str) >= 0);
        assert_se(rs_log_facility_unshifted_to_string_alloc(16, &rs_str) >= 0);
        ASSERT_STREQ(c_str, rs_str);

        c_str = mfree(c_str);
        rs_str = mfree(rs_str);

        /* Out-of-range */
        int c_ret = log_facility_unshifted_to_string_alloc(128, &c_str);
        int rs_ret = rs_log_facility_unshifted_to_string_alloc(128, &rs_str);
        ASSERT_EQ(c_ret, rs_ret);
        ASSERT_LT(c_ret, 0);
}

/* ── log_level_is_valid ──────────────────────────────────────────────── */

TEST(log_level_is_valid_c_vs_rs) {
        for (int i = -1; i <= 10; i++)
                ASSERT_EQ(log_level_is_valid(i), rs_log_level_is_valid(i));
}

/* ── log_level_from_string ───────────────────────────────────────────── */

TEST(log_level_from_string_c_vs_rs) {
        const char *names[] = { "emerg", "alert", "crit", "err", "warning", "notice", "info", "debug", NULL };

        for (const char **p = names; *p; p++) {
                int c_val = log_level_from_string(*p);
                int rs_val = rs_log_level_from_string(*p);
                ASSERT_EQ(c_val, rs_val);
                assert_se(c_val >= 0);
        }

        /* Invalid */
        ASSERT_EQ(log_level_from_string("bogus"), rs_log_level_from_string("bogus"));
        ASSERT_LT(log_level_from_string("bogus"), 0);

        /* Numeric fallback */
        ASSERT_EQ(log_level_from_string("0"), rs_log_level_from_string("0"));
        ASSERT_EQ(log_level_from_string("7"), rs_log_level_from_string("7"));
        ASSERT_EQ(log_level_from_string("8"), rs_log_level_from_string("8"));
        ASSERT_EQ(log_level_from_string("0x7"), rs_log_level_from_string("0x7"));
        ASSERT_EQ(log_level_from_string("0b111"), rs_log_level_from_string("0b111"));
        ASSERT_EQ(log_level_from_string("0o7"), rs_log_level_from_string("0o7"));
}

/* ── log_level_to_string ──────────────────────────────────────────────── */

TEST(log_level_to_string_c_vs_rs) {
        _cleanup_free_ char *c_str = NULL;
        _cleanup_free_ char *rs_str = NULL;

        assert_se(log_level_to_string_alloc(0, &c_str) >= 0);
        assert_se(rs_log_level_to_string_alloc(0, &rs_str) >= 0);
        ASSERT_STREQ(c_str, rs_str);

        c_str = mfree(c_str);
        rs_str = mfree(rs_str);

        assert_se(log_level_to_string_alloc(7, &c_str) >= 0);
        assert_se(rs_log_level_to_string_alloc(7, &rs_str) >= 0);
        ASSERT_STREQ(c_str, rs_str);

        c_str = mfree(c_str);
        rs_str = mfree(rs_str);

        /* Out-of-range */
        int c_ret = log_level_to_string_alloc(8, &c_str);
        int rs_ret = rs_log_level_to_string_alloc(8, &rs_str);
        ASSERT_EQ(c_ret, rs_ret);
        ASSERT_LT(c_ret, 0);
}

/* ── syslog_parse_priority ───────────────────────────────────────────── */

TEST(syslog_parse_priority_c_vs_rs) {
        const char *input1 = "<3>hello";
        const char *input2 = "<13>warning with facility";
        const char *input3 = "<134>kern.alert";
        const char *input4 = "no priority";
        const char *input5 = "<>invalid";
        const char *input6 = "<ab>invalid";

        /* Without facility */
        {
                const char *c_p = input1;
                const char *rs_p = input1;
                int c_pri = 0, rs_pri = 0;
                int c_ret = syslog_parse_priority(&c_p, &c_pri, false);
                int rs_ret = rs_syslog_parse_priority(&rs_p, &rs_pri, false);
                ASSERT_EQ(c_ret, rs_ret);
                ASSERT_EQ(c_pri, rs_pri);
                ASSERT_EQ(c_ret, 1);
        }

        /* With facility */
        {
                const char *c_p = input1;
                const char *rs_p = input1;
                int c_pri = 0, rs_pri = 0;
                int c_ret = syslog_parse_priority(&c_p, &c_pri, true);
                int rs_ret = rs_syslog_parse_priority(&rs_p, &rs_pri, true);
                ASSERT_EQ(c_ret, rs_ret);
                ASSERT_EQ(c_pri, rs_pri);
        }

        /* 2-digit with facility */
        {
                const char *c_p = input2;
                const char *rs_p = input2;
                int c_pri = 0, rs_pri = 0;
                int c_ret = syslog_parse_priority(&c_p, &c_pri, true);
                int rs_ret = rs_syslog_parse_priority(&rs_p, &rs_pri, true);
                ASSERT_EQ(c_ret, rs_ret);
                ASSERT_EQ(c_pri, rs_pri);
        }

        /* 3-digit with facility */
        {
                const char *c_p = input3;
                const char *rs_p = input3;
                int c_pri = 0, rs_pri = 0;
                int c_ret = syslog_parse_priority(&c_p, &c_pri, true);
                int rs_ret = rs_syslog_parse_priority(&rs_p, &rs_pri, true);
                ASSERT_EQ(c_ret, rs_ret);
                ASSERT_EQ(c_pri, rs_pri);
        }

        /* No priority prefix */
        {
                const char *c_p = input4;
                const char *rs_p = input4;
                int c_pri = 0, rs_pri = 0;
                int c_ret = syslog_parse_priority(&c_p, &c_pri, false);
                int rs_ret = rs_syslog_parse_priority(&rs_p, &rs_pri, false);
                ASSERT_EQ(c_ret, rs_ret);
                ASSERT_EQ(c_ret, 0);
        }

        /* Invalid: empty <> */
        {
                const char *c_p = input5;
                const char *rs_p = input5;
                int c_pri = 0, rs_pri = 0;
                int c_ret = syslog_parse_priority(&c_p, &c_pri, true);
                int rs_ret = rs_syslog_parse_priority(&rs_p, &rs_pri, true);
                ASSERT_EQ(c_ret, rs_ret);
        }

        /* Invalid: non-numeric */
        {
                const char *c_p = input6;
                const char *rs_p = input6;
                int c_pri = 0, rs_pri = 0;
                int c_ret = syslog_parse_priority(&c_p, &c_pri, true);
                int rs_ret = rs_syslog_parse_priority(&rs_p, &rs_pri, true);
                ASSERT_EQ(c_ret, rs_ret);
        }

        /* Without facility: level > 7 should fail */
        {
                const char *c_p = "<8>too high";
                const char *rs_p = "<8>too high";
                int c_pri = 0, rs_pri = 0;
                int c_ret = syslog_parse_priority(&c_p, &c_pri, false);
                int rs_ret = rs_syslog_parse_priority(&rs_p, &rs_pri, false);
                ASSERT_EQ(c_ret, rs_ret);
                ASSERT_EQ(c_ret, 0);
        }
}

DEFINE_TEST_MAIN(LOG_INFO);
