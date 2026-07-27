/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "syslog-util.h"
#include "string-util.h"
#include "tests.h"

TEST(log_facility_unshifted_from_string) {
        assert_se(log_facility_unshifted_from_string("kern") == (int) LOG_FAC(LOG_KERN));
        assert_se(log_facility_unshifted_from_string("user") == (int) LOG_FAC(LOG_USER));
        assert_se(log_facility_unshifted_from_string("daemon") == (int) LOG_FAC(LOG_DAEMON));
        assert_se(log_facility_unshifted_from_string("auth") == (int) LOG_FAC(LOG_AUTH));
        assert_se(log_facility_unshifted_from_string("syslog") == (int) LOG_FAC(LOG_SYSLOG));
        assert_se(log_facility_unshifted_from_string("cron") == (int) LOG_FAC(LOG_CRON));
        assert_se(log_facility_unshifted_from_string("local0") == (int) LOG_FAC(LOG_LOCAL0));
        assert_se(log_facility_unshifted_from_string("local7") == (int) LOG_FAC(LOG_LOCAL7));

        /* WITH_FALLBACK: numeric strings also accepted */
        assert_se(log_facility_unshifted_from_string("0") == 0);
        assert_se(log_facility_unshifted_from_string("1") == 1);
        assert_se(log_facility_unshifted_from_string("23") == 23);
}

TEST(log_facility_unshifted_to_string_alloc) {
        _cleanup_free_ char *s = NULL;

        assert_se(log_facility_unshifted_to_string_alloc(LOG_FAC(LOG_KERN), &s) == 0);
        assert_se(streq(s, "kern"));

        s = mfree(s);
        assert_se(log_facility_unshifted_to_string_alloc(LOG_FAC(LOG_USER), &s) == 0);
        assert_se(streq(s, "user"));

        s = mfree(s);
        assert_se(log_facility_unshifted_to_string_alloc(LOG_FAC(LOG_DAEMON), &s) == 0);
        assert_se(streq(s, "daemon"));

        s = mfree(s);
        assert_se(log_facility_unshifted_to_string_alloc(LOG_FAC(LOG_LOCAL7), &s) == 0);
        assert_se(streq(s, "local7"));

        /* Fallback: numeric value not in table */
        s = mfree(s);
        assert_se(log_facility_unshifted_to_string_alloc(15, &s) == 0);
        assert_se(streq(s, "15"));
}

TEST(log_level_from_string) {
        assert_se(log_level_from_string("emerg") == LOG_EMERG);
        assert_se(log_level_from_string("alert") == LOG_ALERT);
        assert_se(log_level_from_string("crit") == LOG_CRIT);
        assert_se(log_level_from_string("err") == LOG_ERR);
        assert_se(log_level_from_string("warning") == LOG_WARNING);
        assert_se(log_level_from_string("notice") == LOG_NOTICE);
        assert_se(log_level_from_string("info") == LOG_INFO);
        assert_se(log_level_from_string("debug") == LOG_DEBUG);

        /* WITH_FALLBACK: numeric strings */
        assert_se(log_level_from_string("0") == 0);
        assert_se(log_level_from_string("7") == 7);
}

TEST(log_level_to_string_alloc) {
        _cleanup_free_ char *s = NULL;

        assert_se(log_level_to_string_alloc(LOG_EMERG, &s) == 0);
        assert_se(streq(s, "emerg"));

        s = mfree(s);
        assert_se(log_level_to_string_alloc(LOG_ERR, &s) == 0);
        assert_se(streq(s, "err"));

        s = mfree(s);
        assert_se(log_level_to_string_alloc(LOG_INFO, &s) == 0);
        assert_se(streq(s, "info"));

        s = mfree(s);
        assert_se(log_level_to_string_alloc(LOG_DEBUG, &s) == 0);
        assert_se(streq(s, "debug"));
}

TEST(log_facility_unshifted_is_valid) {
        assert_se(log_facility_unshifted_is_valid(0));
        assert_se(log_facility_unshifted_is_valid(23));
        assert_se(log_facility_unshifted_is_valid(127));
        assert_se(!log_facility_unshifted_is_valid(-1));
        assert_se(!log_facility_unshifted_is_valid(128));
}

TEST(log_level_is_valid) {
        assert_se(log_level_is_valid(0));
        assert_se(log_level_is_valid(LOG_DEBUG));
        assert_se(!log_level_is_valid(-1));
        assert_se(!log_level_is_valid(LOG_DEBUG + 1));
}

TEST(syslog_parse_priority) {
        int priority = 0;
        const char *p;

        /* Single digit priority */
        p = "<5>test";
        priority = 0;
        assert_se(syslog_parse_priority(&p, &priority, false) == 1);
        assert_se(priority == 5);
        assert_se(streq(p, "test"));

        /* Two digit with facility */
        p = "<15>test";
        priority = 0;
        assert_se(syslog_parse_priority(&p, &priority, true) == 1);
        assert_se(priority == 15);
        assert_se(streq(p, "test"));

        /* Without facility, only 0-7 allowed */
        p = "<3>hello";
        priority = 0;
        assert_se(syslog_parse_priority(&p, &priority, false) == 1);
        assert_se(priority == 3);

        /* No angle bracket */
        p = "no bracket";
        assert_se(syslog_parse_priority(&p, &priority, false) == 0);

        /* No closing bracket */
        p = "<5 no close";
        assert_se(syslog_parse_priority(&p, &priority, false) == 0);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
