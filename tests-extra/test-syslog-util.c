/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdlib.h>
#include <syslog.h>

#include "syslog-util.h"
#include "tests.h"

TEST(syslog_parse_priority_basic) {
        const char *p;
        int priority = 0;

        /* Single digit level, must be <= 7 */
        p = "<3>message";
        ASSERT_EQ(syslog_parse_priority(&p, &priority, false), 1);
        ASSERT_STREQ(p, "message");
        ASSERT_EQ(priority & LOG_PRIMASK, 3);

        /* Level > 7 should fail when with_facility=false */
        p = "<8>message";
        ASSERT_EQ(syslog_parse_priority(&p, &priority, false), 0);

        /* Multi-digit codes fail when with_facility=false */
        p = "<13>message";
        ASSERT_EQ(syslog_parse_priority(&p, &priority, false), 0);
        ASSERT_STREQ(p, "<13>message");

        /* But work when with_facility=true */
        p = "<13>message";
        priority = 0;
        ASSERT_EQ(syslog_parse_priority(&p, &priority, true), 1);
        ASSERT_STREQ(p, "message");
        ASSERT_EQ(priority, 13);

        /* Three-digit with facility, with_facility=true */
        p = "<134>message";
        ASSERT_EQ(syslog_parse_priority(&p, &priority, true), 1);
        ASSERT_STREQ(p, "message");
        ASSERT_EQ(priority, 134);

        /* Five-digit is not supported */
        p = "<1234>message";
        ASSERT_EQ(syslog_parse_priority(&p, &priority, true), 0);
        ASSERT_STREQ(p, "<1234>message");
}

TEST(syslog_parse_priority_no_priority) {
        const char *p = "no priority here";
        int priority = 0;

        ASSERT_EQ(syslog_parse_priority(&p, &priority, false), 0);
        ASSERT_STREQ(p, "no priority here");
}

TEST(syslog_parse_priority_unclosed) {
        const char *p = "<3 no close";
        int priority = 0;

        ASSERT_EQ(syslog_parse_priority(&p, &priority, false), 0);
}

TEST(syslog_parse_priority_too_long) {
        const char *p = "<12345>message";
        int priority = 0;

        ASSERT_EQ(syslog_parse_priority(&p, &priority, false), 0);
}

TEST(syslog_parse_priority_level_preserves_facility) {
        const char *p;
        int priority;

        /* Set initial facility to LOCAL0 (value 128 = 16 << 3) */
        p = "<3>msg";
        priority = LOG_LOCAL0;
        ASSERT_EQ(syslog_parse_priority(&p, &priority, false), 1);
        /* Facility should be preserved, level set to 3 */
        ASSERT_EQ(priority & LOG_FACMASK, LOG_LOCAL0);
        ASSERT_EQ(priority & LOG_PRIMASK, 3);
}

TEST(log_facility_unshifted) {
        _cleanup_free_ char *s = NULL;

        ASSERT_OK(log_facility_unshifted_to_string_alloc(LOG_FAC(LOG_KERN), &s));
        ASSERT_STREQ(s, "kern");

        s = mfree(s);
        ASSERT_OK(log_facility_unshifted_to_string_alloc(LOG_FAC(LOG_USER), &s));
        ASSERT_STREQ(s, "user");

        s = mfree(s);
        ASSERT_OK(log_facility_unshifted_to_string_alloc(LOG_FAC(LOG_DAEMON), &s));
        ASSERT_STREQ(s, "daemon");

        s = mfree(s);
        ASSERT_OK(log_facility_unshifted_to_string_alloc(LOG_FAC(LOG_LOCAL0), &s));
        ASSERT_STREQ(s, "local0");

        s = mfree(s);
        ASSERT_OK(log_facility_unshifted_to_string_alloc(LOG_FAC(LOG_LOCAL7), &s));
        ASSERT_STREQ(s, "local7");

        /* From string */
        ASSERT_EQ(log_facility_unshifted_from_string("kern"), LOG_FAC(LOG_KERN));
        ASSERT_EQ(log_facility_unshifted_from_string("user"), LOG_FAC(LOG_USER));
        ASSERT_EQ(log_facility_unshifted_from_string("daemon"), LOG_FAC(LOG_DAEMON));
        ASSERT_EQ(log_facility_unshifted_from_string("invalid"), -EINVAL);

        /* Numeric fallback */
        ASSERT_EQ(log_facility_unshifted_from_string("0"), 0);
}

TEST(log_facility_unshifted_is_valid) {
        ASSERT_TRUE(log_facility_unshifted_is_valid(0));
        ASSERT_TRUE(log_facility_unshifted_is_valid(LOG_FAC(LOG_KERN)));
        ASSERT_TRUE(log_facility_unshifted_is_valid(LOG_FAC(LOG_LOCAL7)));
        ASSERT_TRUE(log_facility_unshifted_is_valid(LOG_FAC(~0)));
        ASSERT_FALSE(log_facility_unshifted_is_valid(-1));
        ASSERT_FALSE(log_facility_unshifted_is_valid(LOG_FAC(~0) + 1));
}

TEST(log_level) {
        _cleanup_free_ char *s = NULL;

        ASSERT_OK(log_level_to_string_alloc(LOG_EMERG, &s));
        ASSERT_STREQ(s, "emerg");

        s = mfree(s);
        ASSERT_OK(log_level_to_string_alloc(LOG_ALERT, &s));
        ASSERT_STREQ(s, "alert");

        s = mfree(s);
        ASSERT_OK(log_level_to_string_alloc(LOG_CRIT, &s));
        ASSERT_STREQ(s, "crit");

        s = mfree(s);
        ASSERT_OK(log_level_to_string_alloc(LOG_ERR, &s));
        ASSERT_STREQ(s, "err");

        s = mfree(s);
        ASSERT_OK(log_level_to_string_alloc(LOG_WARNING, &s));
        ASSERT_STREQ(s, "warning");

        s = mfree(s);
        ASSERT_OK(log_level_to_string_alloc(LOG_NOTICE, &s));
        ASSERT_STREQ(s, "notice");

        s = mfree(s);
        ASSERT_OK(log_level_to_string_alloc(LOG_INFO, &s));
        ASSERT_STREQ(s, "info");

        s = mfree(s);
        ASSERT_OK(log_level_to_string_alloc(LOG_DEBUG, &s));
        ASSERT_STREQ(s, "debug");

        /* From string */
        ASSERT_EQ(log_level_from_string("emerg"), LOG_EMERG);
        ASSERT_EQ(log_level_from_string("debug"), LOG_DEBUG);
        ASSERT_EQ(log_level_from_string("invalid"), -EINVAL);

        /* Numeric fallback */
        ASSERT_EQ(log_level_from_string("3"), 3);
}

TEST(log_level_is_valid) {
        ASSERT_TRUE(log_level_is_valid(LOG_EMERG));
        ASSERT_TRUE(log_level_is_valid(LOG_DEBUG));
        ASSERT_TRUE(log_level_is_valid(0));
        ASSERT_FALSE(log_level_is_valid(-1));
        ASSERT_FALSE(log_level_is_valid(LOG_DEBUG + 1));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
