/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "log.h"
#include "tests.h"

TEST(log_target_to_from_string) {
        assert_se(streq(log_target_to_string(LOG_TARGET_CONSOLE), "console"));
        assert_se(streq(log_target_to_string(LOG_TARGET_CONSOLE_PREFIXED), "console-prefixed"));
        assert_se(streq(log_target_to_string(LOG_TARGET_KMSG), "kmsg"));
        assert_se(streq(log_target_to_string(LOG_TARGET_JOURNAL), "journal"));
        assert_se(streq(log_target_to_string(LOG_TARGET_JOURNAL_OR_KMSG), "journal-or-kmsg"));
        assert_se(streq(log_target_to_string(LOG_TARGET_SYSLOG), "syslog"));
        assert_se(streq(log_target_to_string(LOG_TARGET_SYSLOG_OR_KMSG), "syslog-or-kmsg"));
        assert_se(streq(log_target_to_string(LOG_TARGET_AUTO), "auto"));
        assert_se(streq(log_target_to_string(LOG_TARGET_NULL), "null"));

        assert_se(log_target_from_string("console") == LOG_TARGET_CONSOLE);
        assert_se(log_target_from_string("console-prefixed") == LOG_TARGET_CONSOLE_PREFIXED);
        assert_se(log_target_from_string("kmsg") == LOG_TARGET_KMSG);
        assert_se(log_target_from_string("journal") == LOG_TARGET_JOURNAL);
        assert_se(log_target_from_string("journal-or-kmsg") == LOG_TARGET_JOURNAL_OR_KMSG);
        assert_se(log_target_from_string("syslog") == LOG_TARGET_SYSLOG);
        assert_se(log_target_from_string("syslog-or-kmsg") == LOG_TARGET_SYSLOG_OR_KMSG);
        assert_se(log_target_from_string("auto") == LOG_TARGET_AUTO);
        assert_se(log_target_from_string("null") == LOG_TARGET_NULL);
        assert_se(log_target_from_string("invalid") < 0);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
