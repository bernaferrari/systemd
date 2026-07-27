/* SPDX-License-Identifier: LGPL-2.1-or-later */


#include "log.h"
#include "tests.h"

TEST(log_target_to_string) {
        ASSERT_STREQ(log_target_to_string(LOG_TARGET_CONSOLE), "console");
        ASSERT_STREQ(log_target_to_string(LOG_TARGET_KMSG), "kmsg");
        ASSERT_STREQ(log_target_to_string(LOG_TARGET_JOURNAL), "journal");
        ASSERT_STREQ(log_target_to_string(LOG_TARGET_SYSLOG), "syslog");
        ASSERT_STREQ(log_target_to_string(LOG_TARGET_CONSOLE_PREFIXED), "console-prefixed");
        ASSERT_STREQ(log_target_to_string(LOG_TARGET_JOURNAL_OR_KMSG), "journal-or-kmsg");
        ASSERT_STREQ(log_target_to_string(LOG_TARGET_SYSLOG_OR_KMSG), "syslog-or-kmsg");
        ASSERT_STREQ(log_target_to_string(LOG_TARGET_AUTO), "auto");
        ASSERT_STREQ(log_target_to_string(LOG_TARGET_NULL), "null");
}

TEST(log_target_from_string) {
        ASSERT_EQ(log_target_from_string("console"), LOG_TARGET_CONSOLE);
        ASSERT_EQ(log_target_from_string("kmsg"), LOG_TARGET_KMSG);
        ASSERT_EQ(log_target_from_string("journal"), LOG_TARGET_JOURNAL);
        ASSERT_EQ(log_target_from_string("syslog"), LOG_TARGET_SYSLOG);
        ASSERT_EQ(log_target_from_string("console-prefixed"), LOG_TARGET_CONSOLE_PREFIXED);
        ASSERT_EQ(log_target_from_string("journal-or-kmsg"), LOG_TARGET_JOURNAL_OR_KMSG);
        ASSERT_EQ(log_target_from_string("syslog-or-kmsg"), LOG_TARGET_SYSLOG_OR_KMSG);
        ASSERT_EQ(log_target_from_string("auto"), LOG_TARGET_AUTO);
        ASSERT_EQ(log_target_from_string("null"), LOG_TARGET_NULL);
        ASSERT_EQ(log_target_from_string("invalid"), _LOG_TARGET_INVALID);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
