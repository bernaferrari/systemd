/* SPDX-License-Identifier: LGPL-2.1-or-later */


#include "locale-util.h"
#include "tests.h"

TEST(locale_variable_to_string) {
        ASSERT_STREQ(locale_variable_to_string(VARIABLE_LANG), "LANG");
        ASSERT_STREQ(locale_variable_to_string(VARIABLE_LANGUAGE), "LANGUAGE");
        ASSERT_STREQ(locale_variable_to_string(VARIABLE_LC_CTYPE), "LC_CTYPE");
        ASSERT_STREQ(locale_variable_to_string(VARIABLE_LC_NUMERIC), "LC_NUMERIC");
        ASSERT_STREQ(locale_variable_to_string(VARIABLE_LC_TIME), "LC_TIME");
        ASSERT_STREQ(locale_variable_to_string(VARIABLE_LC_MESSAGES), "LC_MESSAGES");
        ASSERT_STREQ(locale_variable_to_string(VARIABLE_LC_IDENTIFICATION), "LC_IDENTIFICATION");
}

TEST(locale_variable_from_string) {
        ASSERT_EQ(locale_variable_from_string("LANG"), VARIABLE_LANG);
        ASSERT_EQ(locale_variable_from_string("LANGUAGE"), VARIABLE_LANGUAGE);
        ASSERT_EQ(locale_variable_from_string("LC_CTYPE"), VARIABLE_LC_CTYPE);
        ASSERT_EQ(locale_variable_from_string("LC_NUMERIC"), VARIABLE_LC_NUMERIC);
        ASSERT_EQ(locale_variable_from_string("LC_TIME"), VARIABLE_LC_TIME);
        ASSERT_EQ(locale_variable_from_string("LC_COLLATE"), VARIABLE_LC_COLLATE);
        ASSERT_EQ(locale_variable_from_string("LC_MONETARY"), VARIABLE_LC_MONETARY);
        ASSERT_EQ(locale_variable_from_string("LC_MESSAGES"), VARIABLE_LC_MESSAGES);
        ASSERT_EQ(locale_variable_from_string("LC_PAPER"), VARIABLE_LC_PAPER);
        ASSERT_EQ(locale_variable_from_string("LC_NAME"), VARIABLE_LC_NAME);
        ASSERT_EQ(locale_variable_from_string("LC_ADDRESS"), VARIABLE_LC_ADDRESS);
        ASSERT_EQ(locale_variable_from_string("LC_TELEPHONE"), VARIABLE_LC_TELEPHONE);
        ASSERT_EQ(locale_variable_from_string("LC_MEASUREMENT"), VARIABLE_LC_MEASUREMENT);
        ASSERT_EQ(locale_variable_from_string("LC_IDENTIFICATION"), VARIABLE_LC_IDENTIFICATION);
        ASSERT_EQ(locale_variable_from_string("invalid"), _VARIABLE_LC_INVALID);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
