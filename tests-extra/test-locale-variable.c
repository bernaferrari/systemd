/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "locale-util.h"
#include "tests.h"

TEST(locale_variable) {
        ASSERT_STREQ(locale_variable_to_string(VARIABLE_LANG), "LANG");
        ASSERT_STREQ(locale_variable_to_string(VARIABLE_LANGUAGE), "LANGUAGE");
        ASSERT_STREQ(locale_variable_to_string(VARIABLE_LC_CTYPE), "LC_CTYPE");
        ASSERT_STREQ(locale_variable_to_string(VARIABLE_LC_NUMERIC), "LC_NUMERIC");
        ASSERT_STREQ(locale_variable_to_string(VARIABLE_LC_TIME), "LC_TIME");
        ASSERT_STREQ(locale_variable_to_string(VARIABLE_LC_COLLATE), "LC_COLLATE");
        ASSERT_STREQ(locale_variable_to_string(VARIABLE_LC_MONETARY), "LC_MONETARY");
        ASSERT_STREQ(locale_variable_to_string(VARIABLE_LC_MESSAGES), "LC_MESSAGES");
        ASSERT_EQ(locale_variable_from_string("LANG"), VARIABLE_LANG);
        ASSERT_EQ(locale_variable_from_string("LC_CTYPE"), VARIABLE_LC_CTYPE);
        ASSERT_EQ(locale_variable_from_string("invalid"), _VARIABLE_LC_INVALID);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
