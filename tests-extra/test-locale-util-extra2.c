/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "locale-util.h"
#include "tests.h"

TEST(locale_variable_to_from_string) {
        assert_se(streq(locale_variable_to_string(VARIABLE_LANG), "LANG"));
        assert_se(streq(locale_variable_to_string(VARIABLE_LANGUAGE), "LANGUAGE"));
        assert_se(streq(locale_variable_to_string(VARIABLE_LC_CTYPE), "LC_CTYPE"));
        assert_se(streq(locale_variable_to_string(VARIABLE_LC_NUMERIC), "LC_NUMERIC"));
        assert_se(streq(locale_variable_to_string(VARIABLE_LC_TIME), "LC_TIME"));
        assert_se(streq(locale_variable_to_string(VARIABLE_LC_COLLATE), "LC_COLLATE"));
        assert_se(streq(locale_variable_to_string(VARIABLE_LC_MONETARY), "LC_MONETARY"));
        assert_se(streq(locale_variable_to_string(VARIABLE_LC_MESSAGES), "LC_MESSAGES"));
        assert_se(streq(locale_variable_to_string(VARIABLE_LC_PAPER), "LC_PAPER"));
        assert_se(streq(locale_variable_to_string(VARIABLE_LC_NAME), "LC_NAME"));
        assert_se(streq(locale_variable_to_string(VARIABLE_LC_ADDRESS), "LC_ADDRESS"));
        assert_se(streq(locale_variable_to_string(VARIABLE_LC_TELEPHONE), "LC_TELEPHONE"));
        assert_se(streq(locale_variable_to_string(VARIABLE_LC_MEASUREMENT), "LC_MEASUREMENT"));
        assert_se(streq(locale_variable_to_string(VARIABLE_LC_IDENTIFICATION), "LC_IDENTIFICATION"));

        assert_se(locale_variable_from_string("LANG") == VARIABLE_LANG);
        assert_se(locale_variable_from_string("LANGUAGE") == VARIABLE_LANGUAGE);
        assert_se(locale_variable_from_string("LC_CTYPE") == VARIABLE_LC_CTYPE);
        assert_se(locale_variable_from_string("LC_MESSAGES") == VARIABLE_LC_MESSAGES);
        assert_se(locale_variable_from_string("LC_IDENTIFICATION") == VARIABLE_LC_IDENTIFICATION);
        assert_se(locale_variable_from_string("invalid") < 0);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
