/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "condition.h"
#include "string-util.h"
#include "tests.h"

#include <stdio.h>

TEST(condition_type_to_from_string) {
        /* to_string returns "Condition..." prefix */
        assert_se(streq(condition_type_to_string(CONDITION_ARCHITECTURE), "ConditionArchitecture"));
        assert_se(streq(condition_type_to_string(CONDITION_PATH_EXISTS), "ConditionPathExists"));
        assert_se(streq(condition_type_to_string(CONDITION_KERNEL_COMMAND_LINE), "ConditionKernelCommandLine"));
        assert_se(streq(condition_type_to_string(CONDITION_HOST), "ConditionHost"));
        assert_se(streq(condition_type_to_string(CONDITION_USER), "ConditionUser"));

        /* from_string */
        assert_se(condition_type_from_string("ConditionArchitecture") == CONDITION_ARCHITECTURE);
        assert_se(condition_type_from_string("ConditionPathExists") == CONDITION_PATH_EXISTS);
        assert_se(condition_type_from_string("ConditionKernelCommandLine") == CONDITION_KERNEL_COMMAND_LINE);
        assert_se(condition_type_from_string("invalid") < 0);
}

TEST(assert_type_to_from_string) {
        /* to_string returns "Assert..." prefix */
        assert_se(streq(assert_type_to_string(CONDITION_ARCHITECTURE), "AssertArchitecture"));
        assert_se(streq(assert_type_to_string(CONDITION_PATH_EXISTS), "AssertPathExists"));

        /* from_string */
        assert_se(assert_type_from_string("AssertArchitecture") == CONDITION_ARCHITECTURE);
        assert_se(assert_type_from_string("AssertPathExists") == CONDITION_PATH_EXISTS);
        assert_se(assert_type_from_string("invalid") < 0);
}
TEST(condition_result_to_from_string) {
        assert_se(streq(condition_result_to_string(CONDITION_UNTESTED), "untested"));
        assert_se(streq(condition_result_to_string(CONDITION_SUCCEEDED), "succeeded"));
        assert_se(streq(condition_result_to_string(CONDITION_FAILED), "failed"));
        assert_se(streq(condition_result_to_string(CONDITION_ERROR), "error"));

        assert_se(condition_result_from_string("untested") == CONDITION_UNTESTED);
        assert_se(condition_result_from_string("succeeded") == CONDITION_SUCCEEDED);
        assert_se(condition_result_from_string("failed") == CONDITION_FAILED);
        assert_se(condition_result_from_string("error") == CONDITION_ERROR);
        assert_se(condition_result_from_string("invalid") < 0);
}
DEFINE_TEST_MAIN(LOG_DEBUG);
