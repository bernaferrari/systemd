/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "condition.h"
#include "tests.h"

TEST(condition_result_to_from_string) {
        ASSERT_STREQ(condition_result_to_string(CONDITION_UNTESTED), "untested");
        ASSERT_STREQ(condition_result_to_string(CONDITION_SUCCEEDED), "succeeded");
        ASSERT_STREQ(condition_result_to_string(CONDITION_FAILED), "failed");
        ASSERT_STREQ(condition_result_to_string(CONDITION_ERROR), "error");

        ASSERT_EQ(condition_result_from_string("untested"), CONDITION_UNTESTED);
        ASSERT_EQ(condition_result_from_string("succeeded"), CONDITION_SUCCEEDED);
        ASSERT_EQ(condition_result_from_string("failed"), CONDITION_FAILED);
        ASSERT_EQ(condition_result_from_string("error"), CONDITION_ERROR);

        /* Invalid */
        ASSERT_EQ(condition_result_from_string("invalid"), _CONDITION_RESULT_INVALID);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
