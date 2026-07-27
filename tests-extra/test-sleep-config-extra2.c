/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sleep-config.h"
#include "tests.h"

TEST(sleep_operation_to_from_string) {
        ASSERT_STREQ(sleep_operation_to_string(SLEEP_SUSPEND), "suspend");
        ASSERT_STREQ(sleep_operation_to_string(SLEEP_HIBERNATE), "hibernate");
        ASSERT_STREQ(sleep_operation_to_string(SLEEP_HYBRID_SLEEP), "hybrid-sleep");

        ASSERT_EQ(sleep_operation_from_string("suspend"), SLEEP_SUSPEND);
        ASSERT_EQ(sleep_operation_from_string("hibernate"), SLEEP_HIBERNATE);
        ASSERT_EQ(sleep_operation_from_string("hybrid-sleep"), SLEEP_HYBRID_SLEEP);

        /* Invalid */
        ASSERT_EQ(sleep_operation_from_string("invalid"), _SLEEP_OPERATION_INVALID);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
