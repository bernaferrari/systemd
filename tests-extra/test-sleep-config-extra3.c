/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sleep-config.h"
#include "string-util.h"
#include "tests.h"

TEST(sleep_operation_to_from_string) {
        /* to_string */
        assert_se(streq(sleep_operation_to_string(SLEEP_SUSPEND), "suspend"));
        assert_se(streq(sleep_operation_to_string(SLEEP_HIBERNATE), "hibernate"));
        assert_se(streq(sleep_operation_to_string(SLEEP_HYBRID_SLEEP), "hybrid-sleep"));
        assert_se(streq(sleep_operation_to_string(SLEEP_SUSPEND_THEN_HIBERNATE), "suspend-then-hibernate"));

        /* from_string */
        assert_se(sleep_operation_from_string("suspend") == SLEEP_SUSPEND);
        assert_se(sleep_operation_from_string("hibernate") == SLEEP_HIBERNATE);
        assert_se(sleep_operation_from_string("hybrid-sleep") == SLEEP_HYBRID_SLEEP);
        assert_se(sleep_operation_from_string("suspend-then-hibernate") == SLEEP_SUSPEND_THEN_HIBERNATE);

        /* Invalid */
        assert_se(sleep_operation_from_string("invalid") < 0);
        assert_se(sleep_operation_from_string("") < 0);
}

TEST(sleep_operation_is_hibernation) {
        assert_se(!SLEEP_OPERATION_IS_HIBERNATION(SLEEP_SUSPEND));
        assert_se(SLEEP_OPERATION_IS_HIBERNATION(SLEEP_HIBERNATE));
        assert_se(SLEEP_OPERATION_IS_HIBERNATION(SLEEP_HYBRID_SLEEP));
        assert_se(!SLEEP_OPERATION_IS_HIBERNATION(SLEEP_SUSPEND_THEN_HIBERNATE));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
