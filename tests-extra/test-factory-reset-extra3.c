/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "factory-reset.h"
#include "string-util.h"
#include "tests.h"

TEST(factory_reset_mode_to_from_string) {
        assert_se(streq(factory_reset_mode_to_string(FACTORY_RESET_UNSUPPORTED), "unsupported"));
        assert_se(streq(factory_reset_mode_to_string(FACTORY_RESET_UNSPECIFIED), "unspecified"));
        assert_se(streq(factory_reset_mode_to_string(FACTORY_RESET_OFF), "off"));
        assert_se(streq(factory_reset_mode_to_string(FACTORY_RESET_ON), "on"));
        assert_se(streq(factory_reset_mode_to_string(FACTORY_RESET_COMPLETE), "complete"));
        assert_se(streq(factory_reset_mode_to_string(FACTORY_RESET_PENDING), "pending"));

        assert_se(factory_reset_mode_from_string("unsupported") == FACTORY_RESET_UNSUPPORTED);
        assert_se(factory_reset_mode_from_string("off") == FACTORY_RESET_OFF);
        assert_se(factory_reset_mode_from_string("on") == FACTORY_RESET_ON);
        assert_se(factory_reset_mode_from_string("complete") == FACTORY_RESET_COMPLETE);
        assert_se(factory_reset_mode_from_string("pending") == FACTORY_RESET_PENDING);
        assert_se(factory_reset_mode_from_string("invalid") < 0);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
