/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "factory-reset.h"
#include "tests.h"

TEST(factory_reset_mode_to_from_string) {
        ASSERT_STREQ(factory_reset_mode_to_string(FACTORY_RESET_UNSUPPORTED), "unsupported");
        ASSERT_STREQ(factory_reset_mode_to_string(FACTORY_RESET_UNSPECIFIED), "unspecified");
        ASSERT_STREQ(factory_reset_mode_to_string(FACTORY_RESET_OFF), "off");
        ASSERT_STREQ(factory_reset_mode_to_string(FACTORY_RESET_ON), "on");
        ASSERT_STREQ(factory_reset_mode_to_string(FACTORY_RESET_COMPLETE), "complete");

        ASSERT_EQ(factory_reset_mode_from_string("unsupported"), FACTORY_RESET_UNSUPPORTED);
        ASSERT_EQ(factory_reset_mode_from_string("unspecified"), FACTORY_RESET_UNSPECIFIED);
        ASSERT_EQ(factory_reset_mode_from_string("off"), FACTORY_RESET_OFF);
        ASSERT_EQ(factory_reset_mode_from_string("on"), FACTORY_RESET_ON);
        ASSERT_EQ(factory_reset_mode_from_string("complete"), FACTORY_RESET_COMPLETE);

        /* Invalid */
        ASSERT_EQ(factory_reset_mode_from_string("invalid"), _FACTORY_RESET_MODE_INVALID);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
