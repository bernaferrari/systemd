/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "volatile-util.h"
#include "tests.h"

TEST(volatile_mode_to_string) {
        ASSERT_STREQ(volatile_mode_to_string(VOLATILE_NO), "no");
        ASSERT_STREQ(volatile_mode_to_string(VOLATILE_YES), "yes");
        ASSERT_STREQ(volatile_mode_to_string(VOLATILE_STATE), "state");
        ASSERT_STREQ(volatile_mode_to_string(VOLATILE_OVERLAY), "overlay");
}

TEST(volatile_mode_from_string) {
        ASSERT_EQ(volatile_mode_from_string("no"), VOLATILE_NO);
        ASSERT_EQ(volatile_mode_from_string("yes"), VOLATILE_YES);
        ASSERT_EQ(volatile_mode_from_string("state"), VOLATILE_STATE);
        ASSERT_EQ(volatile_mode_from_string("overlay"), VOLATILE_OVERLAY);
        ASSERT_EQ(volatile_mode_from_string("invalid"), _VOLATILE_MODE_INVALID);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
