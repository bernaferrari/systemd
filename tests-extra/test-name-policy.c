/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "netif-naming-scheme.h"
#include "tests.h"

TEST(name_policy_to_string) {
        ASSERT_STREQ(name_policy_to_string(NAMEPOLICY_KERNEL), "kernel");
        ASSERT_STREQ(name_policy_to_string(NAMEPOLICY_KEEP), "keep");
        ASSERT_STREQ(name_policy_to_string(NAMEPOLICY_DATABASE), "database");
        ASSERT_STREQ(name_policy_to_string(NAMEPOLICY_ONBOARD), "onboard");
        ASSERT_STREQ(name_policy_to_string(NAMEPOLICY_SLOT), "slot");
        ASSERT_STREQ(name_policy_to_string(NAMEPOLICY_PATH), "path");
        ASSERT_STREQ(name_policy_to_string(NAMEPOLICY_MAC), "mac");
}

TEST(name_policy_from_string) {
        ASSERT_EQ(name_policy_from_string("kernel"), NAMEPOLICY_KERNEL);
        ASSERT_EQ(name_policy_from_string("keep"), NAMEPOLICY_KEEP);
        ASSERT_EQ(name_policy_from_string("database"), NAMEPOLICY_DATABASE);
        ASSERT_EQ(name_policy_from_string("onboard"), NAMEPOLICY_ONBOARD);
        ASSERT_EQ(name_policy_from_string("slot"), NAMEPOLICY_SLOT);
        ASSERT_EQ(name_policy_from_string("path"), NAMEPOLICY_PATH);
        ASSERT_EQ(name_policy_from_string("mac"), NAMEPOLICY_MAC);
        ASSERT_EQ(name_policy_from_string("invalid"), _NAMEPOLICY_INVALID);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
