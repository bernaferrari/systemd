/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "netif-naming-scheme.h"
#include "tests.h"

/* alternative_names_policy uses the same NamePolicy type as name_policy
 * but with a different subset of values (database, onboard, slot, path, mac). */

TEST(alternative_names_policy_from_string) {
        ASSERT_EQ(alternative_names_policy_from_string("database"), NAMEPOLICY_DATABASE);
        ASSERT_EQ(alternative_names_policy_from_string("onboard"), NAMEPOLICY_ONBOARD);
        ASSERT_EQ(alternative_names_policy_from_string("slot"), NAMEPOLICY_SLOT);
        ASSERT_EQ(alternative_names_policy_from_string("path"), NAMEPOLICY_PATH);
        ASSERT_EQ(alternative_names_policy_from_string("mac"), NAMEPOLICY_MAC);
        ASSERT_EQ(alternative_names_policy_from_string("kernel"), _NAMEPOLICY_INVALID);
        ASSERT_EQ(alternative_names_policy_from_string("invalid"), _NAMEPOLICY_INVALID);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
