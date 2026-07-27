/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "ipvlan-util.h"
#include "tests.h"

TEST(ipvlan_mode) {
        ASSERT_STREQ(ipvlan_mode_to_string(NETDEV_IPVLAN_MODE_L2), "L2");
        ASSERT_STREQ(ipvlan_mode_to_string(NETDEV_IPVLAN_MODE_L3), "L3");
        ASSERT_STREQ(ipvlan_mode_to_string(NETDEV_IPVLAN_MODE_L3S), "L3S");
        ASSERT_EQ(ipvlan_mode_from_string("L2"), NETDEV_IPVLAN_MODE_L2);
        ASSERT_EQ(ipvlan_mode_from_string("L3"), NETDEV_IPVLAN_MODE_L3);
        ASSERT_EQ(ipvlan_mode_from_string("invalid"), _NETDEV_IPVLAN_MODE_INVALID);
}

TEST(ipvlan_flags) {
        ASSERT_STREQ(ipvlan_flags_to_string(NETDEV_IPVLAN_FLAGS_BRIGDE), "bridge");
        ASSERT_STREQ(ipvlan_flags_to_string(NETDEV_IPVLAN_FLAGS_PRIVATE), "private");
        ASSERT_STREQ(ipvlan_flags_to_string(NETDEV_IPVLAN_FLAGS_VEPA), "vepa");
        ASSERT_EQ(ipvlan_flags_from_string("bridge"), NETDEV_IPVLAN_FLAGS_BRIGDE);
        ASSERT_EQ(ipvlan_flags_from_string("private"), NETDEV_IPVLAN_FLAGS_PRIVATE);
        ASSERT_EQ(ipvlan_flags_from_string("invalid"), _NETDEV_IPVLAN_FLAGS_INVALID);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
