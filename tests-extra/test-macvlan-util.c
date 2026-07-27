/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "macvlan-util.h"
#include "tests.h"

TEST(macvlan_mode) {
        ASSERT_STREQ(macvlan_mode_to_string(NETDEV_MACVLAN_MODE_PRIVATE), "private");
        ASSERT_STREQ(macvlan_mode_to_string(NETDEV_MACVLAN_MODE_VEPA), "vepa");
        ASSERT_STREQ(macvlan_mode_to_string(NETDEV_MACVLAN_MODE_BRIDGE), "bridge");
        ASSERT_STREQ(macvlan_mode_to_string(NETDEV_MACVLAN_MODE_PASSTHRU), "passthru");
        ASSERT_STREQ(macvlan_mode_to_string(NETDEV_MACVLAN_MODE_SOURCE), "source");
        ASSERT_EQ(macvlan_mode_from_string("private"), NETDEV_MACVLAN_MODE_PRIVATE);
        ASSERT_EQ(macvlan_mode_from_string("bridge"), NETDEV_MACVLAN_MODE_BRIDGE);
        ASSERT_EQ(macvlan_mode_from_string("passthru"), NETDEV_MACVLAN_MODE_PASSTHRU);
        ASSERT_EQ(macvlan_mode_from_string("invalid"), _NETDEV_MACVLAN_MODE_INVALID);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
