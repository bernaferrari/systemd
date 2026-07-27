/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "macvlan-util.h"
#include "tests.h"

TEST(macvlan_mode_to_from_string) {
        assert_se(streq(macvlan_mode_to_string(NETDEV_MACVLAN_MODE_PRIVATE), "private"));
        assert_se(streq(macvlan_mode_to_string(NETDEV_MACVLAN_MODE_VEPA), "vepa"));
        assert_se(streq(macvlan_mode_to_string(NETDEV_MACVLAN_MODE_BRIDGE), "bridge"));
        assert_se(streq(macvlan_mode_to_string(NETDEV_MACVLAN_MODE_PASSTHRU), "passthru"));
        assert_se(streq(macvlan_mode_to_string(NETDEV_MACVLAN_MODE_SOURCE), "source"));

        assert_se(macvlan_mode_from_string("private") == NETDEV_MACVLAN_MODE_PRIVATE);
        assert_se(macvlan_mode_from_string("vepa") == NETDEV_MACVLAN_MODE_VEPA);
        assert_se(macvlan_mode_from_string("bridge") == NETDEV_MACVLAN_MODE_BRIDGE);
        assert_se(macvlan_mode_from_string("passthru") == NETDEV_MACVLAN_MODE_PASSTHRU);
        assert_se(macvlan_mode_from_string("source") == NETDEV_MACVLAN_MODE_SOURCE);
        assert_se(macvlan_mode_from_string("invalid") < 0);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
