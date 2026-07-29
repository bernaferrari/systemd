/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "ipvlan-util.h"
#include "tests.h"

TEST(ipvlan_mode_to_from_string) {
        assert_se(streq(ipvlan_mode_to_string(NETDEV_IPVLAN_MODE_L2), "L2"));
        assert_se(streq(ipvlan_mode_to_string(NETDEV_IPVLAN_MODE_L3), "L3"));
        assert_se(streq(ipvlan_mode_to_string(NETDEV_IPVLAN_MODE_L3S), "L3S"));

        assert_se(ipvlan_mode_from_string("L2") == NETDEV_IPVLAN_MODE_L2);
        assert_se(ipvlan_mode_from_string("L3") == NETDEV_IPVLAN_MODE_L3);
        assert_se(ipvlan_mode_from_string("L3S") == NETDEV_IPVLAN_MODE_L3S);
        assert_se(ipvlan_mode_from_string("invalid") < 0);
}

TEST(ipvlan_flags_to_from_string) {
        assert_se(streq(ipvlan_flags_to_string(NETDEV_IPVLAN_FLAGS_BRIDGE), "bridge"));
        assert_se(streq(ipvlan_flags_to_string(NETDEV_IPVLAN_FLAGS_PRIVATE), "private"));
        assert_se(streq(ipvlan_flags_to_string(NETDEV_IPVLAN_FLAGS_VEPA), "vepa"));

        assert_se(ipvlan_flags_from_string("bridge") == NETDEV_IPVLAN_FLAGS_BRIDGE);
        assert_se(ipvlan_flags_from_string("private") == NETDEV_IPVLAN_FLAGS_PRIVATE);
        assert_se(ipvlan_flags_from_string("vepa") == NETDEV_IPVLAN_FLAGS_VEPA);
        assert_se(ipvlan_flags_from_string("invalid") < 0);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
