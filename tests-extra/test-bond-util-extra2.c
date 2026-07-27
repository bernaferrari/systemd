/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "bond-util.h"
#include "string-util.h"
#include "tests.h"

TEST(bond_mode_to_from_string) {
        assert_se(streq(bond_mode_to_string(NETDEV_BOND_MODE_BALANCE_RR), "balance-rr"));
        assert_se(streq(bond_mode_to_string(NETDEV_BOND_MODE_ACTIVE_BACKUP), "active-backup"));
        assert_se(streq(bond_mode_to_string(NETDEV_BOND_MODE_BALANCE_XOR), "balance-xor"));
        assert_se(streq(bond_mode_to_string(NETDEV_BOND_MODE_BROADCAST), "broadcast"));
        assert_se(streq(bond_mode_to_string(NETDEV_BOND_MODE_802_3AD), "802.3ad"));
        assert_se(streq(bond_mode_to_string(NETDEV_BOND_MODE_BALANCE_TLB), "balance-tlb"));
        assert_se(streq(bond_mode_to_string(NETDEV_BOND_MODE_BALANCE_ALB), "balance-alb"));

        assert_se(bond_mode_from_string("balance-rr") == NETDEV_BOND_MODE_BALANCE_RR);
        assert_se(bond_mode_from_string("active-backup") == NETDEV_BOND_MODE_ACTIVE_BACKUP);
        assert_se(bond_mode_from_string("802.3ad") == NETDEV_BOND_MODE_802_3AD);
        assert_se(bond_mode_from_string("invalid") < 0);
}

TEST(bond_xmit_hash_policy_to_from_string) {
        assert_se(streq(bond_xmit_hash_policy_to_string(NETDEV_BOND_XMIT_HASH_POLICY_LAYER2), "layer2"));
        assert_se(streq(bond_xmit_hash_policy_to_string(NETDEV_BOND_XMIT_HASH_POLICY_LAYER34), "layer3+4"));
        assert_se(streq(bond_xmit_hash_policy_to_string(NETDEV_BOND_XMIT_HASH_POLICY_LAYER23), "layer2+3"));
        assert_se(streq(bond_xmit_hash_policy_to_string(NETDEV_BOND_XMIT_HASH_POLICY_ENCAP23), "encap2+3"));
        assert_se(streq(bond_xmit_hash_policy_to_string(NETDEV_BOND_XMIT_HASH_POLICY_ENCAP34), "encap3+4"));

        assert_se(bond_xmit_hash_policy_from_string("layer2") == NETDEV_BOND_XMIT_HASH_POLICY_LAYER2);
        assert_se(bond_xmit_hash_policy_from_string("layer3+4") == NETDEV_BOND_XMIT_HASH_POLICY_LAYER34);
        assert_se(bond_xmit_hash_policy_from_string("invalid") < 0);
}

TEST(bond_lacp_rate_to_from_string) {
        assert_se(streq(bond_lacp_rate_to_string(NETDEV_BOND_LACP_RATE_SLOW), "slow"));
        assert_se(streq(bond_lacp_rate_to_string(NETDEV_BOND_LACP_RATE_FAST), "fast"));

        assert_se(bond_lacp_rate_from_string("slow") == NETDEV_BOND_LACP_RATE_SLOW);
        assert_se(bond_lacp_rate_from_string("fast") == NETDEV_BOND_LACP_RATE_FAST);
}

TEST(bond_ad_select_to_from_string) {
        assert_se(streq(bond_ad_select_to_string(NETDEV_BOND_AD_SELECT_STABLE), "stable"));
        assert_se(streq(bond_ad_select_to_string(NETDEV_BOND_AD_SELECT_BANDWIDTH), "bandwidth"));
        assert_se(streq(bond_ad_select_to_string(NETDEV_BOND_AD_SELECT_COUNT), "count"));

        assert_se(bond_ad_select_from_string("stable") == NETDEV_BOND_AD_SELECT_STABLE);
        assert_se(bond_ad_select_from_string("bandwidth") == NETDEV_BOND_AD_SELECT_BANDWIDTH);
        assert_se(bond_ad_select_from_string("count") == NETDEV_BOND_AD_SELECT_COUNT);
}

TEST(bond_fail_over_mac_to_from_string) {
        assert_se(streq(bond_fail_over_mac_to_string(NETDEV_BOND_FAIL_OVER_MAC_NONE), "none"));
        assert_se(streq(bond_fail_over_mac_to_string(NETDEV_BOND_FAIL_OVER_MAC_ACTIVE), "active"));
        assert_se(streq(bond_fail_over_mac_to_string(NETDEV_BOND_FAIL_OVER_MAC_FOLLOW), "follow"));

        assert_se(bond_fail_over_mac_from_string("none") == NETDEV_BOND_FAIL_OVER_MAC_NONE);
        assert_se(bond_fail_over_mac_from_string("active") == NETDEV_BOND_FAIL_OVER_MAC_ACTIVE);
        assert_se(bond_fail_over_mac_from_string("follow") == NETDEV_BOND_FAIL_OVER_MAC_FOLLOW);
}

TEST(bond_arp_validate_to_from_string) {
        assert_se(streq(bond_arp_validate_to_string(NETDEV_BOND_ARP_VALIDATE_NONE), "none"));
        assert_se(streq(bond_arp_validate_to_string(NETDEV_BOND_ARP_VALIDATE_ACTIVE), "active"));
        assert_se(streq(bond_arp_validate_to_string(NETDEV_BOND_ARP_VALIDATE_BACKUP), "backup"));
        assert_se(streq(bond_arp_validate_to_string(NETDEV_BOND_ARP_VALIDATE_ALL), "all"));

        assert_se(bond_arp_validate_from_string("none") == NETDEV_BOND_ARP_VALIDATE_NONE);
        assert_se(bond_arp_validate_from_string("all") == NETDEV_BOND_ARP_VALIDATE_ALL);
}

TEST(bond_arp_all_targets_to_from_string) {
        assert_se(streq(bond_arp_all_targets_to_string(NETDEV_BOND_ARP_ALL_TARGETS_ANY), "any"));
        assert_se(streq(bond_arp_all_targets_to_string(NETDEV_BOND_ARP_ALL_TARGETS_ALL), "all"));

        assert_se(bond_arp_all_targets_from_string("any") == NETDEV_BOND_ARP_ALL_TARGETS_ANY);
        assert_se(bond_arp_all_targets_from_string("all") == NETDEV_BOND_ARP_ALL_TARGETS_ALL);
}

TEST(bond_primary_reselect_to_from_string) {
        assert_se(streq(bond_primary_reselect_to_string(NETDEV_BOND_PRIMARY_RESELECT_ALWAYS), "always"));
        assert_se(streq(bond_primary_reselect_to_string(NETDEV_BOND_PRIMARY_RESELECT_BETTER), "better"));
        assert_se(streq(bond_primary_reselect_to_string(NETDEV_BOND_PRIMARY_RESELECT_FAILURE), "failure"));

        assert_se(bond_primary_reselect_from_string("always") == NETDEV_BOND_PRIMARY_RESELECT_ALWAYS);
        assert_se(bond_primary_reselect_from_string("better") == NETDEV_BOND_PRIMARY_RESELECT_BETTER);
        assert_se(bond_primary_reselect_from_string("failure") == NETDEV_BOND_PRIMARY_RESELECT_FAILURE);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
