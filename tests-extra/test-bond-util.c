/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "bond-util.h"
#include "tests.h"

TEST(bond_mode_to_string) {
        ASSERT_STREQ(bond_mode_to_string(NETDEV_BOND_MODE_BALANCE_RR), "balance-rr");
        ASSERT_STREQ(bond_mode_to_string(NETDEV_BOND_MODE_ACTIVE_BACKUP), "active-backup");
        ASSERT_STREQ(bond_mode_to_string(NETDEV_BOND_MODE_BALANCE_XOR), "balance-xor");
        ASSERT_STREQ(bond_mode_to_string(NETDEV_BOND_MODE_BROADCAST), "broadcast");
        ASSERT_STREQ(bond_mode_to_string(NETDEV_BOND_MODE_802_3AD), "802.3ad");
        ASSERT_STREQ(bond_mode_to_string(NETDEV_BOND_MODE_BALANCE_TLB), "balance-tlb");
        ASSERT_STREQ(bond_mode_to_string(NETDEV_BOND_MODE_BALANCE_ALB), "balance-alb");
}

TEST(bond_mode_from_string) {
        ASSERT_EQ(bond_mode_from_string("balance-rr"), NETDEV_BOND_MODE_BALANCE_RR);
        ASSERT_EQ(bond_mode_from_string("active-backup"), NETDEV_BOND_MODE_ACTIVE_BACKUP);
        ASSERT_EQ(bond_mode_from_string("802.3ad"), NETDEV_BOND_MODE_802_3AD);
        ASSERT_EQ(bond_mode_from_string("balance-tlb"), NETDEV_BOND_MODE_BALANCE_TLB);
        ASSERT_EQ(bond_mode_from_string("invalid"), _NETDEV_BOND_MODE_INVALID);
}

TEST(bond_xmit_hash_policy_to_string) {
        ASSERT_STREQ(bond_xmit_hash_policy_to_string(NETDEV_BOND_XMIT_HASH_POLICY_LAYER2), "layer2");
        ASSERT_STREQ(bond_xmit_hash_policy_to_string(NETDEV_BOND_XMIT_HASH_POLICY_LAYER34), "layer3+4");
        ASSERT_STREQ(bond_xmit_hash_policy_to_string(NETDEV_BOND_XMIT_HASH_POLICY_LAYER23), "layer2+3");
        ASSERT_STREQ(bond_xmit_hash_policy_to_string(NETDEV_BOND_XMIT_HASH_POLICY_ENCAP23), "encap2+3");
        ASSERT_STREQ(bond_xmit_hash_policy_to_string(NETDEV_BOND_XMIT_HASH_POLICY_ENCAP34), "encap3+4");
}

TEST(bond_xmit_hash_policy_from_string) {
        ASSERT_EQ(bond_xmit_hash_policy_from_string("layer2"), NETDEV_BOND_XMIT_HASH_POLICY_LAYER2);
        ASSERT_EQ(bond_xmit_hash_policy_from_string("layer3+4"), NETDEV_BOND_XMIT_HASH_POLICY_LAYER34);
        ASSERT_EQ(bond_xmit_hash_policy_from_string("invalid"), _NETDEV_BOND_XMIT_HASH_POLICY_INVALID);
}

TEST(bond_lacp_rate_to_string) {
        ASSERT_STREQ(bond_lacp_rate_to_string(NETDEV_BOND_LACP_RATE_SLOW), "slow");
        ASSERT_STREQ(bond_lacp_rate_to_string(NETDEV_BOND_LACP_RATE_FAST), "fast");
}

TEST(bond_lacp_rate_from_string) {
        ASSERT_EQ(bond_lacp_rate_from_string("slow"), NETDEV_BOND_LACP_RATE_SLOW);
        ASSERT_EQ(bond_lacp_rate_from_string("fast"), NETDEV_BOND_LACP_RATE_FAST);
        ASSERT_EQ(bond_lacp_rate_from_string("invalid"), _NETDEV_BOND_LACP_RATE_INVALID);
}

TEST(bond_ad_select_to_string) {
        ASSERT_STREQ(bond_ad_select_to_string(NETDEV_BOND_AD_SELECT_STABLE), "stable");
        ASSERT_STREQ(bond_ad_select_to_string(NETDEV_BOND_AD_SELECT_BANDWIDTH), "bandwidth");
        ASSERT_STREQ(bond_ad_select_to_string(NETDEV_BOND_AD_SELECT_COUNT), "count");
}

TEST(bond_ad_select_from_string) {
        ASSERT_EQ(bond_ad_select_from_string("stable"), NETDEV_BOND_AD_SELECT_STABLE);
        ASSERT_EQ(bond_ad_select_from_string("bandwidth"), NETDEV_BOND_AD_SELECT_BANDWIDTH);
        ASSERT_EQ(bond_ad_select_from_string("count"), NETDEV_BOND_AD_SELECT_COUNT);
        ASSERT_EQ(bond_ad_select_from_string("invalid"), _NETDEV_BOND_AD_SELECT_INVALID);
}

TEST(bond_fail_over_mac_to_string) {
        ASSERT_STREQ(bond_fail_over_mac_to_string(NETDEV_BOND_FAIL_OVER_MAC_NONE), "none");
        ASSERT_STREQ(bond_fail_over_mac_to_string(NETDEV_BOND_FAIL_OVER_MAC_ACTIVE), "active");
        ASSERT_STREQ(bond_fail_over_mac_to_string(NETDEV_BOND_FAIL_OVER_MAC_FOLLOW), "follow");
}

TEST(bond_fail_over_mac_from_string) {
        ASSERT_EQ(bond_fail_over_mac_from_string("none"), NETDEV_BOND_FAIL_OVER_MAC_NONE);
        ASSERT_EQ(bond_fail_over_mac_from_string("active"), NETDEV_BOND_FAIL_OVER_MAC_ACTIVE);
        ASSERT_EQ(bond_fail_over_mac_from_string("follow"), NETDEV_BOND_FAIL_OVER_MAC_FOLLOW);
        ASSERT_EQ(bond_fail_over_mac_from_string("invalid"), _NETDEV_BOND_FAIL_OVER_MAC_INVALID);
}

TEST(bond_arp_validate_to_string) {
        ASSERT_STREQ(bond_arp_validate_to_string(NETDEV_BOND_ARP_VALIDATE_NONE), "none");
        ASSERT_STREQ(bond_arp_validate_to_string(NETDEV_BOND_ARP_VALIDATE_ACTIVE), "active");
        ASSERT_STREQ(bond_arp_validate_to_string(NETDEV_BOND_ARP_VALIDATE_BACKUP), "backup");
        ASSERT_STREQ(bond_arp_validate_to_string(NETDEV_BOND_ARP_VALIDATE_ALL), "all");
}

TEST(bond_arp_validate_from_string) {
        ASSERT_EQ(bond_arp_validate_from_string("none"), NETDEV_BOND_ARP_VALIDATE_NONE);
        ASSERT_EQ(bond_arp_validate_from_string("active"), NETDEV_BOND_ARP_VALIDATE_ACTIVE);
        ASSERT_EQ(bond_arp_validate_from_string("backup"), NETDEV_BOND_ARP_VALIDATE_BACKUP);
        ASSERT_EQ(bond_arp_validate_from_string("all"), NETDEV_BOND_ARP_VALIDATE_ALL);
        ASSERT_EQ(bond_arp_validate_from_string("invalid"), _NETDEV_BOND_ARP_VALIDATE_INVALID);
}

TEST(bond_arp_all_targets_to_string) {
        ASSERT_STREQ(bond_arp_all_targets_to_string(NETDEV_BOND_ARP_ALL_TARGETS_ANY), "any");
        ASSERT_STREQ(bond_arp_all_targets_to_string(NETDEV_BOND_ARP_ALL_TARGETS_ALL), "all");
}

TEST(bond_arp_all_targets_from_string) {
        ASSERT_EQ(bond_arp_all_targets_from_string("any"), NETDEV_BOND_ARP_ALL_TARGETS_ANY);
        ASSERT_EQ(bond_arp_all_targets_from_string("all"), NETDEV_BOND_ARP_ALL_TARGETS_ALL);
        ASSERT_EQ(bond_arp_all_targets_from_string("invalid"), _NETDEV_BOND_ARP_ALL_TARGETS_INVALID);
}

TEST(bond_primary_reselect_to_string) {
        ASSERT_STREQ(bond_primary_reselect_to_string(NETDEV_BOND_PRIMARY_RESELECT_ALWAYS), "always");
        ASSERT_STREQ(bond_primary_reselect_to_string(NETDEV_BOND_PRIMARY_RESELECT_BETTER), "better");
        ASSERT_STREQ(bond_primary_reselect_to_string(NETDEV_BOND_PRIMARY_RESELECT_FAILURE), "failure");
}

TEST(bond_primary_reselect_from_string) {
        ASSERT_EQ(bond_primary_reselect_from_string("always"), NETDEV_BOND_PRIMARY_RESELECT_ALWAYS);
        ASSERT_EQ(bond_primary_reselect_from_string("better"), NETDEV_BOND_PRIMARY_RESELECT_BETTER);
        ASSERT_EQ(bond_primary_reselect_from_string("failure"), NETDEV_BOND_PRIMARY_RESELECT_FAILURE);
        ASSERT_EQ(bond_primary_reselect_from_string("invalid"), _NETDEV_BOND_PRIMARY_RESELECT_INVALID);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
