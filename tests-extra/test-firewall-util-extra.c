/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/netfilter.h>

#include "firewall-util.h"
#include "tests.h"

TEST(nfproto_to_string) {
        ASSERT_STREQ(nfproto_to_string(NFPROTO_ARP), "arp");
        ASSERT_STREQ(nfproto_to_string(NFPROTO_BRIDGE), "bridge");
        ASSERT_STREQ(nfproto_to_string(NFPROTO_INET), "inet");
        ASSERT_STREQ(nfproto_to_string(NFPROTO_IPV4), "ip");
        ASSERT_STREQ(nfproto_to_string(NFPROTO_IPV6), "ip6");
        ASSERT_STREQ(nfproto_to_string(NFPROTO_NETDEV), "netdev");
}

TEST(nfproto_from_string) {
        ASSERT_EQ(nfproto_from_string("arp"), NFPROTO_ARP);
        ASSERT_EQ(nfproto_from_string("bridge"), NFPROTO_BRIDGE);
        ASSERT_EQ(nfproto_from_string("inet"), NFPROTO_INET);
        ASSERT_EQ(nfproto_from_string("ip"), NFPROTO_IPV4);
        ASSERT_EQ(nfproto_from_string("ip6"), NFPROTO_IPV6);
        ASSERT_EQ(nfproto_from_string("netdev"), NFPROTO_NETDEV);
        ASSERT_EQ(nfproto_from_string("invalid"), -EINVAL);
}

TEST(nft_set_source_to_string) {
        ASSERT_STREQ(nft_set_source_to_string(NFT_SET_SOURCE_ADDRESS), "address");
        ASSERT_STREQ(nft_set_source_to_string(NFT_SET_SOURCE_PREFIX), "prefix");
        ASSERT_STREQ(nft_set_source_to_string(NFT_SET_SOURCE_IFINDEX), "ifindex");
        ASSERT_STREQ(nft_set_source_to_string(NFT_SET_SOURCE_CGROUP), "cgroup");
        ASSERT_STREQ(nft_set_source_to_string(NFT_SET_SOURCE_USER), "user");
        ASSERT_STREQ(nft_set_source_to_string(NFT_SET_SOURCE_GROUP), "group");
}

TEST(nft_set_source_from_string) {
        ASSERT_EQ(nft_set_source_from_string("address"), NFT_SET_SOURCE_ADDRESS);
        ASSERT_EQ(nft_set_source_from_string("prefix"), NFT_SET_SOURCE_PREFIX);
        ASSERT_EQ(nft_set_source_from_string("ifindex"), NFT_SET_SOURCE_IFINDEX);
        ASSERT_EQ(nft_set_source_from_string("cgroup"), NFT_SET_SOURCE_CGROUP);
        ASSERT_EQ(nft_set_source_from_string("user"), NFT_SET_SOURCE_USER);
        ASSERT_EQ(nft_set_source_from_string("group"), NFT_SET_SOURCE_GROUP);
        ASSERT_EQ(nft_set_source_from_string("invalid"), -EINVAL);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
