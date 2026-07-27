/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/netfilter.h>

#include "firewall-util.h"
#include "string-util.h"
#include "tests.h"

TEST(nfproto_to_from_string) {
        /* to_string */
        assert_se(streq(nfproto_to_string(NFPROTO_IPV4), "ip"));
        assert_se(streq(nfproto_to_string(NFPROTO_IPV6), "ip6"));
        assert_se(streq(nfproto_to_string(NFPROTO_ARP), "arp"));
        assert_se(streq(nfproto_to_string(NFPROTO_BRIDGE), "bridge"));
        assert_se(streq(nfproto_to_string(NFPROTO_INET), "inet"));
        assert_se(streq(nfproto_to_string(NFPROTO_NETDEV), "netdev"));

        /* from_string */
        assert_se(nfproto_from_string("ip") == NFPROTO_IPV4);
        assert_se(nfproto_from_string("ip6") == NFPROTO_IPV6);
        assert_se(nfproto_from_string("arp") == NFPROTO_ARP);
        assert_se(nfproto_from_string("bridge") == NFPROTO_BRIDGE);
        assert_se(nfproto_from_string("inet") == NFPROTO_INET);
        assert_se(nfproto_from_string("netdev") == NFPROTO_NETDEV);
        assert_se(nfproto_from_string("invalid") < 0);
}

TEST(nft_set_source_to_from_string) {
        /* to_string */
        assert_se(streq(nft_set_source_to_string(NFT_SET_SOURCE_ADDRESS), "address"));
        assert_se(streq(nft_set_source_to_string(NFT_SET_SOURCE_PREFIX), "prefix"));
        assert_se(streq(nft_set_source_to_string(NFT_SET_SOURCE_IFINDEX), "ifindex"));
        assert_se(streq(nft_set_source_to_string(NFT_SET_SOURCE_CGROUP), "cgroup"));
        assert_se(streq(nft_set_source_to_string(NFT_SET_SOURCE_USER), "user"));
        assert_se(streq(nft_set_source_to_string(NFT_SET_SOURCE_GROUP), "group"));

        /* from_string */
        assert_se(nft_set_source_from_string("address") == NFT_SET_SOURCE_ADDRESS);
        assert_se(nft_set_source_from_string("prefix") == NFT_SET_SOURCE_PREFIX);
        assert_se(nft_set_source_from_string("ifindex") == NFT_SET_SOURCE_IFINDEX);
        assert_se(nft_set_source_from_string("cgroup") == NFT_SET_SOURCE_CGROUP);
        assert_se(nft_set_source_from_string("user") == NFT_SET_SOURCE_USER);
        assert_se(nft_set_source_from_string("group") == NFT_SET_SOURCE_GROUP);
        assert_se(nft_set_source_from_string("invalid") < 0);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
