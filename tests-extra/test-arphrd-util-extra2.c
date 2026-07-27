/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/if_arp.h>
#include <net/ethernet.h>

#include "arphrd-util.h"
#include "tests.h"

TEST(arphrd_to_name_basic) {
        assert_se(streq(arphrd_to_name(ARPHRD_ETHER), "ETHER"));
        assert_se(streq(arphrd_to_name(ARPHRD_LOOPBACK), "LOOPBACK"));
        assert_se(streq(arphrd_to_name(ARPHRD_INFINIBAND), "INFINIBAND"));
        assert_se(arphrd_to_name(99999) == NULL);
}

TEST(arphrd_from_name_basic) {
        assert_se(arphrd_from_name("ETHER") == ARPHRD_ETHER);
        assert_se(arphrd_from_name("LOOPBACK") == ARPHRD_LOOPBACK);
        assert_se(arphrd_from_name("INFINIBAND") == ARPHRD_INFINIBAND);
        assert_se(arphrd_from_name("nonexistent") == -EINVAL);
}

TEST(arphrd_roundtrip) {
        assert_se(arphrd_from_name(arphrd_to_name(ARPHRD_ETHER)) == ARPHRD_ETHER);
        assert_se(arphrd_from_name(arphrd_to_name(ARPHRD_LOOPBACK)) == ARPHRD_LOOPBACK);
        assert_se(arphrd_from_name(arphrd_to_name(ARPHRD_INFINIBAND)) == ARPHRD_INFINIBAND);
}

TEST(arphrd_to_hw_addr_len_basic) {
        assert_se(arphrd_to_hw_addr_len(ARPHRD_ETHER) == ETH_ALEN);
        assert_se(arphrd_to_hw_addr_len(ARPHRD_INFINIBAND) == 20);
        assert_se(arphrd_to_hw_addr_len(ARPHRD_TUNNEL) == 4);
        assert_se(arphrd_to_hw_addr_len(ARPHRD_TUNNEL6) == 16);
        assert_se(arphrd_to_hw_addr_len(ARPHRD_LOOPBACK) == 0);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
