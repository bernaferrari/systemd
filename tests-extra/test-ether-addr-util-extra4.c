/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <netinet/if_ether.h>
#include <string.h>

#include "ether-addr-util.h"
#include "string-util.h"
#include "tests.h"

TEST(ether_addr_is_multicast) {
        /* 01:xx:xx:xx:xx:xx is multicast */
        struct ether_addr a;
        assert_se(parse_ether_addr("01:00:5e:00:00:01", &a) >= 0);
        assert_se(ether_addr_is_multicast(&a));

        /* Broadcast (ff:ff:ff:ff:ff:ff) is multicast */
        assert_se(parse_ether_addr("ff:ff:ff:ff:ff:ff", &a) >= 0);
        assert_se(ether_addr_is_multicast(&a));

        /* 03:xx (multicast + local) */
        assert_se(parse_ether_addr("03:00:00:00:00:00", &a) >= 0);
        assert_se(ether_addr_is_multicast(&a));

        /* Normal unicast */
        assert_se(parse_ether_addr("00:1a:2b:3c:4d:5e", &a) >= 0);
        assert_se(!ether_addr_is_multicast(&a));

        /* 02:xx (local but unicast) */
        assert_se(parse_ether_addr("02:00:00:00:00:01", &a) >= 0);
        assert_se(!ether_addr_is_multicast(&a));
}

TEST(ether_addr_is_unicast) {
        struct ether_addr a;
        assert_se(parse_ether_addr("00:1a:2b:3c:4d:5e", &a) >= 0);
        assert_se(ether_addr_is_unicast(&a));

        assert_se(parse_ether_addr("01:00:5e:00:00:01", &a) >= 0);
        assert_se(!ether_addr_is_unicast(&a));

        /* Broadcast is NOT unicast */
        assert_se(parse_ether_addr("ff:ff:ff:ff:ff:ff", &a) >= 0);
        assert_se(!ether_addr_is_unicast(&a));
}

TEST(ether_addr_is_local) {
        struct ether_addr a;

        /* 02:xx:xx:xx:xx:xx is locally assigned */
        assert_se(parse_ether_addr("02:00:00:00:00:01", &a) >= 0);
        assert_se(ether_addr_is_local(&a));

        /* 06:xx (local) */
        assert_se(parse_ether_addr("06:00:00:00:00:01", &a) >= 0);
        assert_se(ether_addr_is_local(&a));

        /* 00:xx is globally assigned */
        assert_se(parse_ether_addr("00:1a:2b:3c:4d:5e", &a) >= 0);
        assert_se(!ether_addr_is_local(&a));
}

TEST(ether_addr_is_global) {
        struct ether_addr a;

        assert_se(parse_ether_addr("00:1a:2b:3c:4d:5e", &a) >= 0);
        assert_se(ether_addr_is_global(&a));

        assert_se(parse_ether_addr("02:00:00:00:00:01", &a) >= 0);
        assert_se(!ether_addr_is_global(&a));
}

TEST(ether_addr_multicast_local_independence) {
        struct ether_addr a;

        /* 00 = global unicast */
        assert_se(parse_ether_addr("00:11:22:33:44:55", &a) >= 0);
        assert_se(!ether_addr_is_multicast(&a));
        assert_se(!ether_addr_is_local(&a));

        /* 01 = global multicast */
        assert_se(parse_ether_addr("01:00:5e:00:00:01", &a) >= 0);
        assert_se(ether_addr_is_multicast(&a));
        assert_se(!ether_addr_is_local(&a));

        /* 02 = local unicast */
        assert_se(parse_ether_addr("02:11:22:33:44:55", &a) >= 0);
        assert_se(!ether_addr_is_multicast(&a));
        assert_se(ether_addr_is_local(&a));

        /* 03 = local multicast */
        assert_se(parse_ether_addr("03:00:00:00:00:01", &a) >= 0);
        assert_se(ether_addr_is_multicast(&a));
        assert_se(ether_addr_is_local(&a));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
