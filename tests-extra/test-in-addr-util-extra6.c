/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <netinet/in.h>

#include "in-addr-util.h"
#include "string-util.h"
#include "tests.h"

TEST(in4_addr_prefixlen_to_netmask) {
        struct in_addr mask;

        /* /8 → 255.0.0.0 */
        assert_se(in4_addr_prefixlen_to_netmask(&mask, 8));
        assert_se(mask.s_addr == htobe32(0xff000000));

        /* /24 → 255.255.255.0 */
        assert_se(in4_addr_prefixlen_to_netmask(&mask, 24));
        assert_se(mask.s_addr == htobe32(0xffffff00));

        /* /32 → 255.255.255.255 */
        assert_se(in4_addr_prefixlen_to_netmask(&mask, 32));
        assert_se(mask.s_addr == htobe32(0xffffffff));
}

TEST(in4_addr_netmask_to_prefixlen) {
        struct in_addr mask;

        /* 255.255.255.0 → 24 */
        mask.s_addr = htobe32(0xffffff00);
        assert_se(in4_addr_netmask_to_prefixlen(&mask) == 24);

        /* 255.0.0.0 → 8 */
        mask.s_addr = htobe32(0xff000000);
        assert_se(in4_addr_netmask_to_prefixlen(&mask) == 8);

        /* 0.0.0.0 → 0 */
        mask.s_addr = 0;
        assert_se(in4_addr_netmask_to_prefixlen(&mask) == 0);

        /* 255.255.255.255 → 32 */
        mask.s_addr = htobe32(0xffffffff);
        assert_se(in4_addr_netmask_to_prefixlen(&mask) == 32);
}

TEST(in4_addr_mask) {
        struct in_addr a;

        /* 192.168.1.100 / 24 → 192.168.1.0 */
        a.s_addr = htobe32(0xc0a80164);
        in4_addr_mask(&a, 24);
        assert_se(a.s_addr == htobe32(0xc0a80100));

        /* 10.0.0.1 / 8 → 10.0.0.0 */
        a.s_addr = htobe32(0x0a000001);
        in4_addr_mask(&a, 8);
        assert_se(a.s_addr == htobe32(0x0a000000));

        /* /32 → unchanged */
        a.s_addr = htobe32(0x01020304);
        in4_addr_mask(&a, 32);
        assert_se(a.s_addr == htobe32(0x01020304));

        /* /0 → 0.0.0.0 */
        a.s_addr = htobe32(0x01020304);
        in4_addr_mask(&a, 0);
        assert_se(a.s_addr == 0);
}

TEST(in4_addr_default_prefixlen) {
        struct in_addr a;
        unsigned char prefixlen;

        /* Class A: 10.x.x.x → 8 */
        a.s_addr = htobe32(0x0a000001);
        assert_se(in4_addr_default_prefixlen(&a, &prefixlen) >= 0);
        assert_se(prefixlen == 8);

        /* Class B: 172.16.x.x → 16 */
        a.s_addr = htobe32(0xac100001);
        assert_se(in4_addr_default_prefixlen(&a, &prefixlen) >= 0);
        assert_se(prefixlen == 16);

        /* Class C: 192.168.1.x → 24 */
        a.s_addr = htobe32(0xc0a80101);
        assert_se(in4_addr_default_prefixlen(&a, &prefixlen) >= 0);
        assert_se(prefixlen == 24);

        /* Multicast/other → returns error */
        a.s_addr = htobe32(0xe0000001);
        assert_se(in4_addr_default_prefixlen(&a, &prefixlen) < 0);
}

TEST(in_addr_equal_basic) {
        union in_addr_union a = {}, b = {};

        /* Both zero */
        assert_se(in_addr_equal(AF_INET, &a, &b));

        /* Same value */
        a.in.s_addr = htobe32(0x0a000001);
        b.in.s_addr = htobe32(0x0a000001);
        assert_se(in_addr_equal(AF_INET, &a, &b));

        /* Different values */
        b.in.s_addr = htobe32(0x0a000002);
        assert_se(!in_addr_equal(AF_INET, &a, &b));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
