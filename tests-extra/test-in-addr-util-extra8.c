/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <netinet/in.h>
#include <string.h>

#include "in-addr-util.h"
#include "string-util.h"
#include "tests.h"

TEST(in4_addr_default_subnet_mask) {
        struct in_addr addr, mask;

        /* Class A: 10.x.x.x → 255.0.0.0 */
        addr.s_addr = htobe32(0x0a000001);
        assert_se(in4_addr_default_subnet_mask(&addr, &mask) >= 0);
        assert_se(mask.s_addr == htobe32(0xff000000));

        /* Class B: 172.16.x.x → 255.255.0.0 */
        addr.s_addr = htobe32(0xac100001);
        assert_se(in4_addr_default_subnet_mask(&addr, &mask) >= 0);
        assert_se(mask.s_addr == htobe32(0xffff0000));

        /* Class C: 192.168.1.x → 255.255.255.0 */
        addr.s_addr = htobe32(0xc0a80101);
        assert_se(in4_addr_default_subnet_mask(&addr, &mask) >= 0);
        assert_se(mask.s_addr == htobe32(0xffffff00));
}

TEST(in6_addr_prefixlen_to_netmask) {
        struct in6_addr mask;

        /* /0 → all zeros */
        assert_se(in6_addr_prefixlen_to_netmask(&mask, 0));
        assert_se(memcmp(&mask, &(struct in6_addr){}, sizeof(mask)) == 0);

        /* /128 → all ones */
        assert_se(in6_addr_prefixlen_to_netmask(&mask, 128));
        struct in6_addr all_ones;
        memset(&all_ones, 0xff, sizeof(all_ones));
        assert_se(memcmp(&mask, &all_ones, sizeof(mask)) == 0);

        /* /64 → first 8 bytes ones, rest zeros */
        assert_se(in6_addr_prefixlen_to_netmask(&mask, 64));
        for (int i = 0; i < 8; i++)
                assert_se(mask.s6_addr[i] == 0xff);
        for (int i = 8; i < 16; i++)
                assert_se(mask.s6_addr[i] == 0x00);

        /* /16 → first 2 bytes ones */
        assert_se(in6_addr_prefixlen_to_netmask(&mask, 16));
        assert_se(mask.s6_addr[0] == 0xff);
        assert_se(mask.s6_addr[1] == 0xff);
        for (int i = 2; i < 16; i++)
                assert_se(mask.s6_addr[i] == 0x00);
}

TEST(in6_addr_mask) {
        struct in6_addr a;

        /* fe80::1 /64 → fe80:: */
        memset(&a, 0, sizeof(a));
        a.s6_addr[0] = 0xfe;
        a.s6_addr[1] = 0x80;
        a.s6_addr[15] = 0x01;
        assert_se(in6_addr_mask(&a, 64) >= 0);
        assert_se(a.s6_addr[0] == 0xfe);
        assert_se(a.s6_addr[1] == 0x80);
        for (int i = 2; i < 16; i++)
                assert_se(a.s6_addr[i] == 0);

        /* /128 → unchanged */
        memset(&a, 0, sizeof(a));
        a.s6_addr[0] = 0xfe;
        a.s6_addr[15] = 0x01;
        struct in6_addr orig = a;
        assert_se(in6_addr_mask(&a, 128) >= 0);
        assert_se(memcmp(&a, &orig, sizeof(a)) == 0);

        /* /0 → all zeros */
        a.s6_addr[0] = 0xff;
        a.s6_addr[15] = 0xff;
        assert_se(in6_addr_mask(&a, 0) >= 0);
        for (int i = 0; i < 16; i++)
                assert_se(a.s6_addr[i] == 0);
}

TEST(in_addr_prefix_from_string) {
        union in_addr_union prefix;
        unsigned char prefixlen;
        int r;

        /* Valid IPv4 with prefix */
        r = in_addr_prefix_from_string("192.168.1.0/24", AF_INET, &prefix, &prefixlen);
        assert_se(r >= 0);
        assert_se(prefixlen == 24);
        assert_se(prefix.in.s_addr == htobe32(0xC0A80100));

        /* Valid IPv6 with prefix */
        r = in_addr_prefix_from_string("fe80::/64", AF_INET6, &prefix, &prefixlen);
        assert_se(r >= 0);
        assert_se(prefixlen == 64);

        /* No prefix → defaults to /32 for IPv4 */
        r = in_addr_prefix_from_string("192.168.1.0", AF_INET, &prefix, &prefixlen);
        assert_se(r >= 0);
        assert_se(prefixlen == 32);

        /* Unsupported family */
        assert_se(in_addr_prefix_from_string("test", AF_UNIX, &prefix, &prefixlen) == -EAFNOSUPPORT);
}

TEST(in4_addr_equal_basic) {
        struct in_addr a, b;

        a.s_addr = htobe32(0xC0A80101);
        b.s_addr = htobe32(0xC0A80101);
        assert_se(in4_addr_equal(&a, &b));

        b.s_addr = htobe32(0xC0A80102);
        assert_se(!in4_addr_equal(&a, &b));
}

TEST(in6_addr_equal_basic) {
        struct in6_addr a = {}, b = {};

        assert_se(in6_addr_equal(&a, &b));

        a.s6_addr[15] = 1;
        assert_se(!in6_addr_equal(&a, &b));

        b.s6_addr[15] = 1;
        assert_se(in6_addr_equal(&a, &b));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
