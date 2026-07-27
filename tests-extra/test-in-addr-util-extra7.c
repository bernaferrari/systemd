/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <netinet/in.h>

#include "in-addr-util.h"
#include "string-util.h"
#include "tests.h"

TEST(in4_addr_is_null) {
        struct in_addr a;

        a.s_addr = htobe32(0);
        assert_se(in4_addr_is_null(&a));

        a.s_addr = htobe32(0x0a000001);
        assert_se(!in4_addr_is_null(&a));
}

TEST(in6_addr_is_null) {
        struct in6_addr a = {}, b = {};

        assert_se(in6_addr_is_null(&a));

        b.s6_addr[15] = 1;
        assert_se(!in6_addr_is_null(&b));
}

TEST(in_addr_is_null) {
        union in_addr_union u = {};

        assert_se(in_addr_is_null(AF_INET, &u));
        assert_se(in_addr_is_null(AF_INET6, &u));

        u.in.s_addr = htobe32(0x0a000001);
        assert_se(!in_addr_is_null(AF_INET, &u));

        assert_se(in_addr_is_null(AF_UNIX, &u) == -EAFNOSUPPORT);
}

TEST(in4_addr_is_link_local) {
        struct in_addr a;

        /* 169.254.1.1 is link-local */
        a.s_addr = htobe32(0xA9FE0101);
        assert_se(in4_addr_is_link_local(&a));

        /* 169.254.0.0 is link-local */
        a.s_addr = htobe32(0xA9FE0000);
        assert_se(in4_addr_is_link_local(&a));

        /* 192.168.1.1 is not link-local */
        a.s_addr = htobe32(0xC0A80101);
        assert_se(!in4_addr_is_link_local(&a));
}

TEST(in4_addr_is_link_local_dynamic) {
        struct in_addr a;

        /* 169.254.1.1 is dynamic link-local (RFC 3927 valid range) */
        a.s_addr = htobe32(0xA9FE0101);
        assert_se(in4_addr_is_link_local_dynamic(&a));

        /* 169.254.0.1 is NOT dynamic (reserved /24) */
        a.s_addr = htobe32(0xA9FE0001);
        assert_se(!in4_addr_is_link_local_dynamic(&a));

        /* 169.254.255.1 is NOT dynamic (reserved /24) */
        a.s_addr = htobe32(0xA9FEFF01);
        assert_se(!in4_addr_is_link_local_dynamic(&a));

        /* 192.168.1.1 is not link-local at all */
        a.s_addr = htobe32(0xC0A80101);
        assert_se(!in4_addr_is_link_local_dynamic(&a));
}

TEST(in6_addr_is_link_local) {
        struct in6_addr a = {};

        /* fe80::1 is link-local */
        a.s6_addr[0] = 0xfe;
        a.s6_addr[1] = 0x80;
        a.s6_addr[15] = 1;
        assert_se(in6_addr_is_link_local(&a));

        /* fc00::1 is NOT link-local (unique local) */
        a.s6_addr[0] = 0xfc;
        a.s6_addr[1] = 0x00;
        assert_se(!in6_addr_is_link_local(&a));
}

TEST(in6_addr_is_link_local_all_nodes) {
        struct in6_addr a = {};

        /* ff02::1 */
        a.s6_addr[0] = 0xff;
        a.s6_addr[1] = 0x02;
        a.s6_addr[15] = 0x01;
        assert_se(in6_addr_is_link_local_all_nodes(&a));

        /* ff02::2 is NOT all-nodes */
        a.s6_addr[15] = 0x02;
        assert_se(!in6_addr_is_link_local_all_nodes(&a));
}

TEST(in4_addr_is_multicast) {
        struct in_addr a;

        /* 224.0.0.1 is multicast */
        a.s_addr = htobe32(0xE0000001);
        assert_se(in4_addr_is_multicast(&a));

        /* 239.255.255.255 is multicast */
        a.s_addr = htobe32(0xEFFFFFFF);
        assert_se(in4_addr_is_multicast(&a));

        /* 192.168.1.1 is not multicast */
        a.s_addr = htobe32(0xC0A80101);
        assert_se(!in4_addr_is_multicast(&a));
}

TEST(in6_addr_is_multicast) {
        struct in6_addr a = {};

        a.s6_addr[0] = 0xff;
        a.s6_addr[15] = 1;
        assert_se(in6_addr_is_multicast(&a));

        a.s6_addr[0] = 0xfe;
        assert_se(!in6_addr_is_multicast(&a));
}

TEST(in4_addr_is_local_multicast) {
        struct in_addr a;

        /* 224.0.0.1 is local multicast */
        a.s_addr = htobe32(0xE0000001);
        assert_se(in4_addr_is_local_multicast(&a));

        /* 224.0.0.255 is local multicast */
        a.s_addr = htobe32(0xE00000FF);
        assert_se(in4_addr_is_local_multicast(&a));

        /* 224.1.0.0 is NOT local multicast (outside /24) */
        a.s_addr = htobe32(0xE0010000);
        assert_se(!in4_addr_is_local_multicast(&a));

        /* 239.0.0.1 is NOT local multicast */
        a.s_addr = htobe32(0xEF000001);
        assert_se(!in4_addr_is_local_multicast(&a));
}

TEST(in4_addr_is_localhost) {
        struct in_addr a;

        /* 127.0.0.1 */
        a.s_addr = htobe32(0x7F000001);
        assert_se(in4_addr_is_localhost(&a));

        /* 127.255.255.255 */
        a.s_addr = htobe32(0x7FFFFFFF);
        assert_se(in4_addr_is_localhost(&a));

        /* 10.0.0.1 is not localhost */
        a.s_addr = htobe32(0x0A000001);
        assert_se(!in4_addr_is_localhost(&a));
}

TEST(in4_addr_is_non_local) {
        struct in_addr a;

        /* 8.8.8.8 is non-local */
        a.s_addr = htobe32(0x08080808);
        assert_se(in4_addr_is_non_local(&a));

        /* 0.0.0.0 is NOT non-local (null) */
        a.s_addr = 0;
        assert_se(!in4_addr_is_non_local(&a));

        /* 127.0.0.1 is NOT non-local (localhost) */
        a.s_addr = htobe32(0x7F000001);
        assert_se(!in4_addr_is_non_local(&a));
}

TEST(in_addr_is_localhost_one) {
        union in_addr_union u = {};

        /* 127.0.0.1 */
        u.in.s_addr = htobe32(0x7F000001);
        assert_se(in_addr_is_localhost_one(AF_INET, &u));

        /* 127.0.0.2 is NOT localhost_one */
        u.in.s_addr = htobe32(0x7F000002);
        assert_se(!in_addr_is_localhost_one(AF_INET, &u));

        /* ::1 */
        u = (union in_addr_union) {};
        u.in6.s6_addr[15] = 1;
        assert_se(in_addr_is_localhost_one(AF_INET6, &u));

        /* unsupported family */
        assert_se(in_addr_is_localhost_one(AF_UNIX, &u) == -EAFNOSUPPORT);
}

TEST(in6_addr_is_ipv4_mapped) {
        struct in6_addr a = {};

        /* ::ffff:192.168.1.1 */
        a.s6_addr[10] = 0xff;
        a.s6_addr[11] = 0xff;
        a.s6_addr[12] = 192;
        a.s6_addr[13] = 168;
        a.s6_addr[14] = 1;
        a.s6_addr[15] = 1;
        assert_se(in6_addr_is_ipv4_mapped_address(&a));

        /* Regular IPv6 is not mapped */
        a = (struct in6_addr) {};
        a.s6_addr[15] = 1;
        assert_se(!in6_addr_is_ipv4_mapped_address(&a));
}

TEST(in4_addr_prefix_intersect) {
        struct in_addr a, b;

        /* 192.168.1.0/24 and 192.168.1.128/25 → intersect */
        a.s_addr = htobe32(0xC0A80100);
        b.s_addr = htobe32(0xC0A80180);
        assert_se(in4_addr_prefix_intersect(&a, 24, &b, 25));

        /* 192.168.1.0/24 and 192.168.2.0/24 → no intersect */
        b.s_addr = htobe32(0xC0A80200);
        assert_se(!in4_addr_prefix_intersect(&a, 24, &b, 24));

        /* prefixlen 0 always intersects */
        assert_se(in4_addr_prefix_intersect(&a, 0, &b, 0));
}

TEST(in4_addr_prefix_covers) {
        struct in_addr prefix, addr;

        /* 192.168.1.0/24 covers 192.168.1.100 */
        prefix.s_addr = htobe32(0xC0A80100);
        addr.s_addr = htobe32(0xC0A80164);
        assert_se(in4_addr_prefix_covers_full(&prefix, 24, &addr, 32));

        /* 192.168.1.0/24 does NOT cover 192.168.2.1 */
        addr.s_addr = htobe32(0xC0A80201);
        assert_se(!in4_addr_prefix_covers_full(&prefix, 24, &addr, 32));

        /* /25 does NOT cover /24 (prefixlen > address_prefixlen) */
        assert_se(!in4_addr_prefix_covers_full(&prefix, 25, &addr, 24));
}

TEST(in_addr_parse_prefixlen) {
        unsigned char plen;

        assert_se(in_addr_parse_prefixlen(AF_INET, "24", &plen) >= 0);
        assert_se(plen == 24);

        assert_se(in_addr_parse_prefixlen(AF_INET, "32", &plen) >= 0);
        assert_se(plen == 32);

        assert_se(in_addr_parse_prefixlen(AF_INET6, "64", &plen) >= 0);
        assert_se(plen == 64);

        /* Out of range for IPv4 */
        assert_se(in_addr_parse_prefixlen(AF_INET, "33", &plen) == -ERANGE);

        /* Out of range for IPv6 */
        assert_se(in_addr_parse_prefixlen(AF_INET6, "129", &plen) == -ERANGE);

        /* Invalid string */
        assert_se(in_addr_parse_prefixlen(AF_INET, "abc", &plen) < 0);

        /* Unsupported family */
        assert_se(in_addr_parse_prefixlen(AF_UNIX, "24", &plen) == -EAFNOSUPPORT);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
