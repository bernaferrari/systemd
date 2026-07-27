/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <arpa/inet.h>

#include "in-addr-util.h"
#include "tests.h"

TEST(in4_addr_null_and_set) {
        struct in_addr a = {};
        assert_se(in4_addr_is_null(&a));
        assert_se(!in4_addr_is_set(&a));

        a.s_addr = htobe32(0x01020304);
        assert_se(!in4_addr_is_null(&a));
        assert_se(in4_addr_is_set(&a));
}

TEST(in6_addr_null_and_set) {
        struct in6_addr a = {};
        assert_se(in6_addr_is_null(&a));
        assert_se(!in6_addr_is_set(&a));

        a.s6_addr[15] = 1;
        assert_se(!in6_addr_is_null(&a));
        assert_se(in6_addr_is_set(&a));
}

TEST(in4_addr_equal_basic) {
        struct in_addr a = { .s_addr = htobe32(0x0a000001) };
        struct in_addr b = { .s_addr = htobe32(0x0a000001) };
        struct in_addr c = { .s_addr = htobe32(0x0a000002) };

        assert_se(in4_addr_equal(&a, &b));
        assert_se(!in4_addr_equal(&a, &c));
}

TEST(in6_addr_equal_basic) {
        struct in6_addr a = {}, b = {}, c = {};
        a.s6_addr[15] = 1;
        b.s6_addr[15] = 1;
        c.s6_addr[15] = 2;

        assert_se(in6_addr_equal(&a, &b));
        assert_se(!in6_addr_equal(&a, &c));
}

TEST(in4_addr_is_localhost_basic) {
        struct in_addr loopback = { .s_addr = htobe32((UINT32_C(127) << 24) | 1) };
        struct in_addr loopback2 = { .s_addr = htobe32((UINT32_C(127) << 24) | 0x0a) };
        struct in_addr other = { .s_addr = htobe32(0x0a000001) };

        assert_se(in4_addr_is_localhost(&loopback));
        assert_se(in4_addr_is_localhost(&loopback2));
        assert_se(!in4_addr_is_localhost(&other));
}

TEST(in4_addr_is_link_local_basic) {
        struct in_addr linklocal = { .s_addr = htobe32((UINT32_C(169) << 24) | (UINT32_C(254) << 16) | 1) };
        struct in_addr other = { .s_addr = htobe32(0x0a000001) };

        assert_se(in4_addr_is_link_local(&linklocal));
        assert_se(!in4_addr_is_link_local(&other));
}

TEST(in4_addr_is_multicast_basic) {
        struct in_addr mcast = { .s_addr = htobe32((UINT32_C(224) << 24) | 1) };
        struct in_addr mcast2 = { .s_addr = htobe32((UINT32_C(239) << 24) | 255) };
        struct in_addr other = { .s_addr = htobe32(0x0a000001) };

        assert_se(in4_addr_is_multicast(&mcast));
        assert_se(in4_addr_is_multicast(&mcast2));
        assert_se(!in4_addr_is_multicast(&other));
}

TEST(in6_addr_is_multicast_basic) {
        struct in6_addr mcast = {};
        mcast.s6_addr[0] = 0xff;
        struct in6_addr other = {};
        other.s6_addr[0] = 0xfe;

        assert_se(in6_addr_is_multicast(&mcast));
        assert_se(!in6_addr_is_multicast(&other));
}

TEST(in4_addr_is_local_multicast_basic) {
        /* 224.0.0.0/24 is local multicast */
        struct in_addr local_mcast = { .s_addr = htobe32((UINT32_C(224) << 24) | 1) };
        struct in_addr global_mcast = { .s_addr = htobe32((UINT32_C(225) << 24) | 1) };

        assert_se(in4_addr_is_local_multicast(&local_mcast));
        assert_se(!in4_addr_is_local_multicast(&global_mcast));
}

TEST(in4_addr_prefix_intersect_basic) {
        struct in_addr a = { .s_addr = htobe32(0x0a000000) }; /* 10.0.0.0 */
        struct in_addr b = { .s_addr = htobe32(0x0a000100) }; /* 10.0.1.0 */
        struct in_addr c = { .s_addr = htobe32(0x0b000000) }; /* 11.0.0.0 */

        /* Same /8 prefix */
        assert_se(in4_addr_prefix_intersect(&a, 8, &b, 8));
        /* Same /16 */
        assert_se(in4_addr_prefix_intersect(&a, 16, &b, 16));
        /* Different /8 */
        assert_se(!in4_addr_prefix_intersect(&a, 8, &c, 8));
        /* /0 always matches */
        assert_se(in4_addr_prefix_intersect(&a, 0, &c, 0));
}

TEST(in6_addr_prefix_intersect_basic) {
        struct in6_addr a = {}, b = {}, c = {};
        a.s6_addr[0] = 0xfd;
        b.s6_addr[0] = 0xfd;
        b.s6_addr[1] = 0x01;
        c.s6_addr[0] = 0xfe;

        assert_se(in6_addr_prefix_intersect(&a, 8, &b, 8));
        assert_se(!in6_addr_prefix_intersect(&a, 8, &c, 8));
        assert_se(in6_addr_prefix_intersect(&a, 0, &c, 0));
}

TEST(in_addr_is_null_and_set) {
        union in_addr_union a4 = {}, a6 = {};
        a4.in.s_addr = 0;
        assert_se(in_addr_is_null(AF_INET, &a4));
        assert_se(!in_addr_is_set(AF_INET, &a4));

        a4.in.s_addr = htobe32(1);
        assert_se(!in_addr_is_null(AF_INET, &a4));
        assert_se(in_addr_is_set(AF_INET, &a4));

        assert_se(in_addr_is_null(AF_INET6, &a6));
        assert_se(!in_addr_is_set(AF_INET6, &a6));

        a6.in6.s6_addr[15] = 1;
        assert_se(!in_addr_is_null(AF_INET6, &a6));
        assert_se(in_addr_is_set(AF_INET6, &a6));
}

TEST(in_addr_is_localhost_generic) {
        union in_addr_union a;
        a.in.s_addr = htobe32((UINT32_C(127) << 24) | 1);
        assert_se(in_addr_is_localhost(AF_INET, &a));

        a.in.s_addr = htobe32(0x0a000001);
        assert_se(!in_addr_is_localhost(AF_INET, &a));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
