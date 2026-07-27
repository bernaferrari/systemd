/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "in-addr-util.h"
#include "tests.h"
#include <netinet/in.h>

/* Use htobe32 instead of htonl to avoid include ordering issues */
#include "macro.h"

TEST(in4_addr_is_null) {
        struct in_addr a;

        a = (struct in_addr){ .s_addr = 0 };
        ASSERT_TRUE(in4_addr_is_null(&a));

        a = (struct in_addr){ .s_addr = 1 };
        ASSERT_FALSE(in4_addr_is_null(&a));
}

TEST(in6_addr_is_null) {
        struct in6_addr a = {};

        ASSERT_TRUE(in6_addr_is_null(&a));

        a.s6_addr[0] = 1;
        ASSERT_FALSE(in6_addr_is_null(&a));
}

TEST(in4_addr_is_localhost) {
        struct in_addr a;

        /* 127.0.0.1 = 0x7F000001 in network byte order */
        a = (struct in_addr){ .s_addr = htobe32(0x7F000001) };
        ASSERT_TRUE(in4_addr_is_localhost(&a));

        /* 127.0.0.2 */
        a.s_addr = htobe32(0x7F000002);
        ASSERT_TRUE(in4_addr_is_localhost(&a));

        /* 8.8.8.8 */
        a.s_addr = htobe32(0x08080808);
        ASSERT_FALSE(in4_addr_is_localhost(&a));
}

TEST(in4_addr_is_link_local) {
        struct in_addr a;

        /* 169.254.1.1 */
        a.s_addr = htobe32(0xA9FE0101);
        ASSERT_TRUE(in4_addr_is_link_local(&a));

        /* 169.254.0.0 */
        a.s_addr = htobe32(0xA9FE0000);
        ASSERT_TRUE(in4_addr_is_link_local(&a));

        /* 10.0.0.1 */
        a.s_addr = htobe32(0x0A000001);
        ASSERT_FALSE(in4_addr_is_link_local(&a));
}

TEST(in4_addr_is_multicast) {
        struct in_addr a;

        /* 224.0.0.1 */
        a.s_addr = htobe32(0xE0000001);
        ASSERT_TRUE(in4_addr_is_multicast(&a));

        /* 239.255.255.255 */
        a.s_addr = htobe32(0xEFFFFFFF);
        ASSERT_TRUE(in4_addr_is_multicast(&a));

        /* 223.255.255.255 */
        a.s_addr = htobe32(0xDFFFFFFF);
        ASSERT_FALSE(in4_addr_is_multicast(&a));
}

TEST(in6_addr_is_link_local) {
        struct in6_addr a = {};

        /* fe80::1 */
        a.s6_addr[0] = 0xFE;
        a.s6_addr[1] = 0x80;
        a.s6_addr[15] = 0x01;
        ASSERT_TRUE(in6_addr_is_link_local(&a));

        /* 2001:db8::1 */
        a = (struct in6_addr){};
        a.s6_addr[0] = 0x20;
        a.s6_addr[1] = 0x01;
        ASSERT_FALSE(in6_addr_is_link_local(&a));
}

TEST(in6_addr_is_multicast) {
        struct in6_addr a = {};

        /* ff02::1 */
        a.s6_addr[0] = 0xFF;
        a.s6_addr[1] = 0x02;
        a.s6_addr[15] = 0x01;
        ASSERT_TRUE(in6_addr_is_multicast(&a));

        /* 2001:db8::1 */
        a = (struct in6_addr){};
        a.s6_addr[0] = 0x20;
        ASSERT_FALSE(in6_addr_is_multicast(&a));
}

TEST(in4_addr_equal) {
        struct in_addr a, b;

        a.s_addr = htobe32(0x0A000001);
        b.s_addr = htobe32(0x0A000001);
        ASSERT_TRUE(in4_addr_equal(&a, &b));

        b.s_addr = htobe32(0x0A000002);
        ASSERT_FALSE(in4_addr_equal(&a, &b));
}

TEST(in6_addr_equal) {
        struct in6_addr a = {}, b = {};

        a.s6_addr[0] = 1;
        b.s6_addr[0] = 1;
        ASSERT_TRUE(in6_addr_equal(&a, &b));

        b.s6_addr[0] = 2;
        ASSERT_FALSE(in6_addr_equal(&a, &b));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
