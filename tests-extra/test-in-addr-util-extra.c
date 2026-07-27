/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "in-addr-util.h"
#include "tests.h"

TEST(in4_addr_is_null) {
        struct in_addr a = {};
        ASSERT_TRUE(in4_addr_is_null(&a));
        a.s_addr = htobe32(1);
        ASSERT_FALSE(in4_addr_is_null(&a));
}

TEST(in4_addr_is_localhost) {
        struct in_addr a = {};
        a.s_addr = htobe32(INADDR_LOOPBACK);
        ASSERT_TRUE(in4_addr_is_localhost(&a));
        a.s_addr = htobe32(1);
        ASSERT_FALSE(in4_addr_is_localhost(&a));
}

TEST(in4_addr_is_multicast) {
        struct in_addr a = {};
        a.s_addr = htobe32(0xE0000001); /* 224.0.0.1 */
        ASSERT_TRUE(in4_addr_is_multicast(&a));
        a.s_addr = htobe32(1);
        ASSERT_FALSE(in4_addr_is_multicast(&a));
}

TEST(in4_addr_equal) {
        struct in_addr a = {}, b = {};
        ASSERT_TRUE(in4_addr_equal(&a, &b));
        a.s_addr = htobe32(1);
        ASSERT_FALSE(in4_addr_equal(&a, &b));
        b.s_addr = htobe32(1);
        ASSERT_TRUE(in4_addr_equal(&a, &b));
}

TEST(in6_addr_is_null) {
        struct in6_addr a = {};
        ASSERT_TRUE(in6_addr_is_null(&a));
        a.s6_addr[0] = 1;
        ASSERT_FALSE(in6_addr_is_null(&a));
}

TEST(in6_addr_is_multicast) {
        struct in6_addr a = {};
        a.s6_addr[0] = 0xff;
        ASSERT_TRUE(in6_addr_is_multicast(&a));
        a.s6_addr[0] = 0;
        ASSERT_FALSE(in6_addr_is_multicast(&a));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
