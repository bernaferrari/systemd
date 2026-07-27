/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "in-addr-util.h"
#include "tests.h"
#include <netinet/in.h>
#include "macro.h"

TEST(in4_addr_is_null) {
        struct in_addr a = { .s_addr = htobe32(0x00000000) };
        ASSERT_TRUE(in4_addr_is_null(&a));

        a.s_addr = htobe32(0x7F000001);
        ASSERT_FALSE(in4_addr_is_null(&a));
}

TEST(in4_addr_is_multicast) {
        struct in_addr a = { .s_addr = htobe32(0xE0000001) }; /* 224.0.0.1 */
        ASSERT_TRUE(in4_addr_is_multicast(&a));

        a.s_addr = htobe32(0x01020304);
        ASSERT_FALSE(in4_addr_is_multicast(&a));
}

TEST(in4_addr_is_link_local) {
        struct in_addr a = { .s_addr = htobe32(0xA9FE0102) }; /* 169.254.1.2 */
        ASSERT_TRUE(in4_addr_is_link_local(&a));

        a.s_addr = htobe32(0x0A000001); /* 10.0.0.1 */
        ASSERT_FALSE(in4_addr_is_link_local(&a));
}

TEST(in6_addr_is_null) {
        struct in6_addr a = IN6ADDR_ANY_INIT;
        ASSERT_TRUE(in6_addr_is_null(&a));

        struct in6_addr b = {{{ 1 }}};
        ASSERT_FALSE(in6_addr_is_null(&b));
}

TEST(in6_addr_is_multicast) {
        struct in6_addr a = {{{ 0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 }}};
        ASSERT_TRUE(in6_addr_is_multicast(&a));

        struct in6_addr b = IN6ADDR_ANY_INIT;
        ASSERT_FALSE(in6_addr_is_multicast(&b));
}

TEST(in6_addr_is_link_local) {
        struct in6_addr a = {{{ 0xfe, 0x80 }}};
        ASSERT_TRUE(in6_addr_is_link_local(&a));

        struct in6_addr b = IN6ADDR_ANY_INIT;
        ASSERT_FALSE(in6_addr_is_link_local(&b));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
