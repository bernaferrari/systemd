/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "ether-addr-util.h"
#include "tests.h"

TEST(parse_ether_addr) {
        struct ether_addr addr;

        ASSERT_OK(parse_ether_addr("00:11:22:33:44:55", &addr));
        ASSERT_EQ(addr.ether_addr_octet[0], 0x00);
        ASSERT_EQ(addr.ether_addr_octet[1], 0x11);
        ASSERT_EQ(addr.ether_addr_octet[5], 0x55);

        /* Uppercase */
        ASSERT_OK(parse_ether_addr("AA:BB:CC:DD:EE:FF", &addr));
        ASSERT_EQ(addr.ether_addr_octet[0], 0xAA);
        ASSERT_EQ(addr.ether_addr_octet[5], 0xFF);

        /* Mixed case with leading zeros */
        ASSERT_OK(parse_ether_addr("0a:0B:0c:0D:0e:0F", &addr));
        ASSERT_EQ(addr.ether_addr_octet[0], 0x0a);

        /* Invalid: too short */
        ASSERT_LT(parse_ether_addr("00:11:22", &addr), 0);

        /* Invalid: bad characters */
        ASSERT_LT(parse_ether_addr("gg:hh:ii:jj:kk:ll", &addr), 0);

        /* Invalid: empty */
        ASSERT_LT(parse_ether_addr("", &addr), 0);
}

TEST(ether_addr_to_string) {
        struct ether_addr addr;
        char buf[ETHER_ADDR_TO_STRING_MAX];

        addr = (struct ether_addr){ .ether_addr_octet = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 } };
        ASSERT_STREQ(ether_addr_to_string(&addr, buf), "00:11:22:33:44:55");

        addr = (struct ether_addr){ .ether_addr_octet = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF } };
        ASSERT_STREQ(ether_addr_to_string(&addr, buf), "ff:ff:ff:ff:ff:ff");
}

TEST(ether_addr_compare) {
        struct ether_addr a = { .ether_addr_octet = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 } };
        struct ether_addr b = { .ether_addr_octet = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 } };
        struct ether_addr c = { .ether_addr_octet = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x56 } };

        ASSERT_EQ(ether_addr_compare(&a, &b), 0);
        ASSERT_LT(ether_addr_compare(&a, &c), 0);
        ASSERT_GT(ether_addr_compare(&c, &a), 0);
}

TEST(ether_addr_is_broadcast) {
        struct ether_addr bcast = { .ether_addr_octet = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF } };
        struct ether_addr not_bcast = { .ether_addr_octet = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 } };

        ASSERT_TRUE(ether_addr_is_broadcast(&bcast));
        ASSERT_FALSE(ether_addr_is_broadcast(&not_bcast));
}

TEST(hw_addr_is_null) {
        struct hw_addr_data addr = { .length = 6 };

        ASSERT_TRUE(hw_addr_is_null(&addr));

        addr.bytes[0] = 1;
        ASSERT_FALSE(hw_addr_is_null(&addr));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
