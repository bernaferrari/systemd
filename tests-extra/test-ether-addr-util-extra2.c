/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <netinet/ether.h>
#include <string.h>

#include "ether-addr-util.h"
#include "tests.h"

TEST(parse_ether_addr_valid) {
        struct ether_addr addr;

        /* Colon-separated hex */
        assert_se(parse_ether_addr("01:02:03:04:05:06", &addr) == 0);
        assert_se(addr.ether_addr_octet[0] == 0x01);
        assert_se(addr.ether_addr_octet[5] == 0x06);

        /* Hyphen-separated hex */
        assert_se(parse_ether_addr("aa-bb-cc-dd-ee-ff", &addr) == 0);
        assert_se(addr.ether_addr_octet[0] == 0xaa);
        assert_se(addr.ether_addr_octet[5] == 0xff);
}

TEST(parse_ether_addr_invalid) {
        struct ether_addr addr;

        assert_se(parse_ether_addr("not-an-address", &addr) < 0);
        assert_se(parse_ether_addr("", &addr) < 0);
        assert_se(parse_ether_addr("01:02:03:04:05", &addr) < 0);   /* too short */
        assert_se(parse_ether_addr("01:02:03:04:05:06:07", &addr) < 0); /* too long */
}

TEST(ether_addr_to_string_basic) {
        struct ether_addr addr = {
                .ether_addr_octet = { 0xde, 0xad, 0xbe, 0xef, 0x00, 0x01 }
        };
        char buf[ETHER_ADDR_TO_STRING_MAX];
        const char *s;

        s = ether_addr_to_string(&addr, buf);
        assert_se(s == buf);
        assert_se(streq(s, "de:ad:be:ef:00:01"));
}

TEST(ether_addr_compare_basic) {
        struct ether_addr a = { .ether_addr_octet = { 1, 2, 3, 4, 5, 6 } };
        struct ether_addr b = { .ether_addr_octet = { 1, 2, 3, 4, 5, 6 } };
        struct ether_addr c = { .ether_addr_octet = { 1, 2, 3, 4, 5, 7 } };

        assert_se(ether_addr_compare(&a, &b) == 0);
        assert_se(ether_addr_compare(&a, &c) != 0);
        assert_se(ether_addr_equal(&a, &b));
        assert_se(!ether_addr_equal(&a, &c));
}

TEST(ether_addr_is_null_basic) {
        struct ether_addr zero = { .ether_addr_octet = { 0, 0, 0, 0, 0, 0 } };
        struct ether_addr nonzero = { .ether_addr_octet = { 1, 0, 0, 0, 0, 0 } };

        assert_se(ether_addr_is_null(&zero));
        assert_se(!ether_addr_is_null(&nonzero));
        assert_se(ether_addr_is_null(&ETHER_ADDR_NULL));
}

TEST(ether_addr_is_broadcast_basic) {
        struct ether_addr bcast = { .ether_addr_octet = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff } };
        struct ether_addr normal = { .ether_addr_octet = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 } };

        assert_se(ether_addr_is_broadcast(&bcast));
        assert_se(!ether_addr_is_broadcast(&normal));
}

TEST(ether_addr_is_multicast_unicast) {
        /* Multicast: least significant bit of first byte is set (0x01) */
        struct ether_addr mcast = { .ether_addr_octet = { 0x01, 0, 0, 0, 0, 0 } };
        struct ether_addr mcast2 = { .ether_addr_octet = { 0x03, 0, 0, 0, 0, 0 } };
        struct ether_addr ucast = { .ether_addr_octet = { 0x00, 0, 0, 0, 0, 0 } };
        struct ether_addr ucast2 = { .ether_addr_octet = { 0x02, 0, 0, 0, 0, 0 } };

        assert_se(ether_addr_is_multicast(&mcast));
        assert_se(ether_addr_is_multicast(&mcast2));
        assert_se(!ether_addr_is_multicast(&ucast));
        assert_se(!ether_addr_is_multicast(&ucast2));

        assert_se(!ether_addr_is_unicast(&mcast));
        assert_se(ether_addr_is_unicast(&ucast));
        assert_se(ether_addr_is_unicast(&ucast2));
}

TEST(ether_addr_is_local_global) {
        /* Local: second bit of first byte is set (0x02) */
        struct ether_addr local = { .ether_addr_octet = { 0x02, 0, 0, 0, 0, 0 } };
        struct ether_addr local2 = { .ether_addr_octet = { 0x06, 0, 0, 0, 0, 0 } };
        struct ether_addr global = { .ether_addr_octet = { 0x00, 0, 0, 0, 0, 0 } };
        struct ether_addr global2 = { .ether_addr_octet = { 0x01, 0, 0, 0, 0, 0 } };

        assert_se(ether_addr_is_local(&local));
        assert_se(ether_addr_is_local(&local2));
        assert_se(!ether_addr_is_local(&global));
        assert_se(!ether_addr_is_local(&global2));

        assert_se(!ether_addr_is_global(&local));
        assert_se(ether_addr_is_global(&global));
        assert_se(ether_addr_is_global(&global2));
}

TEST(ether_addr_roundtrip) {
        struct ether_addr addr = {
                .ether_addr_octet = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab }
        };
        char buf[ETHER_ADDR_TO_STRING_MAX];
        struct ether_addr parsed;

        const char *s = ether_addr_to_string(&addr, buf);
        assert_se(parse_ether_addr(s, &parsed) == 0);
        assert_se(ether_addr_equal(&addr, &parsed));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
