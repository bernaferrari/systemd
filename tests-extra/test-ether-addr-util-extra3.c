/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <net/ethernet.h>
#include <string.h>

#include "ether-addr-util.h"
#include "string-util.h"
#include "tests.h"

TEST(ether_addr_to_string) {
        struct ether_addr addr = { .ether_addr_octet = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55} };
        char buf[ETHER_ADDR_TO_STRING_MAX];

        assert_se(streq(ether_addr_to_string(&addr, buf), "00:11:22:33:44:55"));

        /* All zeros */
        struct ether_addr zero = {};
        assert_se(streq(ether_addr_to_string(&zero, buf), "00:00:00:00:00:00"));

        /* All ff (broadcast) */
        struct ether_addr broadcast = { .ether_addr_octet = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff} };
        assert_se(streq(ether_addr_to_string(&broadcast, buf), "ff:ff:ff:ff:ff:ff"));
}

TEST(ether_addr_compare) {
        struct ether_addr a = { .ether_addr_octet = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55} };
        struct ether_addr b = { .ether_addr_octet = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55} };
        struct ether_addr c = { .ether_addr_octet = {0x00, 0x11, 0x22, 0x33, 0x44, 0x56} };

        assert_se(ether_addr_compare(&a, &b) == 0);
        assert_se(ether_addr_compare(&a, &c) < 0);
        assert_se(ether_addr_compare(&c, &a) > 0);
}

TEST(ether_addr_is_broadcast) {
        struct ether_addr broadcast = { .ether_addr_octet = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff} };
        struct ether_addr normal = { .ether_addr_octet = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55} };
        struct ether_addr zero = {};

        assert_se(ether_addr_is_broadcast(&broadcast));
        assert_se(!ether_addr_is_broadcast(&normal));
        assert_se(!ether_addr_is_broadcast(&zero));
}

TEST(parse_ether_addr) {
        struct ether_addr ret;
        int r;

        /* Valid MAC addresses */
        r = parse_ether_addr("00:11:22:33:44:55", &ret);
        assert_se(r == 0);
        assert_se(ret.ether_addr_octet[0] == 0x00);
        assert_se(ret.ether_addr_octet[5] == 0x55);

        r = parse_ether_addr("ff:ff:ff:ff:ff:ff", &ret);
        assert_se(r == 0);
        assert_se(ret.ether_addr_octet[0] == 0xff);

        /* Hyphen separated */
        r = parse_ether_addr("00-11-22-33-44-55", &ret);
        assert_se(r == 0);
        assert_se(ret.ether_addr_octet[5] == 0x55);

        /* Invalid */
        r = parse_ether_addr("invalid", &ret);
        assert_se(r < 0);

        r = parse_ether_addr("", &ret);
        assert_se(r < 0);
}

TEST(ether_addr_mark_random) {
        struct ether_addr addr = { .ether_addr_octet = {0xff, 0x00, 0x00, 0x00, 0x00, 0x00} };

        ether_addr_mark_random(&addr);
        /* Multicast bit (bit 0 of first octet) should be cleared */
        assert_se(!(addr.ether_addr_octet[0] & 0x01));
        /* Local assignment bit (bit 1 of first octet) should be set */
        assert_se(addr.ether_addr_octet[0] & 0x02);
}

TEST(hw_addr_is_null) {
        struct hw_addr_data zero = {};
        struct hw_addr_data nonzero = { .length = 6, .bytes = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55} };
        struct hw_addr_data allzero = { .length = 6, .bytes = {0, 0, 0, 0, 0, 0} };

        assert_se(hw_addr_is_null(&zero));
        assert_se(!hw_addr_is_null(&nonzero));
        assert_se(hw_addr_is_null(&allzero));
}

TEST(hw_addr_compare) {
        struct hw_addr_data a = { .length = 6, .bytes = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55} };
        struct hw_addr_data b = { .length = 6, .bytes = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55} };
        struct hw_addr_data c = { .length = 6, .bytes = {0x00, 0x11, 0x22, 0x33, 0x44, 0x56} };
        struct hw_addr_data d = { .length = 4, .bytes = {0x00, 0x11, 0x22, 0x33} };

        assert_se(hw_addr_compare(&a, &b) == 0);
        assert_se(hw_addr_compare(&a, &c) < 0);
        assert_se(hw_addr_compare(&c, &a) > 0);
        /* Different lengths: shorter < longer */
        assert_se(hw_addr_compare(&d, &a) < 0);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
