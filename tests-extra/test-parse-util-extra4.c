/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "parse-util.h"
#include "tests.h"

TEST(parse_boolean_basic) {
        /* True values */
        assert_se(parse_boolean("yes") > 0);
        assert_se(parse_boolean("y") > 0);
        assert_se(parse_boolean("true") > 0);
        assert_se(parse_boolean("t") > 0);
        assert_se(parse_boolean("on") > 0);
        assert_se(parse_boolean("1") > 0);

        /* False values */
        assert_se(parse_boolean("no") == 0);
        assert_se(parse_boolean("n") == 0);
        assert_se(parse_boolean("false") == 0);
        assert_se(parse_boolean("f") == 0);
        assert_se(parse_boolean("off") == 0);
        assert_se(parse_boolean("0") == 0);

        /* Invalid */
        assert_se(parse_boolean("maybe") < 0);
        assert_se(parse_boolean("invalid") < 0);
        assert_se(parse_boolean("") < 0);
}

TEST(parse_errno_roundtrip) {
        assert_se(parse_errno("EINVAL") == EINVAL);
        assert_se(parse_errno("ENOENT") == ENOENT);
        assert_se(parse_errno("ENOMEM") == ENOMEM);
        assert_se(parse_errno("EPERM") == EPERM);
        assert_se(parse_errno("invalid") < 0);
}

TEST(safe_atou_basic) {
        unsigned u;
        assert_se(safe_atou("42", &u) >= 0);
        assert_se(u == 42);
        assert_se(safe_atou("0", &u) >= 0);
        assert_se(u == 0);
        assert_se(safe_atou("4294967295", &u) >= 0);
        assert_se(u == 4294967295u);
        assert_se(safe_atou("", &u) < 0);
        assert_se(safe_atou("abc", &u) < 0);
}

TEST(safe_atoi_basic) {
        int i;
        assert_se(safe_atoi("42", &i) >= 0);
        assert_se(i == 42);
        assert_se(safe_atoi("-1", &i) >= 0);
        assert_se(i == -1);
        assert_se(safe_atoi("0", &i) >= 0);
        assert_se(i == 0);
        assert_se(safe_atoi("", &i) < 0);
        assert_se(safe_atoi("abc", &i) < 0);
}

TEST(safe_atollu_basic) {
        unsigned long long llu;
        assert_se(safe_atollu("12345678901234", &llu) >= 0);
        assert_se(llu == 12345678901234ULL);
        assert_se(safe_atollu("0", &llu) >= 0);
        assert_se(llu == 0);
        assert_se(safe_atollu("", &llu) < 0);
}

TEST(safe_atolli_basic) {
        long long lli;
        assert_se(safe_atolli("-9223372036854775807", &lli) >= 0);
        assert_se(lli == -9223372036854775807LL);
        assert_se(safe_atolli("0", &lli) >= 0);
        assert_se(lli == 0);
}

TEST(safe_atou16_basic) {
        uint16_t u16;
        assert_se(safe_atou16("65535", &u16) >= 0);
        assert_se(u16 == 65535);
        assert_se(safe_atou16("0", &u16) >= 0);
        assert_se(u16 == 0);
        assert_se(safe_atou16("65536", &u16) < 0);
}

TEST(safe_atoux16_basic) {
        uint16_t u16;
        assert_se(safe_atoux16("ff", &u16) >= 0);
        assert_se(u16 == 255);
        assert_se(safe_atoux16("FFFF", &u16) >= 0);
        assert_se(u16 == 65535);
        assert_se(safe_atoux16("0", &u16) >= 0);
        assert_se(u16 == 0);
}

TEST(safe_atod_basic) {
        double d;
        assert_se(safe_atod("3.14", &d) >= 0);
        assert_se(d > 3.13 && d < 3.15);
        assert_se(safe_atod("-1.5", &d) >= 0);
        assert_se(d > -1.51 && d < -1.49);
        assert_se(safe_atod("0", &d) >= 0);
        assert_se(d == 0.0);
        assert_se(safe_atod("", &d) < 0);
}

TEST(parse_nice_basic) {
        int nice_val;
        assert_se(parse_nice("0", &nice_val) >= 0);
        assert_se(nice_val == 0);
        assert_se(parse_nice("19", &nice_val) >= 0);
        assert_se(nice_val == 19);
        assert_se(parse_nice("-20", &nice_val) >= 0);
        assert_se(nice_val == -20);
        assert_se(parse_nice("20", &nice_val) < 0);
        assert_se(parse_nice("-21", &nice_val) < 0);
}

TEST(parse_ip_port_basic) {
        uint16_t port;
        assert_se(parse_ip_port("80", &port) >= 0);
        assert_se(port == 80);
        assert_se(parse_ip_port("443", &port) >= 0);
        assert_se(port == 443);
        assert_se(parse_ip_port("65535", &port) >= 0);
        assert_se(port == 65535);
        assert_se(parse_ip_port("1", &port) >= 0);
        assert_se(port == 1);
        assert_se(parse_ip_port("0", &port) < 0);
        assert_se(parse_ip_port("65536", &port) < 0);
}

TEST(parse_range_basic) {
        unsigned lower, upper;
        assert_se(parse_range("10-20", &lower, &upper) >= 0);
        assert_se(lower == 10);
        assert_se(upper == 20);
        assert_se(parse_range("5-5", &lower, &upper) >= 0);
        assert_se(lower == 5);
        assert_se(upper == 5);
        assert_se(parse_range("abc", &lower, &upper) < 0);
}

TEST(nft_identifier_valid_basic) {
        assert_se(nft_identifier_valid("valid_name"));
        assert_se(nft_identifier_valid("abc123"));
        assert_se(!nft_identifier_valid(""));
        assert_se(!nft_identifier_valid("has space"));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
