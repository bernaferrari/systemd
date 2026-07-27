/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/socket.h>

#include "parse-util.h"
#include "string-util.h"
#include "tests.h"

TEST(parse_ifindex) {
        int r;

        r = parse_ifindex("1");
        ASSERT_GE(r, 0);
        ASSERT_EQ(r, 1);

        r = parse_ifindex("42");
        ASSERT_GE(r, 0);
        ASSERT_EQ(r, 42);

        /* 0 is not a valid ifindex */
        r = parse_ifindex("0");
        ASSERT_EQ(r, -EINVAL);

        /* Negative is not valid — safe_atoi("-1") gives -1, but parse_ifindex rejects ifi <= 0 */
        r = parse_ifindex("-1");
        ASSERT_EQ(r, -EINVAL);

        /* Not a number */
        r = parse_ifindex("abc");
        ASSERT_EQ(r, -EINVAL);

        /* Empty */
        r = parse_ifindex("");
        ASSERT_EQ(r, -EINVAL);
}

TEST(parse_mtu) {
        uint32_t mtu;
        int r;

        /* IPv4 minimum MTU is 68 */
        r = parse_mtu(AF_INET, "1500", &mtu);
        ASSERT_EQ(r, 0);
        ASSERT_EQ(mtu, 1500);

        r = parse_mtu(AF_INET, "68", &mtu);
        ASSERT_EQ(r, 0);
        ASSERT_EQ(mtu, 68);

        /* Below IPv4 minimum */
        r = parse_mtu(AF_INET, "67", &mtu);
        ASSERT_EQ(r, -ERANGE);

        /* IPv6 minimum MTU is 1280 */
        r = parse_mtu(AF_INET6, "1500", &mtu);
        ASSERT_EQ(r, 0);
        ASSERT_EQ(mtu, 1500);

        r = parse_mtu(AF_INET6, "1280", &mtu);
        ASSERT_EQ(r, 0);
        ASSERT_EQ(mtu, 1280);

        /* Below IPv6 minimum */
        r = parse_mtu(AF_INET6, "1279", &mtu);
        ASSERT_EQ(r, -ERANGE);

        /* AF_UNSPEC has no minimum */
        r = parse_mtu(AF_UNSPEC, "1", &mtu);
        ASSERT_EQ(r, 0);
        ASSERT_EQ(mtu, 1);

        /* With K suffix */
        r = parse_mtu(AF_INET, "4K", &mtu);
        ASSERT_EQ(r, 0);
        ASSERT_EQ(mtu, 4096);

        /* Not a number */
        r = parse_mtu(AF_INET, "abc", &mtu);
        ASSERT_LT(r, 0);
}

TEST(parse_sector_size) {
        uint64_t ss;
        int r;

        r = parse_sector_size("512", &ss);
        ASSERT_EQ(r, 0);
        ASSERT_EQ(ss, 512);

        r = parse_sector_size("4096", &ss);
        ASSERT_EQ(r, 0);
        ASSERT_EQ(ss, 4096);

        r = parse_sector_size("1024", &ss);
        ASSERT_EQ(r, 0);
        ASSERT_EQ(ss, 1024);

        /* Too small */
        r = parse_sector_size("256", &ss);
        ASSERT_EQ(r, -ERANGE);

        /* Too large */
        r = parse_sector_size("8192", &ss);
        ASSERT_EQ(r, -ERANGE);

        /* Not a power of 2 */
        r = parse_sector_size("1000", &ss);
        ASSERT_EQ(r, -EINVAL);

        /* Not a number */
        r = parse_sector_size("abc", &ss);
        ASSERT_LT(r, 0);
}

TEST(parse_user_shell) {
        _cleanup_free_ char *sh = NULL;
        bool copy;
        int r;

        /* Absolute path returns copy=false */
        r = parse_user_shell("/bin/bash", &sh, &copy);
        ASSERT_EQ(r, 0);
        ASSERT_STREQ(sh, "/bin/bash");
        ASSERT_EQ(copy, false);
        sh = mfree(sh);

        /* Boolean "yes" returns copy=true */
        r = parse_user_shell("yes", &sh, &copy);
        ASSERT_EQ(r, 0);
        ASSERT_NULL(sh);
        ASSERT_EQ(copy, true);

        /* Boolean "no" returns copy=false */
        r = parse_user_shell("no", &sh, &copy);
        ASSERT_EQ(r, 0);
        ASSERT_NULL(sh);
        ASSERT_EQ(copy, false);

        /* Boolean "1" returns copy=true */
        r = parse_user_shell("1", &sh, &copy);
        ASSERT_EQ(r, 0);
        ASSERT_NULL(sh);
        ASSERT_EQ(copy, true);

        /* Boolean "0" returns copy=false */
        r = parse_user_shell("0", &sh, &copy);
        ASSERT_EQ(r, 0);
        ASSERT_NULL(sh);
        ASSERT_EQ(copy, false);

        /* Non-normalized path is treated as boolean, fails if invalid */
        r = parse_user_shell("relative/path", &sh, &copy);
        ASSERT_LT(r, 0);

        /* Invalid boolean */
        r = parse_user_shell("maybe", &sh, &copy);
        ASSERT_LT(r, 0);
}

TEST(safe_atou_bounded) {
        unsigned v;
        int r;

        r = safe_atou_bounded("5", 1, 10, &v);
        ASSERT_EQ(r, 0);
        ASSERT_EQ(v, 5);

        r = safe_atou_bounded("1", 1, 10, &v);
        ASSERT_EQ(r, 0);
        ASSERT_EQ(v, 1);

        r = safe_atou_bounded("10", 1, 10, &v);
        ASSERT_EQ(r, 0);
        ASSERT_EQ(v, 10);

        /* Below min */
        r = safe_atou_bounded("0", 1, 10, &v);
        ASSERT_EQ(r, -ERANGE);

        /* Above max */
        r = safe_atou_bounded("11", 1, 10, &v);
        ASSERT_EQ(r, -ERANGE);

        /* Not a number */
        r = safe_atou_bounded("abc", 1, 10, &v);
        ASSERT_EQ(r, -EINVAL);
}

TEST(safe_atou8_full) {
        uint8_t v;
        int r;

        r = safe_atou8_full("42", 0, &v);
        ASSERT_EQ(r, 0);
        ASSERT_EQ(v, 42);

        r = safe_atou8_full("255", 0, &v);
        ASSERT_EQ(r, 0);
        ASSERT_EQ(v, 255);

        /* Overflow */
        r = safe_atou8_full("256", 0, &v);
        ASSERT_EQ(r, -ERANGE);

        /* Hex */
        r = safe_atou8_full("ff", 16, &v);
        ASSERT_EQ(r, 0);
        ASSERT_EQ(v, 255);

        /* REFUSE_LEADING_ZERO */
        r = safe_atou8_full("042", SAFE_ATO_REFUSE_LEADING_ZERO, &v);
        ASSERT_EQ(r, -EINVAL);

        /* 0 itself is fine */
        r = safe_atou8_full("0", SAFE_ATO_REFUSE_LEADING_ZERO, &v);
        ASSERT_EQ(r, 0);
        ASSERT_EQ(v, 0);

        /* 0b prefix for binary */
        r = safe_atou8_full("0b1010", 0, &v);
        ASSERT_EQ(r, 0);
        ASSERT_EQ(v, 10);
}

TEST(safe_atou16_full) {
        uint16_t v;
        int r;

        r = safe_atou16_full("1000", 0, &v);
        ASSERT_EQ(r, 0);
        ASSERT_EQ(v, 1000);

        r = safe_atou16_full("65535", 0, &v);
        ASSERT_EQ(r, 0);
        ASSERT_EQ(v, 65535);

        /* Overflow */
        r = safe_atou16_full("65536", 0, &v);
        ASSERT_EQ(r, -ERANGE);

        /* Hex */
        r = safe_atou16_full("ffff", 16, &v);
        ASSERT_EQ(r, 0);
        ASSERT_EQ(v, 65535);

        /* REFUSE_LEADING_ZERO */
        r = safe_atou16_full("0xff", SAFE_ATO_REFUSE_LEADING_ZERO, &v);
        ASSERT_EQ(r, -EINVAL);
}

TEST(safe_atoi16) {
        int16_t v;
        int r;

        r = safe_atoi16("1000", &v);
        ASSERT_EQ(r, 0);
        ASSERT_EQ(v, 1000);

        r = safe_atoi16("-1000", &v);
        ASSERT_EQ(r, 0);
        ASSERT_EQ(v, -1000);

        r = safe_atoi16("32767", &v);
        ASSERT_EQ(r, 0);
        ASSERT_EQ(v, 32767);

        r = safe_atoi16("-32768", &v);
        ASSERT_EQ(r, 0);
        ASSERT_EQ(v, -32768);

        /* Overflow */
        r = safe_atoi16("32768", &v);
        ASSERT_EQ(r, -ERANGE);

        r = safe_atoi16("-32769", &v);
        ASSERT_EQ(r, -ERANGE);

        /* Not a number */
        r = safe_atoi16("abc", &v);
        ASSERT_EQ(r, -EINVAL);
}

TEST(safe_atolli) {
        long long v;
        int r;

        r = safe_atolli("1234567890123", &v);
        ASSERT_EQ(r, 0);
        assert_se(v == 1234567890123LL);

        r = safe_atolli("-9876543210", &v);
        ASSERT_EQ(r, 0);
        assert_se(v == -9876543210LL);

        r = safe_atolli("0", &v);
        ASSERT_EQ(r, 0);
        assert_se(v == 0);

        /* Hex with 0x prefix */
        r = safe_atolli("0xff", &v);
        ASSERT_EQ(r, 0);
        assert_se(v == 255);

        /* Octal with 0o prefix */
        r = safe_atolli("0o77", &v);
        ASSERT_EQ(r, 0);
        assert_se(v == 63);

        /* Binary with 0b prefix */
        r = safe_atolli("0b1010", &v);
        ASSERT_EQ(r, 0);
        assert_se(v == 10);

        /* Not a number */
        r = safe_atolli("abc", &v);
        ASSERT_EQ(r, -EINVAL);
}

TEST(safe_atollu_full) {
        unsigned long long v;
        int r;

        r = safe_atollu_full("18446744073709551614", 0, &v);
        ASSERT_EQ(r, 0);
        assert_se(v == 18446744073709551614ULL);

        r = safe_atollu_full("0", 0, &v);
        ASSERT_EQ(r, 0);
        assert_se(v == 0);

        /* Hex */
        r = safe_atollu_full("0xff", 0, &v);
        ASSERT_EQ(r, 0);
        assert_se(v == 255);

        /* REFUSE_PLUS_MINUS */
        r = safe_atollu_full("10", SAFE_ATO_REFUSE_PLUS_MINUS, &v);
        ASSERT_EQ(r, 0);
        assert_se(v == 10);

        r = safe_atollu_full("-10", SAFE_ATO_REFUSE_PLUS_MINUS, &v);
        ASSERT_EQ(r, -EINVAL);

        r = safe_atollu_full("+10", SAFE_ATO_REFUSE_PLUS_MINUS, &v);
        ASSERT_EQ(r, -EINVAL);

        /* REFUSE_LEADING_ZERO */
        r = safe_atollu_full("010", SAFE_ATO_REFUSE_LEADING_ZERO, &v);
        ASSERT_EQ(r, -EINVAL);

        r = safe_atollu_full("0", SAFE_ATO_REFUSE_LEADING_ZERO, &v);
        ASSERT_EQ(r, 0);
        assert_se(v == 0);

        /* REFUSE_LEADING_WHITESPACE */
        r = safe_atollu_full(" 10", SAFE_ATO_REFUSE_LEADING_WHITESPACE, &v);
        ASSERT_EQ(r, -EINVAL);

        r = safe_atollu_full("10", SAFE_ATO_REFUSE_LEADING_WHITESPACE, &v);
        ASSERT_EQ(r, 0);
        assert_se(v == 10);
}

TEST(parse_fractional_part_u) {
        const char *p;
        unsigned val;
        int r;

        /* Simple 3-digit fractional part */
        p = "500ms";
        r = parse_fractional_part_u(&p, 3, &val);
        ASSERT_EQ(r, 0);
        assert_se(val == 500);
        ASSERT_STREQ(p, "ms");

        /* Fewer digits than requested — padded with 0 */
        p = "5ms";
        r = parse_fractional_part_u(&p, 3, &val);
        ASSERT_EQ(r, 0);
        assert_se(val == 500); /* 5 → 500 */
        ASSERT_STREQ(p, "ms");

        /* Rounding */
        p = "5678s";
        r = parse_fractional_part_u(&p, 3, &val);
        ASSERT_EQ(r, 0);
        assert_se(val == 568); /* 567.8 rounds up to 568 */
        ASSERT_STREQ(p, "s");

        /* No digits */
        p = "ms";
        r = parse_fractional_part_u(&p, 3, &val);
        ASSERT_EQ(r, -EINVAL);

        /* All zeros */
        p = "000x";
        r = parse_fractional_part_u(&p, 3, &val);
        ASSERT_EQ(r, 0);
        assert_se(val == 0);
        ASSERT_STREQ(p, "x");

        /* 9 rounds up */
        p = "999s";
        r = parse_fractional_part_u(&p, 2, &val);
        ASSERT_EQ(r, 0);
        assert_se(val == 100); /* 99.9 rounds up to 100 */
        ASSERT_STREQ(p, "s");
}

DEFINE_TEST_MAIN(LOG_INFO);
