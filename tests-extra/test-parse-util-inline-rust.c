/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Shadow test: parse-util.h inline wrapper functions vs Rust */

#include <assert.h>
#include <stdint.h>
#include <string.h>
#include "tests.h"
#include "parse-util.h"
#include "rust/parse_util.h"

static void test_safe_atou8(void) {
        uint8_t c_r, rs_r;
        int c_ret, rs_ret;

        c_ret = safe_atou8("42", &c_r);
        rs_ret = rs_safe_atou8("42", &rs_r);
        assert_se(c_ret == rs_ret && c_ret == 0);
        assert_se(c_r == rs_r && c_r == 42);

        c_ret = safe_atou8("255", &c_r);
        rs_ret = rs_safe_atou8("255", &rs_r);
        assert_se(c_ret == rs_ret && c_ret == 0);
        assert_se(c_r == rs_r && c_r == 255);

        c_ret = safe_atou8("256", &c_r);
        rs_ret = rs_safe_atou8("256", &rs_r);
        assert_se(c_ret == rs_ret && c_ret < 0);

        c_ret = safe_atou8("abc", &c_r);
        rs_ret = rs_safe_atou8("abc", &rs_r);
        assert_se(c_ret == rs_ret && c_ret < 0);
}

static void test_safe_atou16(void) {
        uint16_t c_r, rs_r;
        int c_ret, rs_ret;

        c_ret = safe_atou16("1000", &c_r);
        rs_ret = rs_safe_atou16("1000", &rs_r);
        assert_se(c_ret == rs_ret && c_ret == 0);
        assert_se(c_r == rs_r && c_r == 1000);

        c_ret = safe_atou16("65535", &c_r);
        rs_ret = rs_safe_atou16("65535", &rs_r);
        assert_se(c_ret == rs_ret && c_ret == 0);

        c_ret = safe_atou16("65536", &c_r);
        rs_ret = rs_safe_atou16("65536", &rs_r);
        assert_se(c_ret == rs_ret && c_ret < 0);
}

static void test_safe_atoux16(void) {
        uint16_t c_r, rs_r;
        int c_ret, rs_ret;

        c_ret = safe_atoux16("ff", &c_r);
        rs_ret = rs_safe_atoux16("ff", &rs_r);
        assert_se(c_ret == rs_ret && c_ret == 0);
        assert_se(c_r == rs_r && c_r == 255);

        c_ret = safe_atoux16("FF", &c_r);
        rs_ret = rs_safe_atoux16("FF", &rs_r);
        assert_se(c_ret == rs_ret && c_ret == 0);

        c_ret = safe_atoux16("10000", &c_r);
        rs_ret = rs_safe_atoux16("10000", &rs_r);
        assert_se(c_ret == rs_ret && c_ret < 0);  /* 0x10000 overflows uint16_t */
}

static void test_safe_atou32(void) {
        uint32_t c_r, rs_r;
        int c_ret, rs_ret;

        c_ret = safe_atou32("12345", &c_r);
        rs_ret = rs_safe_atou32("12345", &rs_r);
        assert_se(c_ret == rs_ret && c_ret == 0);
        assert_se(c_r == rs_r && c_r == 12345);

        c_ret = safe_atou32("4294967295", &c_r);
        rs_ret = rs_safe_atou32("4294967295", &rs_r);
        assert_se(c_ret == rs_ret && c_ret == 0);

        c_ret = safe_atou32("4294967296", &c_r);
        rs_ret = rs_safe_atou32("4294967296", &rs_r);
        assert_se(c_ret == rs_ret && c_ret < 0);
}

static void test_safe_atoi32(void) {
        int32_t c_r, rs_r;
        int c_ret, rs_ret;

        c_ret = safe_atoi32("-42", &c_r);
        rs_ret = rs_safe_atoi32("-42", &rs_r);
        assert_se(c_ret == rs_ret && c_ret == 0);
        assert_se(c_r == rs_r && c_r == -42);

        c_ret = safe_atoi32("2147483647", &c_r);
        rs_ret = rs_safe_atoi32("2147483647", &rs_r);
        assert_se(c_ret == rs_ret && c_ret == 0);

        c_ret = safe_atoi32("abc", &c_r);
        rs_ret = rs_safe_atoi32("abc", &rs_r);
        assert_se(c_ret == rs_ret && c_ret < 0);
}

static void test_safe_atolu(void) {
        unsigned long c_r, rs_r;
        int c_ret, rs_ret;

        c_ret = safe_atolu("1234567890", &c_r);
        rs_ret = rs_safe_atolu("1234567890", &rs_r);
        assert_se(c_ret == rs_ret && c_ret == 0);
        assert_se(c_r == rs_r);

        c_ret = safe_atolu("abc", &c_r);
        rs_ret = rs_safe_atolu("abc", &rs_r);
        assert_se(c_ret == rs_ret && c_ret < 0);
}

static void test_safe_atoli(void) {
        long c_r, rs_r;
        int c_ret, rs_ret;

        c_ret = safe_atoli("-1234567890", &c_r);
        rs_ret = rs_safe_atoli("-1234567890", &rs_r);
        assert_se(c_ret == rs_ret && c_ret == 0);
        assert_se(c_r == rs_r);

        c_ret = safe_atoli("abc", &c_r);
        rs_ret = rs_safe_atoli("abc", &rs_r);
        assert_se(c_ret == rs_ret && c_ret < 0);
}

static void test_safe_atozu(void) {
        size_t c_r, rs_r;
        int c_ret, rs_ret;

        c_ret = safe_atozu("99999", &c_r);
        rs_ret = rs_safe_atozu("99999", &rs_r);
        assert_se(c_ret == rs_ret && c_ret == 0);
        assert_se(c_r == rs_r && c_r == 99999);

        c_ret = safe_atozu("abc", &c_r);
        rs_ret = rs_safe_atozu("abc", &rs_r);
        assert_se(c_ret == rs_ret && c_ret < 0);
}

static void test_parse_tristate(void) {
        int c_r, rs_r;
        int c_ret, rs_ret;

        c_ret = parse_tristate("true", &c_r);
        rs_ret = rs_parse_tristate("true", &rs_r);
        assert_se(c_ret == rs_ret && c_ret == 0);
        assert_se(c_r == rs_r);

        c_ret = parse_tristate("false", &c_r);
        rs_ret = rs_parse_tristate("false", &rs_r);
        assert_se(c_ret == rs_ret && c_ret == 0);
        assert_se(c_r == rs_r);

        c_ret = parse_tristate("1", &c_r);
        rs_ret = rs_parse_tristate("1", &rs_r);
        assert_se(c_ret == rs_ret && c_ret == 0);

        c_ret = parse_tristate("0", &c_r);
        rs_ret = rs_parse_tristate("0", &rs_r);
        assert_se(c_ret == rs_ret && c_ret == 0);

        c_ret = parse_tristate("invalid", &c_r);
        rs_ret = rs_parse_tristate("invalid", &rs_r);
        assert_se(c_ret == rs_ret && c_ret < 0);
}

int main(int argc, char **argv) {
        test_safe_atou8();
        test_safe_atou16();
        test_safe_atoux16();
        test_safe_atou32();
        test_safe_atoi32();
        test_safe_atolu();
        test_safe_atoli();
        test_safe_atozu();
        test_parse_tristate();
        return 0;
}
