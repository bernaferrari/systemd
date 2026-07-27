/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "parse-util.h"
#include "tests.h"

TEST(safe_atou) {
        unsigned u;
        ASSERT_OK(safe_atou("123", &u));
        ASSERT_EQ(u, 123);
        ASSERT_OK(safe_atou("0", &u));
        ASSERT_EQ(u, 0);
        ASSERT_EQ(safe_atou("-1", &u), -ERANGE);
        ASSERT_EQ(safe_atou("abc", &u), -EINVAL);
        ASSERT_EQ(safe_atou("", &u), -EINVAL);
}

TEST(safe_atoi) {
        int i;
        ASSERT_OK(safe_atoi("42", &i));
        ASSERT_EQ(i, 42);
        ASSERT_OK(safe_atoi("-7", &i));
        ASSERT_EQ(i, -7);
        ASSERT_OK(safe_atoi("0", &i));
        ASSERT_EQ(i, 0);
        ASSERT_EQ(safe_atoi("abc", &i), -EINVAL);
}

TEST(safe_atou64) {
        uint64_t u;
        ASSERT_OK(safe_atou64("18446744073709551615", &u));
        ASSERT_EQ(u, UINT64_MAX);
        ASSERT_OK(safe_atou64("0", &u));
        ASSERT_EQ(u, 0);
        ASSERT_EQ(safe_atou64("-1", &u), -ERANGE);
        ASSERT_EQ(safe_atou64("abc", &u), -EINVAL);
}

TEST(safe_atoi64) {
        int64_t i;
        ASSERT_OK(safe_atoi64("9223372036854775807", &i));
        ASSERT_EQ(i, INT64_MAX);
        ASSERT_OK(safe_atoi64("-9223372036854775808", &i));
        ASSERT_EQ(i, INT64_MIN);
        ASSERT_EQ(safe_atoi64("abc", &i), -EINVAL);
}

TEST(safe_atolu) {
        unsigned long u;
        ASSERT_OK(safe_atolu("12345", &u));
        ASSERT_EQ(u, 12345UL);
        ASSERT_EQ(safe_atolu("-1", &u), -ERANGE);
}

TEST(safe_atou32) {
        uint32_t u;
        ASSERT_OK(safe_atou32("4294967295", &u));
        ASSERT_EQ(u, UINT32_MAX);
        ASSERT_OK(safe_atou32("0", &u));
        ASSERT_EQ(u, 0);
        ASSERT_EQ(safe_atou32("4294967296", &u), -ERANGE);
}

TEST(safe_atoi32) {
        int32_t i;
        ASSERT_OK(safe_atoi32("2147483647", &i));
        ASSERT_EQ(i, INT32_MAX);
        ASSERT_OK(safe_atoi32("-2147483648", &i));
        ASSERT_EQ(i, INT32_MIN);
        ASSERT_EQ(safe_atoi32("2147483648", &i), -ERANGE);
}

TEST(safe_atou16) {
        uint16_t u;
        ASSERT_OK(safe_atou16("65535", &u));
        ASSERT_EQ(u, 65535);
        ASSERT_EQ(safe_atou16("65536", &u), -ERANGE);
        ASSERT_EQ(safe_atou16("-1", &u), -ERANGE);
}

TEST(safe_atou8) {
        uint8_t u;
        ASSERT_OK(safe_atou8("255", &u));
        ASSERT_EQ(u, 255);
        ASSERT_EQ(safe_atou8("256", &u), -ERANGE);
        ASSERT_EQ(safe_atou8("-1", &u), -ERANGE);
}

TEST(parse_errno) {
        int r;
        /* parse_errno takes 1 arg, returns int directly */
        r = parse_errno("0");
        ASSERT_OK(r);
        ASSERT_EQ(r, 0);
        r = parse_errno("2");
        ASSERT_OK(r);
        ASSERT_EQ(r, 2);
        r = parse_errno("ENOENT");
        ASSERT_OK(r);
        ASSERT_EQ(r, ENOENT);
        r = parse_errno("EINVAL");
        ASSERT_OK(r);
        ASSERT_EQ(r, EINVAL);
        ASSERT_EQ(parse_errno("invalid"), -EINVAL);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
