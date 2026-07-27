/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "percent-util.h"
#include "tests.h"

TEST(parse_percent) {
        int p;
        /* parse_percent requires "%" suffix */
        p = parse_percent("0%");
        ASSERT_OK(p);
        ASSERT_EQ(p, 0);
        p = parse_percent("50%");
        ASSERT_OK(p);
        ASSERT_EQ(p, 50);
        p = parse_percent("100%");
        ASSERT_OK(p);
        ASSERT_EQ(p, 100);
        ASSERT_EQ(parse_percent("101%"), -ERANGE);
        ASSERT_EQ(parse_percent("-1%"), -ERANGE);
        ASSERT_EQ(parse_percent("abc"), -EINVAL);
}

TEST(parse_permille) {
        int p;
        p = parse_permille("0‰");
        ASSERT_OK(p);
        ASSERT_EQ(p, 0);
        p = parse_permille("500‰");
        ASSERT_OK(p);
        ASSERT_EQ(p, 500);
        p = parse_permille("1000‰");
        ASSERT_OK(p);
        ASSERT_EQ(p, 1000);
        ASSERT_EQ(parse_permille("1001‰"), -ERANGE);
}

TEST(parse_permyriad) {
        int p;
        p = parse_permyriad("0‱");
        ASSERT_OK(p);
        ASSERT_EQ(p, 0);
        p = parse_permyriad("5000‱");
        ASSERT_OK(p);
        ASSERT_EQ(p, 5000);
        p = parse_permyriad("10000‱");
        ASSERT_OK(p);
        ASSERT_EQ(p, 10000);
        ASSERT_EQ(parse_permyriad("10001‱"), -ERANGE);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
