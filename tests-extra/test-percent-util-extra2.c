/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "percent-util.h"
#include "tests.h"

TEST(parse_percent_basic) {
        assert_se(parse_percent("0%") == 0);
        assert_se(parse_percent("50%") == 50);
        assert_se(parse_percent("100%") == 100);
        assert_se(parse_percent("100") < 0);
        assert_se(parse_percent("101%") < 0);
        assert_se(parse_percent("-1%") < 0);
        assert_se(parse_percent("abc") < 0);
        assert_se(parse_percent("") < 0);
}

TEST(parse_percent_unbounded_basic) {
        assert_se(parse_percent_unbounded("0%") == 0);
        assert_se(parse_percent_unbounded("100%") == 100);
        assert_se(parse_percent_unbounded("200%") == 200);
        assert_se(parse_percent_unbounded("1000%") == 1000);
        assert_se(parse_percent_unbounded("100") < 0);
        assert_se(parse_percent_unbounded("abc") < 0);
}

TEST(parse_permille_basic) {
        assert_se(parse_permille("0‰") == 0);
        assert_se(parse_permille("500‰") == 500);
        assert_se(parse_permille("1000‰") == 1000);
        assert_se(parse_permille("1001‰") < 0);
        assert_se(parse_permille("500") < 0);
}

TEST(parse_permyriad_basic) {
        assert_se(parse_permyriad("0‱") == 0);
        assert_se(parse_permyriad("5000‱") == 5000);
        assert_se(parse_permyriad("10000‱") == 10000);
        assert_se(parse_permyriad("10001‱") < 0);
        assert_se(parse_permyriad("5000") < 0);
}

TEST(uint32_scale_from_percent_roundtrip) {
        uint32_t scaled = UINT32_SCALE_FROM_PERCENT(50);
        assert_se(scaled > 0);
        int back = UINT32_SCALE_TO_PERCENT(scaled);
        assert_se(back == 50);

        assert_se(UINT32_SCALE_TO_PERCENT(UINT32_SCALE_FROM_PERCENT(0)) == 0);
        assert_se(UINT32_SCALE_TO_PERCENT(UINT32_SCALE_FROM_PERCENT(100)) == 100);
}

TEST(uint32_scale_from_permille_roundtrip) {
        uint32_t scaled = UINT32_SCALE_FROM_PERMILLE(500);
        assert_se(scaled > 0);
        int back = UINT32_SCALE_TO_PERMILLE(scaled);
        assert_se(back == 500);

        assert_se(UINT32_SCALE_TO_PERMILLE(UINT32_SCALE_FROM_PERMILLE(0)) == 0);
        assert_se(UINT32_SCALE_TO_PERMILLE(UINT32_SCALE_FROM_PERMILLE(1000)) == 1000);
}

TEST(uint32_scale_from_permyriad_roundtrip) {
        uint32_t scaled = UINT32_SCALE_FROM_PERMYRIAD(5000);
        assert_se(scaled > 0);
        int back = UINT32_SCALE_TO_PERMYRIAD(scaled);
        assert_se(back == 5000);

        assert_se(UINT32_SCALE_TO_PERMYRIAD(UINT32_SCALE_FROM_PERMYRIAD(0)) == 0);
        assert_se(UINT32_SCALE_TO_PERMYRIAD(UINT32_SCALE_FROM_PERMYRIAD(10000)) == 10000);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
