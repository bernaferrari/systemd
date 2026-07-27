/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "cgroup-setup.h"
#include "cgroup-util.h"
#include "tests.h"

TEST(cg_weight_parse_basic) {
        uint64_t val;

        assert_se(cg_weight_parse("1", &val) == 0);
        assert_se(val == 1);

        assert_se(cg_weight_parse("100", &val) == 0);
        assert_se(val == 100);

        assert_se(cg_weight_parse("10000", &val) == 0);
        assert_se(val == 10000);
}

TEST(cg_weight_parse_empty) {
        uint64_t val;

        assert_se(cg_weight_parse("", &val) == 0);
        assert_se(val == CGROUP_WEIGHT_INVALID);
}

TEST(cg_weight_parse_invalid) {
        uint64_t val;

        assert_se(cg_weight_parse("0", &val) == -ERANGE);
        assert_se(cg_weight_parse("10001", &val) == -ERANGE);
        assert_se(cg_weight_parse("-1", &val) < 0);
        assert_se(cg_weight_parse("abc", &val) < 0);
}

TEST(cg_cpu_weight_parse_basic) {
        uint64_t val;

        assert_se(cg_cpu_weight_parse("100", &val) == 0);
        assert_se(val == 100);

        assert_se(cg_cpu_weight_parse("1", &val) == 0);
        assert_se(val == 1);
}

TEST(cg_cpu_weight_parse_idle) {
        uint64_t val;

        assert_se(cg_cpu_weight_parse("idle", &val) == 0);
        assert_se(val == CGROUP_WEIGHT_IDLE);
}

TEST(cg_cpu_weight_parse_empty) {
        uint64_t val;

        assert_se(cg_cpu_weight_parse("", &val) == 0);
        assert_se(val == CGROUP_WEIGHT_INVALID);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
