/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "cgroup-util.h"
#include "tests.h"

TEST(cgroup_io_limit_type_roundtrip) {
        /* DECLARE_STRING_TABLE_LOOKUP returns value directly */
        for (CGroupIOLimitType i = 0; i < _CGROUP_IO_LIMIT_TYPE_MAX; i++) {
                const char *s = cgroup_io_limit_type_to_string(i);
                assert_se(s);
                assert_se(cgroup_io_limit_type_from_string(s) == i);
        }
}

TEST(cgroup_weight_is_ok_basic) {
        assert_se(CGROUP_WEIGHT_IS_OK(CGROUP_WEIGHT_DEFAULT));
        assert_se(CGROUP_WEIGHT_IS_OK(1));
        assert_se(CGROUP_WEIGHT_IS_OK(10000));
        assert_se(!CGROUP_WEIGHT_IS_OK(0));
        assert_se(!CGROUP_WEIGHT_IS_OK(10001));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
