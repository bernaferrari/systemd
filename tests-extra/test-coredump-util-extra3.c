/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "coredump-util.h"
#include "tests.h"

TEST(coredump_filter_mask_from_string) {
        uint64_t m;

        assert_se(coredump_filter_mask_from_string("private-anonymous", &m) >= 0);
        assert_se(m == (UINT64_C(1) << COREDUMP_FILTER_PRIVATE_ANONYMOUS));

        assert_se(coredump_filter_mask_from_string("shared-anonymous shared-huge", &m) >= 0);
        assert_se(FLAGS_SET(m, UINT64_C(1) << COREDUMP_FILTER_SHARED_ANONYMOUS));
        assert_se(FLAGS_SET(m, UINT64_C(1) << COREDUMP_FILTER_SHARED_HUGE));

        assert_se(coredump_filter_mask_from_string("default", &m) >= 0);
        assert_se(m == COREDUMP_FILTER_MASK_DEFAULT);

        assert_se(coredump_filter_mask_from_string("all", &m) >= 0);
        assert_se(m == COREDUMP_FILTER_MASK_ALL);

        assert_se(coredump_filter_mask_from_string("invalid", &m) < 0);
}

TEST(coredump_filter_roundtrip) {
        for (int i = 0; i < _COREDUMP_FILTER_MAX; i++) {
                const char *s = coredump_filter_to_string(i);
                if (s) {
                        int v = coredump_filter_from_string(s);
                        assert_se(v == i);
                }
        }
}

DEFINE_TEST_MAIN(LOG_DEBUG);
