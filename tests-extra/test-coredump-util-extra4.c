/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "coredump-util.h"
#include "string-util.h"
#include "tests.h"

TEST(coredump_filter_roundtrip) {
        for (int i = 0; i < _COREDUMP_FILTER_MAX; i++) {
                const char *s = coredump_filter_to_string(i);
                assert_se(s);
                CoredumpFilter v = coredump_filter_from_string(s);
                assert_se(v == i);
        }
}

TEST(coredump_filter_mask_from_string_basic) {
        uint64_t m;

        assert_se(coredump_filter_mask_from_string("private-anonymous", &m) >= 0);
        assert_se(m == (1u << COREDUMP_FILTER_PRIVATE_ANONYMOUS));

        assert_se(coredump_filter_mask_from_string("default", &m) >= 0);
        assert_se(m == COREDUMP_FILTER_MASK_DEFAULT);

        assert_se(coredump_filter_mask_from_string("all", &m) >= 0);
        assert_se(m == COREDUMP_FILTER_MASK_ALL);

        assert_se(coredump_filter_mask_from_string("private-anonymous shared-anonymous", &m) >= 0);
        assert_se(m == ((1u << COREDUMP_FILTER_PRIVATE_ANONYMOUS) | (1u << COREDUMP_FILTER_SHARED_ANONYMOUS)));

        /* Numeric */
        assert_se(coredump_filter_mask_from_string("0x33", &m) >= 0);
        assert_se(m == 0x33);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
