/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "namespace-util.h"
#include "tests.h"

TEST(userns_shift_range_valid) {
        /* Normal valid range */
        assert_se(userns_shift_range_valid(0, 65536));
        assert_se(userns_shift_range_valid(1000, 1));
        assert_se(userns_shift_range_valid(65536, 65536));
        assert_se(userns_shift_range_valid(1000000, 65536));

        /* range == 0 is invalid */
        assert_se(!userns_shift_range_valid(0, 0));
        assert_se(!userns_shift_range_valid(1000, 0));

        /* Overflow: shift + range > UID_MAX */
        assert_se(!userns_shift_range_valid((uid_t) -1, 1));
        assert_se(!userns_shift_range_valid((uid_t) -5, 10));
        assert_se(!userns_shift_range_valid((uid_t) -65536, 65536));

        /* Edge case: shift + range == UID_MAX should be valid */
        assert_se(userns_shift_range_valid(0, (uid_t) -1));
        assert_se(userns_shift_range_valid(1, (uid_t) -2));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
