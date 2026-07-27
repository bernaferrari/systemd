/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "capability-util.h"
#include "string-util.h"
#include "tests.h"

TEST(cap_last_cap_basic) {
        /* Should return a reasonable value */
        unsigned c = cap_last_cap();
        assert_se(c > 0);
        assert_se(c <= CAP_LIMIT);
}

TEST(all_capabilities_basic) {
        uint64_t all = all_capabilities();
        /* Should have at least CAP_CHOWN set */
        assert_se(FLAGS_SET(all, UINT64_C(1) << CAP_CHOWN));
        /* Should not be 0 or CAP_MASK_UNSET */
        assert_se(all != 0);
        assert_se(all != CAP_MASK_UNSET);
}

TEST(cap_test_all_basic) {
        uint64_t all = all_capabilities();
        assert_se(cap_test_all(all));

        /* Missing one cap → false */
        assert_se(!cap_test_all(all & ~(UINT64_C(1) << 0)));
}

TEST(capability_quintet_null) {
        CapabilityQuintet q = CAPABILITY_QUINTET_NULL;
        assert_se(q.effective == CAP_MASK_UNSET);
        assert_se(q.bounding == CAP_MASK_UNSET);
        assert_se(q.inheritable == CAP_MASK_UNSET);
        assert_se(q.permitted == CAP_MASK_UNSET);
        assert_se(q.ambient == CAP_MASK_UNSET);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
