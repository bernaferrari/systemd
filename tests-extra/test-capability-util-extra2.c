/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "capability-util.h"
#include "tests.h"

TEST(capability_is_set_basic) {
        assert_se(capability_is_set(0));
        assert_se(capability_is_set(1));
        assert_se(capability_is_set(UINT64_MAX - 1));
        /* CAP_MASK_UNSET is UINT64_MAX — that is the "unset" sentinel */
        assert_se(!capability_is_set(CAP_MASK_UNSET));
}

TEST(capability_quintet_is_set_any) {
        CapabilityQuintet q = CAPABILITY_QUINTET_NULL;
        /* All unset → is_set returns false */
        assert_se(!capability_quintet_is_set(&q));

        /* Set just one field */
        q.effective = 0;
        assert_se(capability_quintet_is_set(&q));

        /* Reset and set a different field */
        q = CAPABILITY_QUINTET_NULL;
        q.ambient = 1;
        assert_se(capability_quintet_is_set(&q));
}

TEST(capability_quintet_is_fully_set) {
        CapabilityQuintet q = CAPABILITY_QUINTET_NULL;
        /* All unset → is_fully_set returns false */
        assert_se(!capability_quintet_is_fully_set(&q));

        /* Set all fields */
        q.effective = 0;
        q.bounding = 0;
        q.inheritable = 0;
        q.permitted = 0;
        q.ambient = 0;
        assert_se(capability_quintet_is_fully_set(&q));

        /* Set 4 out of 5 → not fully set */
        q.ambient = CAP_MASK_UNSET;
        assert_se(!capability_quintet_is_fully_set(&q));
}

TEST(capability_quintet_equal_basic) {
        CapabilityQuintet a = CAPABILITY_QUINTET_NULL;
        CapabilityQuintet b = CAPABILITY_QUINTET_NULL;
        assert_se(capability_quintet_equal(&a, &b));

        a.effective = 42;
        assert_se(!capability_quintet_equal(&a, &b));

        b.effective = 42;
        assert_se(capability_quintet_equal(&a, &b));

        a.ambient = 1;
        assert_se(!capability_quintet_equal(&a, &b));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
