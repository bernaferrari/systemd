/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "assert-util.h"
#include "tests.h"

TEST(assert_se_basic) {
        assert_se(true);
        assert_se(1);
        assert_se(1 == 1);
        assert_se(0 == 0);
}

TEST(assert_se_pointer) {
        void *p = (void*)1;
        assert_se(p);
        assert_se(p != NULL);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
