/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/sysmacros.h>

#include "hash-funcs.h"
#include "rust/bus_type_util.h"
#include "tests.h"

TEST(devt_compare_equal) {
        dev_t d = makedev(8, 1);
        assert_se(devt_compare_func(&d, &d) == 0);
}

TEST(devt_compare_less_by_minor) {
        dev_t d1 = makedev(8, 1);
        dev_t d2 = makedev(8, 2);
        assert_se(devt_compare_func(&d1, &d2) < 0);
        assert_se(devt_compare_func(&d2, &d1) > 0);
}

TEST(devt_compare_less_by_major) {
        dev_t d1 = makedev(7, 99);
        dev_t d2 = makedev(8, 0);
        assert_se(devt_compare_func(&d1, &d2) < 0);
        assert_se(devt_compare_func(&d2, &d1) > 0);
}

TEST(devt_compare_zero) {
        dev_t d1 = makedev(0, 0);
        dev_t d2 = makedev(0, 1);
        assert_se(devt_compare_func(&d1, &d2) < 0);
}

TEST(devt_compare_c_vs_rust) {
        dev_t d1 = makedev(8, 1);
        dev_t d2 = makedev(8, 2);
        dev_t d3 = makedev(7, 99);
        dev_t d4 = makedev(0, 0);
        dev_t d5 = makedev(254, 255);
        dev_t d6 = makedev(4095, 0);
        dev_t d7 = makedev(0, 1048575);

        /* Equal */
        assert_se(devt_compare_func(&d1, &d1) == rs_devt_compare_func(&d1, &d1));

        /* Less by minor */
        assert_se(devt_compare_func(&d1, &d2) == rs_devt_compare_func(&d1, &d2));

        /* Greater by minor */
        assert_se(devt_compare_func(&d2, &d1) == rs_devt_compare_func(&d2, &d1));

        /* Less by major */
        assert_se(devt_compare_func(&d3, &d1) == rs_devt_compare_func(&d3, &d1));

        /* Greater by major */
        assert_se(devt_compare_func(&d1, &d3) == rs_devt_compare_func(&d1, &d3));

        /* Zero */
        assert_se(devt_compare_func(&d4, &d4) == rs_devt_compare_func(&d4, &d4));

        /* Large values */
        assert_se(devt_compare_func(&d4, &d5) == rs_devt_compare_func(&d4, &d5));
        assert_se(devt_compare_func(&d5, &d4) == rs_devt_compare_func(&d5, &d4));

        /* Major ordering dominates even when the other value has max minor. */
        assert_se(devt_compare_func(&d6, &d7) == rs_devt_compare_func(&d6, &d7));
        assert_se(devt_compare_func(&d6, &d7) > 0);
        assert_se(devt_compare_func(&d7, &d6) == rs_devt_compare_func(&d7, &d6));
        assert_se(devt_compare_func(&d7, &d6) < 0);
}

DEFINE_TEST_MAIN(LOG_INFO);
