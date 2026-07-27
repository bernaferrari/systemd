/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "numa-util.h"
#include "tests.h"

TEST(mpol_to_from_string) {
        assert_se(streq(mpol_to_string(MPOL_DEFAULT), "default"));
        assert_se(streq(mpol_to_string(MPOL_PREFERRED), "preferred"));
        assert_se(streq(mpol_to_string(MPOL_BIND), "bind"));
        assert_se(streq(mpol_to_string(MPOL_INTERLEAVE), "interleave"));
        assert_se(streq(mpol_to_string(MPOL_LOCAL), "local"));

        assert_se(mpol_from_string("default") == MPOL_DEFAULT);
        assert_se(mpol_from_string("preferred") == MPOL_PREFERRED);
        assert_se(mpol_from_string("bind") == MPOL_BIND);
        assert_se(mpol_from_string("interleave") == MPOL_INTERLEAVE);
        assert_se(mpol_from_string("local") == MPOL_LOCAL);
        assert_se(mpol_from_string("invalid") < 0);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
