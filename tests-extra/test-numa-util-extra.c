/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "numa-util.h"
#include "tests.h"

TEST(mpol_to_string) {
        ASSERT_STREQ(mpol_to_string(MPOL_DEFAULT), "default");
        ASSERT_STREQ(mpol_to_string(MPOL_PREFERRED), "preferred");
        ASSERT_STREQ(mpol_to_string(MPOL_BIND), "bind");
        ASSERT_STREQ(mpol_to_string(MPOL_INTERLEAVE), "interleave");
        ASSERT_STREQ(mpol_to_string(MPOL_LOCAL), "local");
}

TEST(mpol_from_string) {
        ASSERT_EQ(mpol_from_string("default"), MPOL_DEFAULT);
        ASSERT_EQ(mpol_from_string("preferred"), MPOL_PREFERRED);
        ASSERT_EQ(mpol_from_string("bind"), MPOL_BIND);
        ASSERT_EQ(mpol_from_string("interleave"), MPOL_INTERLEAVE);
        ASSERT_EQ(mpol_from_string("local"), MPOL_LOCAL);
        ASSERT_EQ(mpol_from_string("invalid"), -EINVAL);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
