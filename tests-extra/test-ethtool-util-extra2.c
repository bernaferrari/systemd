/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "ethtool-util.h"
#include "tests.h"

TEST(duplex_to_from_string) {
        assert_se(streq(duplex_to_string(DUP_FULL), "full"));
        assert_se(streq(duplex_to_string(DUP_HALF), "half"));

        assert_se(duplex_from_string("full") == DUP_FULL);
        assert_se(duplex_from_string("half") == DUP_HALF);
        assert_se(duplex_from_string("invalid") < 0);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
