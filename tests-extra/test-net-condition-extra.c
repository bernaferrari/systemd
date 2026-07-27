/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "net-condition.h"
#include "tests.h"

TEST(net_match_is_empty) {
        NetMatch m = {};
        ASSERT_TRUE(net_match_is_empty(&m));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
