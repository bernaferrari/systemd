/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "net-condition.h"
#include "strv.h"
#include "tests.h"

TEST(net_match_is_empty) {
        NetMatch match = {};

        /* Freshly zeroed match is empty */
        assert_se(net_match_is_empty(&match));

        /* Set a strv field → not empty */
        match.driver = strv_new("e1000");
        assert_se(!net_match_is_empty(&match));
        net_match_clear(&match);
        assert_se(net_match_is_empty(&match));

        match.ifname = strv_new("eth0");
        assert_se(!net_match_is_empty(&match));
        net_match_clear(&match);

        match.path = strv_new("/sys/pci/*");
        assert_se(!net_match_is_empty(&match));
        net_match_clear(&match);

        match.property = strv_new("DRIVER=e1000");
        assert_se(!net_match_is_empty(&match));
        net_match_clear(&match);

        assert_se(net_match_is_empty(&match));
}

TEST(net_match_clear) {
        NetMatch match = {};

        match.driver = strv_new("e1000");
        match.ifname = strv_new("eth0");
        match.path = strv_new("/sys/pci/*");

        assert_se(!net_match_is_empty(&match));
        net_match_clear(&match);
        assert_se(net_match_is_empty(&match));

        /* Clearing NULL is safe */
        net_match_clear(NULL);

        /* Double clear is safe */
        net_match_clear(&match);
        assert_se(net_match_is_empty(&match));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
