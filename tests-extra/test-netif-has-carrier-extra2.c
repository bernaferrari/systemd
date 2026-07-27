/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <net/if.h>
#include "tests.h"
#include "netif-util.h"

TEST(netif_has_carrier) {
        /* IF_OPER_UP → always has carrier */
        assert_se(netif_has_carrier(IF_OPER_UP, 0));
        assert_se(netif_has_carrier(IF_OPER_UP, IFF_UP));

        /* IF_OPER_DOWN or IF_OPER_TESTING → no carrier */
        assert_se(!netif_has_carrier(IF_OPER_DOWN, 0));
        assert_se(!netif_has_carrier(IF_OPER_TESTING, 0));
        assert_se(!netif_has_carrier(IF_OPER_DORMANT, 0));
        assert_se(!netif_has_carrier(IF_OPER_NOTPRESENT, 0));

        /* IF_OPER_UNKNOWN → fall back to flags */
        assert_se(netif_has_carrier(IF_OPER_UNKNOWN, IFF_LOWER_UP | IFF_RUNNING));
        assert_se(!netif_has_carrier(IF_OPER_UNKNOWN, 0));
        assert_se(!netif_has_carrier(IF_OPER_UNKNOWN, IFF_LOWER_UP));
        assert_se(!netif_has_carrier(IF_OPER_UNKNOWN, IFF_RUNNING));
        assert_se(!netif_has_carrier(IF_OPER_UNKNOWN, IFF_LOWER_UP | IFF_RUNNING | IFF_DORMANT));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
