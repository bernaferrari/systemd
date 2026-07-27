/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/if.h>

#include "netif-util.h"
#include "tests.h"

TEST(netif_has_carrier) {
        /* IF_OPER_UP (1) always has carrier */
        ASSERT_TRUE(netif_has_carrier(IF_OPER_UP, 0));
        /* IF_OPER_DOWN (2) never has carrier */
        ASSERT_FALSE(netif_has_carrier(IF_OPER_DOWN, 0));
        ASSERT_FALSE(netif_has_carrier(IF_OPER_DOWN, IFF_LOWER_UP));
        /* IF_OPER_UNKNOWN (0) falls back to flags */
        ASSERT_FALSE(netif_has_carrier(IF_OPER_UNKNOWN, 0));
        /* IFF_RUNNING alone is not enough */
        ASSERT_FALSE(netif_has_carrier(IF_OPER_UNKNOWN, IFF_RUNNING));
        /* Both IFF_LOWER_UP and IFF_RUNNING needed */
        ASSERT_TRUE(netif_has_carrier(IF_OPER_UNKNOWN, IFF_LOWER_UP | IFF_RUNNING));
        /* DORMANT overrides */
        ASSERT_FALSE(netif_has_carrier(IF_OPER_UNKNOWN, IFF_LOWER_UP | IFF_RUNNING | IFF_DORMANT));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
