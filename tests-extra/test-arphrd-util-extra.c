/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/if_arp.h>

#include "arphrd-util.h"
#include "tests.h"

TEST(arphrd_to_hw_addr_len) {
        /* Common ARPHRD types */
        ASSERT_EQ(arphrd_to_hw_addr_len(ARPHRD_LOOPBACK), 0u);
        ASSERT_EQ(arphrd_to_hw_addr_len(ARPHRD_ETHER), 6u);
        ASSERT_EQ(arphrd_to_hw_addr_len(ARPHRD_INFINIBAND), 20u);
        /* Unknown type returns 0 */
        ASSERT_EQ(arphrd_to_hw_addr_len(0), 0u);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
