/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <netinet/in.h>

#include "local-addresses.h"
#include "string-util.h"
#include "tests.h"

TEST(has_local_address) {
        struct local_address addrs[] = {
                { .family = AF_INET, .address.in.s_addr = htobe32(INADDR_LOOPBACK) },
                { .family = AF_INET, .address.in.s_addr = htobe32(0x0a000001) }, /* 10.0.0.1 */
        };
        struct local_address needle = {
                .family = AF_INET, .address.in.s_addr = htobe32(INADDR_LOOPBACK)
        };
        struct local_address needle2 = {
                .family = AF_INET, .address.in.s_addr = htobe32(0xc0a80001) /* 192.168.0.1 */
        };

        /* Found */
        assert_se(has_local_address(addrs, 2, &needle) == true);

        /* Not found */
        assert_se(has_local_address(addrs, 2, &needle2) == false);

        /* Empty list */
        assert_se(has_local_address(NULL, 0, &needle) == false);

        /* Single element match */
        assert_se(has_local_address(addrs, 1, &needle) == true);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
