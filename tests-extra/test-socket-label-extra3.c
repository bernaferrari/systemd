/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "socket-label.h"
#include "string-util.h"
#include "tests.h"

TEST(socket_address_bind_ipv6_only_to_from_string) {
        assert_se(streq(socket_address_bind_ipv6_only_to_string(SOCKET_ADDRESS_DEFAULT), "default"));
        assert_se(streq(socket_address_bind_ipv6_only_to_string(SOCKET_ADDRESS_BOTH), "both"));
        assert_se(streq(socket_address_bind_ipv6_only_to_string(SOCKET_ADDRESS_IPV6_ONLY), "ipv6-only"));

        assert_se(socket_address_bind_ipv6_only_from_string("default") == SOCKET_ADDRESS_DEFAULT);
        assert_se(socket_address_bind_ipv6_only_from_string("both") == SOCKET_ADDRESS_BOTH);
        assert_se(socket_address_bind_ipv6_only_from_string("ipv6-only") == SOCKET_ADDRESS_IPV6_ONLY);
        assert_se(socket_address_bind_ipv6_only_from_string("invalid") < 0);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
