/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "socket-label.h"
#include "tests.h"

TEST(socket_address_bind_ipv6_only_to_string) {
        ASSERT_STREQ(socket_address_bind_ipv6_only_to_string(SOCKET_ADDRESS_DEFAULT), "default");
        ASSERT_STREQ(socket_address_bind_ipv6_only_to_string(SOCKET_ADDRESS_BOTH), "both");
        ASSERT_STREQ(socket_address_bind_ipv6_only_to_string(SOCKET_ADDRESS_IPV6_ONLY), "ipv6-only");
}

TEST(socket_address_bind_ipv6_only_from_string) {
        ASSERT_EQ(socket_address_bind_ipv6_only_from_string("default"), SOCKET_ADDRESS_DEFAULT);
        ASSERT_EQ(socket_address_bind_ipv6_only_from_string("both"), SOCKET_ADDRESS_BOTH);
        ASSERT_EQ(socket_address_bind_ipv6_only_from_string("ipv6-only"), SOCKET_ADDRESS_IPV6_ONLY);
        ASSERT_EQ(socket_address_bind_ipv6_only_from_string("invalid"), _SOCKET_ADDRESS_BIND_IPV6_ONLY_INVALID);
}

TEST(socket_address_bind_ipv6_only_or_bool_from_string) {
        /* Boolean true → IPV6_ONLY */
        ASSERT_EQ(socket_address_bind_ipv6_only_or_bool_from_string("1"), SOCKET_ADDRESS_IPV6_ONLY);
        ASSERT_EQ(socket_address_bind_ipv6_only_or_bool_from_string("yes"), SOCKET_ADDRESS_IPV6_ONLY);
        ASSERT_EQ(socket_address_bind_ipv6_only_or_bool_from_string("true"), SOCKET_ADDRESS_IPV6_ONLY);
        /* Boolean false → BOTH */
        ASSERT_EQ(socket_address_bind_ipv6_only_or_bool_from_string("0"), SOCKET_ADDRESS_BOTH);
        ASSERT_EQ(socket_address_bind_ipv6_only_or_bool_from_string("no"), SOCKET_ADDRESS_BOTH);
        ASSERT_EQ(socket_address_bind_ipv6_only_or_bool_from_string("false"), SOCKET_ADDRESS_BOTH);
        /* Named values fall through to regular from_string */
        ASSERT_EQ(socket_address_bind_ipv6_only_or_bool_from_string("default"), SOCKET_ADDRESS_DEFAULT);
        ASSERT_EQ(socket_address_bind_ipv6_only_or_bool_from_string("both"), SOCKET_ADDRESS_BOTH);
        ASSERT_EQ(socket_address_bind_ipv6_only_or_bool_from_string("ipv6-only"), SOCKET_ADDRESS_IPV6_ONLY);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
