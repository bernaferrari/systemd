/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <netinet/in.h>

#include "af-list.h"
#include "tests.h"

TEST(af_to_name_basic) {
        /* af_to_name returns the AF_* name string */
        assert_se(af_to_name(AF_INET));
        assert_se(af_to_name(AF_INET6));
        assert_se(af_to_name(AF_UNIX));
        assert_se(af_to_name(AF_NETLINK));
        assert_se(!af_to_name(0));
        assert_se(!af_to_name(-1));
}

TEST(af_to_name_short_basic) {
        /* af_to_name_short strips the AF_ prefix */
        assert_se(streq(af_to_name_short(AF_INET), "INET"));
        assert_se(streq(af_to_name_short(AF_INET6), "INET6"));
        assert_se(streq(af_to_name_short(AF_UNIX), "UNIX"));
        assert_se(streq(af_to_name_short(AF_NETLINK), "NETLINK"));
        assert_se(streq(af_to_name_short(AF_UNSPEC), "*"));
        assert_se(streq(af_to_name_short(99999), "unknown"));
}

TEST(af_from_name_basic) {
        assert_se(af_from_name("AF_INET") == AF_INET);
        assert_se(af_from_name("AF_INET6") == AF_INET6);
        assert_se(af_from_name("AF_UNIX") == AF_UNIX);
        assert_se(af_from_name("AF_NETLINK") == AF_NETLINK);
        assert_se(af_from_name("invalid") == -EINVAL);
}

TEST(af_to_ipv4_ipv6_basic) {
        assert_se(streq(af_to_ipv4_ipv6(AF_INET), "ipv4"));
        assert_se(streq(af_to_ipv4_ipv6(AF_INET6), "ipv6"));
        assert_se(af_to_ipv4_ipv6(AF_UNIX) == NULL);
}

TEST(af_from_ipv4_ipv6_basic) {
        assert_se(af_from_ipv4_ipv6("ipv4") == AF_INET);
        assert_se(af_from_ipv4_ipv6("ipv6") == AF_INET6);
        assert_se(af_from_ipv4_ipv6("unix") == AF_UNSPEC);
}

TEST(af_name_roundtrip) {
        assert_se(af_from_name(af_to_name(AF_INET)) == AF_INET);
        assert_se(af_from_name(af_to_name(AF_INET6)) == AF_INET6);
        assert_se(af_from_name(af_to_name(AF_UNIX)) == AF_UNIX);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
