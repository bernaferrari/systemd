/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <netinet/ip.h>

#include "socket-util.h"
#include "string-util.h"
#include "tests.h"

TEST(ip_tos_from_string) {
        assert_se(ip_tos_from_string("low-delay") == IPTOS_LOWDELAY);
        assert_se(ip_tos_from_string("throughput") == IPTOS_THROUGHPUT);
        assert_se(ip_tos_from_string("reliability") == IPTOS_RELIABILITY);
        assert_se(ip_tos_from_string("low-cost") == IPTOS_LOWCOST);

        /* WITH_FALLBACK: numeric strings accepted */
        assert_se(ip_tos_from_string("0") == 0);
        assert_se(ip_tos_from_string("128") == 128);
        assert_se(ip_tos_from_string("255") == 255);
}

TEST(ip_tos_to_string_alloc) {
        _cleanup_free_ char *s = NULL;

        assert_se(ip_tos_to_string_alloc(IPTOS_LOWDELAY, &s) == 0);
        assert_se(streq(s, "low-delay"));

        s = mfree(s);
        assert_se(ip_tos_to_string_alloc(IPTOS_THROUGHPUT, &s) == 0);
        assert_se(streq(s, "throughput"));

        s = mfree(s);
        assert_se(ip_tos_to_string_alloc(IPTOS_RELIABILITY, &s) == 0);
        assert_se(streq(s, "reliability"));

        s = mfree(s);
        assert_se(ip_tos_to_string_alloc(IPTOS_LOWCOST, &s) == 0);
        assert_se(streq(s, "low-cost"));

        /* Fallback: numeric value not in table */
        s = mfree(s);
        assert_se(ip_tos_to_string_alloc(128, &s) == 0);
        assert_se(streq(s, "128"));
}

TEST(netlink_family_from_string) {
        assert_se(netlink_family_from_string("route") == NETLINK_ROUTE);
        assert_se(netlink_family_from_string("firewall") == NETLINK_FIREWALL);
        assert_se(netlink_family_from_string("xfrm") == NETLINK_XFRM);
        assert_se(netlink_family_from_string("audit") == NETLINK_AUDIT);
        assert_se(netlink_family_from_string("kobject-uevent") == NETLINK_KOBJECT_UEVENT);
        assert_se(netlink_family_from_string("generic") == NETLINK_GENERIC);
        assert_se(netlink_family_from_string("rdma") == NETLINK_RDMA);

        /* WITH_FALLBACK: numeric strings */
        assert_se(netlink_family_from_string("0") == 0);
}

TEST(netlink_family_to_string_alloc) {
        _cleanup_free_ char *s = NULL;

        assert_se(netlink_family_to_string_alloc(NETLINK_ROUTE, &s) == 0);
        assert_se(streq(s, "route"));

        s = mfree(s);
        assert_se(netlink_family_to_string_alloc(NETLINK_FIREWALL, &s) == 0);
        assert_se(streq(s, "firewall"));

        s = mfree(s);
        assert_se(netlink_family_to_string_alloc(NETLINK_AUDIT, &s) == 0);
        assert_se(streq(s, "audit"));

        s = mfree(s);
        assert_se(netlink_family_to_string_alloc(NETLINK_GENERIC, &s) == 0);
        assert_se(streq(s, "generic"));

        s = mfree(s);
        assert_se(netlink_family_to_string_alloc(NETLINK_RDMA, &s) == 0);
        assert_se(streq(s, "rdma"));
}

TEST(ifname_valid_char_basic) {
        assert_se(ifname_valid_char('a'));
        assert_se(ifname_valid_char('z'));
        assert_se(ifname_valid_char('0'));
        assert_se(ifname_valid_char('9'));
        assert_se(ifname_valid_char('-'));
        assert_se(ifname_valid_char('.'));

        assert_se(!ifname_valid_char('\0'));
        assert_se(!ifname_valid_char('\n'));
        assert_se(!ifname_valid_char(' '));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
