/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <netinet/in.h>
#include <netinet/ip.h>
#include <stdlib.h>
#include <sys/socket.h>

#include "socket-util.h"
#include "tests.h"

TEST(socket_address_type_to_string) {
        ASSERT_STREQ(socket_address_type_to_string(SOCK_STREAM), "Stream");
        ASSERT_STREQ(socket_address_type_to_string(SOCK_DGRAM), "Datagram");
        ASSERT_STREQ(socket_address_type_to_string(SOCK_RAW), "Raw");
        ASSERT_STREQ(socket_address_type_to_string(SOCK_SEQPACKET), "SequentialPacket");
}

TEST(socket_address_type_from_string) {
        ASSERT_EQ(socket_address_type_from_string("Stream"), SOCK_STREAM);
        ASSERT_EQ(socket_address_type_from_string("Datagram"), SOCK_DGRAM);
        ASSERT_EQ(socket_address_type_from_string("Raw"), SOCK_RAW);
        ASSERT_EQ(socket_address_type_from_string("SequentialPacket"), SOCK_SEQPACKET);
}

TEST(netlink_family_to_string) {
        _cleanup_free_ char *s = NULL;

        ASSERT_OK(netlink_family_to_string_alloc(NETLINK_ROUTE, &s));
        ASSERT_STREQ(s, "route");

        s = mfree(s);
        ASSERT_OK(netlink_family_to_string_alloc(NETLINK_KOBJECT_UEVENT, &s));
        ASSERT_STREQ(s, "kobject-uevent");

        s = mfree(s);
        ASSERT_OK(netlink_family_to_string_alloc(NETLINK_GENERIC, &s));
        ASSERT_STREQ(s, "generic");
}

TEST(netlink_family_from_string) {
        ASSERT_EQ(netlink_family_from_string("route"), NETLINK_ROUTE);
        ASSERT_EQ(netlink_family_from_string("kobject-uevent"), NETLINK_KOBJECT_UEVENT);
        ASSERT_EQ(netlink_family_from_string("generic"), NETLINK_GENERIC);
        /* Fallback: unknown non-numeric string should return -EINVAL */
        ASSERT_EQ(netlink_family_from_string("invalid"), -EINVAL);
        /* Numeric fallback: "99" should be parsed as 99 */
        ASSERT_EQ(netlink_family_from_string("99"), 99);
}

TEST(ip_tos_to_string) {
        _cleanup_free_ char *s = NULL;

        ASSERT_OK(ip_tos_to_string_alloc(IPTOS_LOWDELAY, &s));
        ASSERT_STREQ(s, "low-delay");

        s = mfree(s);
        ASSERT_OK(ip_tos_to_string_alloc(IPTOS_THROUGHPUT, &s));
        ASSERT_STREQ(s, "throughput");

        s = mfree(s);
        ASSERT_OK(ip_tos_to_string_alloc(IPTOS_RELIABILITY, &s));
        ASSERT_STREQ(s, "reliability");

        s = mfree(s);
        ASSERT_OK(ip_tos_to_string_alloc(IPTOS_LOWCOST, &s));
        ASSERT_STREQ(s, "low-cost");
}

TEST(ip_tos_from_string) {
        ASSERT_EQ(ip_tos_from_string("low-delay"), IPTOS_LOWDELAY);
        ASSERT_EQ(ip_tos_from_string("throughput"), IPTOS_THROUGHPUT);
        ASSERT_EQ(ip_tos_from_string("reliability"), IPTOS_RELIABILITY);
        ASSERT_EQ(ip_tos_from_string("low-cost"), IPTOS_LOWCOST);
        /* Fallback: unknown non-numeric string should return -EINVAL */
        ASSERT_EQ(ip_tos_from_string("invalid"), -EINVAL);
        /* Numeric fallback: "0x10" should be parsed as 16 */
        ASSERT_EQ(ip_tos_from_string("0x10"), 0x10);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
