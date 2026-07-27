/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <netinet/in.h>
#include <netinet/ip.h>

#include "in-addr-util.h"
#include "socket-util.h"
#include "string-util.h"
#include "tests.h"

TEST(socket_address_type_to_string_basic) {
        assert_se(streq(socket_address_type_to_string(SOCK_STREAM), "Stream"));
        assert_se(streq(socket_address_type_to_string(SOCK_DGRAM), "Datagram"));
        assert_se(streq(socket_address_type_to_string(SOCK_RAW), "Raw"));
        assert_se(streq(socket_address_type_to_string(SOCK_SEQPACKET), "SequentialPacket"));

        /* Reverse lookups */
        assert_se(socket_address_type_from_string("Stream") == SOCK_STREAM);
        assert_se(socket_address_type_from_string("Datagram") == SOCK_DGRAM);
        assert_se(socket_address_type_from_string("Raw") == SOCK_RAW);
        assert_se(socket_address_type_from_string("SequentialPacket") == SOCK_SEQPACKET);
        assert_se(socket_address_type_from_string("invalid") < 0);
}

TEST(netlink_family_from_string_basic) {
        assert_se(netlink_family_from_string("route") >= 0);
        assert_se(netlink_family_from_string("kobject-uevent") >= 0);
        assert_se(netlink_family_from_string("invalid") < 0);

        /* Numeric fallback */
        assert_se(netlink_family_from_string("0") >= 0);
        assert_se(netlink_family_from_string("15") >= 0);
}

TEST(ip_tos_from_string_basic) {
        assert_se(ip_tos_from_string("low-delay") == IPTOS_LOWDELAY);
        assert_se(ip_tos_from_string("throughput") == IPTOS_THROUGHPUT);
        assert_se(ip_tos_from_string("reliability") == IPTOS_RELIABILITY);
        assert_se(ip_tos_from_string("invalid") < 0);

        /* Numeric fallback */
        assert_se(ip_tos_from_string("0") == 0);
}

TEST(socket_address_equal_basic) {
        SocketAddress a = {}, b = {};

        a.sockaddr.sa.sa_family = AF_INET;
        a.size = sizeof(struct sockaddr_in);
        a.type = SOCK_STREAM;
        a.protocol = 0;
        a.sockaddr.in.sin_addr.s_addr = htobe32(0x7F000001);
        a.sockaddr.in.sin_port = htobe16(80);

        b = a;
        assert_se(socket_address_equal(&a, &b));

        /* Different port → not equal */
        b.sockaddr.in.sin_port = htobe16(443);
        assert_se(!socket_address_equal(&a, &b));
}

TEST(sockaddr_equal_basic) {
        union sockaddr_union a = {}, b = {};

        a.sa.sa_family = AF_INET;
        a.in.sin_addr.s_addr = htobe32(0x7F000001);
        a.in.sin_port = htobe16(80);

        b = a;
        assert_se(sockaddr_equal(&a, &b));

        /* Different address → not equal */
        b.in.sin_addr.s_addr = htobe32(0x7F000002);
        assert_se(!sockaddr_equal(&a, &b));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
