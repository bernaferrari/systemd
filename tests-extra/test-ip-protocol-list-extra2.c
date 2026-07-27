/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <netinet/in.h>
#include "ip-protocol-list.h"
#include "string-util.h"
#include "tests.h"

TEST(ip_protocol_to_tcp_udp) {
        assert_se(streq(ip_protocol_to_tcp_udp(IPPROTO_TCP), "tcp"));
        assert_se(streq(ip_protocol_to_tcp_udp(IPPROTO_UDP), "udp"));
        assert_se(!ip_protocol_to_tcp_udp(IPPROTO_ICMP));
        assert_se(!ip_protocol_to_tcp_udp(IPPROTO_RAW));
}

TEST(ip_protocol_from_tcp_udp) {
        assert_se(ip_protocol_from_tcp_udp("tcp") == IPPROTO_TCP);
        assert_se(ip_protocol_from_tcp_udp("udp") == IPPROTO_UDP);
        assert_se(ip_protocol_from_tcp_udp("icmp") == -EINVAL);
        assert_se(ip_protocol_from_tcp_udp("raw") == -EINVAL);
}

TEST(parse_ip_protocol_full) {
        assert_se(parse_ip_protocol_full("tcp", false) == IPPROTO_TCP);
        assert_se(parse_ip_protocol_full("udp", false) == IPPROTO_UDP);
        assert_se(parse_ip_protocol_full("icmp", false) == IPPROTO_ICMP);
        assert_se(parse_ip_protocol_full("TCP", false) == IPPROTO_TCP);
        assert_se(parse_ip_protocol_full("6", false) == IPPROTO_TCP);
        assert_se(parse_ip_protocol_full("", false) == IPPROTO_IP);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
