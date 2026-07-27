/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <netinet/in.h>

#include "ip-protocol-list.h"
#include "tests.h"

TEST(ip_protocol_to_from_name) {
        /* Names are generated as lowercase */
        assert_se(streq(ip_protocol_to_name(IPPROTO_TCP), "tcp"));
        assert_se(streq(ip_protocol_to_name(IPPROTO_UDP), "udp"));

        /* ip_protocol_from_name is case-sensitive gperf lookup (lowercase only) */
        assert_se(ip_protocol_from_name("tcp") == IPPROTO_TCP);
        assert_se(ip_protocol_from_name("udp") == IPPROTO_UDP);
        assert_se(ip_protocol_from_name("invalid") < 0);
}

TEST(parse_ip_protocol_full) {
        /* Empty string → IPPROTO_IP (0) */
        assert_se(parse_ip_protocol_full("", true) == IPPROTO_IP);

        /* Lowercase protocol names */
        assert_se(parse_ip_protocol_full("tcp", true) == IPPROTO_TCP);
        assert_se(parse_ip_protocol_full("udp", true) == IPPROTO_UDP);

        /* Uppercase gets lowered internally */
        assert_se(parse_ip_protocol_full("TCP", true) == IPPROTO_TCP);
        assert_se(parse_ip_protocol_full("UDP", true) == IPPROTO_UDP);

        /* Numeric strings */
        assert_se(parse_ip_protocol_full("6", true) == IPPROTO_TCP);
        assert_se(parse_ip_protocol_full("17", true) == IPPROTO_UDP);

        /* Relaxed mode: accepts unknown numeric protocols */
        assert_se(parse_ip_protocol_full("200", true) == 200);

        /* Strict mode: rejects unknown numeric protocols */
        assert_se(parse_ip_protocol_full("200", false) == -EPROTONOSUPPORT);

        /* Invalid */
        assert_se(parse_ip_protocol_full("invalid", true) < 0);
        assert_se(parse_ip_protocol_full("-1", true) == -ERANGE);
}

TEST(ip_protocol_to_tcp_udp) {
        assert_se(streq(ip_protocol_to_tcp_udp(IPPROTO_TCP), "tcp"));
        assert_se(streq(ip_protocol_to_tcp_udp(IPPROTO_UDP), "udp"));
        assert_se(!ip_protocol_to_tcp_udp(IPPROTO_ICMP));
}

TEST(ip_protocol_from_tcp_udp) {
        assert_se(ip_protocol_from_tcp_udp("tcp") == IPPROTO_TCP);
        assert_se(ip_protocol_from_tcp_udp("udp") == IPPROTO_UDP);
        assert_se(ip_protocol_from_tcp_udp("icmp") == -EINVAL);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
