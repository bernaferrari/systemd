/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <netinet/in.h>

#include "parse-helpers.h"
#include "string-util.h"
#include "tests.h"

TEST(parse_socket_bind_item) {
        int af, proto;
        uint16_t nr_ports, port_min;
        int r;

        /* IPv4 + TCP + port range */
        r = parse_socket_bind_item("ipv4:tcp:80-443", &af, &proto, &nr_ports, &port_min);
        assert_se(r >= 0);
        assert_se(af == AF_INET);
        assert_se(proto == IPPROTO_TCP);
        assert_se(nr_ports == 364);
        assert_se(port_min == 80);

        /* IPv6 + UDP + single port */
        r = parse_socket_bind_item("ipv6:udp:53", &af, &proto, &nr_ports, &port_min);
        assert_se(r >= 0);
        assert_se(af == AF_INET6);
        assert_se(proto == IPPROTO_UDP);
        assert_se(nr_ports == 1);
        assert_se(port_min == 53);

        /* Just port */
        r = parse_socket_bind_item("8080", &af, &proto, &nr_ports, &port_min);
        assert_se(r >= 0);
        assert_se(af == AF_UNSPEC);
        assert_se(nr_ports == 1);
        assert_se(port_min == 8080);

        /* TCP + port */
        r = parse_socket_bind_item("tcp:22", &af, &proto, &nr_ports, &port_min);
        assert_se(r >= 0);
        assert_se(proto == IPPROTO_TCP);
        assert_se(port_min == 22);

        /* Empty → error */
        assert_se(parse_socket_bind_item("", &af, &proto, &nr_ports, &port_min) == -EINVAL);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
