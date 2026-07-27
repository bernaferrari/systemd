/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <netinet/in.h>
#include <sys/socket.h>

#include "socket-util.h"
#include "string-util.h"
#include "tests.h"

TEST(ifname_valid_char_basic) {
        assert_se(ifname_valid_char('a'));
        assert_se(ifname_valid_char('Z'));
        assert_se(ifname_valid_char('0'));
        assert_se(ifname_valid_char('9'));
        assert_se(ifname_valid_char('-'));
        assert_se(ifname_valid_char('_'));
        assert_se(ifname_valid_char('.'));

        assert_se(!ifname_valid_char(':'));
        assert_se(!ifname_valid_char('/'));
        assert_se(!ifname_valid_char('%'));
        assert_se(!ifname_valid_char(' '));
        assert_se(!ifname_valid_char('\0'));
        assert_se(!ifname_valid_char('\n'));
        assert_se(!ifname_valid_char((char) 128));
}

TEST(address_label_valid_basic) {
        assert_se(address_label_valid("eth0"));
        assert_se(address_label_valid("myhost"));

        assert_se(!address_label_valid(""));
}

TEST(socket_address_can_accept_basic) {
        SocketAddress a = {
                .type = SOCK_STREAM,
                .size = sizeof(struct sockaddr_in),
        };
        assert_se(socket_address_can_accept(&a));

        a.type = SOCK_SEQPACKET;
        assert_se(socket_address_can_accept(&a));

        a.type = SOCK_DGRAM;
        assert_se(!socket_address_can_accept(&a));

        a.type = SOCK_RAW;
        assert_se(!socket_address_can_accept(&a));
}

TEST(sockaddr_equal_basic) {
        union sockaddr_union a = {}, b = {};

        a.in.sin_family = AF_INET;
        a.in.sin_addr.s_addr = htobe32(0x0a000001);
        b.in.sin_family = AF_INET;
        b.in.sin_addr.s_addr = htobe32(0x0a000001);
        assert_se(sockaddr_equal(&a, &b));

        b.in.sin_addr.s_addr = htobe32(0x0a000002);
        assert_se(!sockaddr_equal(&a, &b));

        /* Different families */
        b.in.sin_family = AF_INET6;
        assert_se(!sockaddr_equal(&a, &b));
}

TEST(vsock_cid_is_regular_basic) {
        assert_se(!VSOCK_CID_IS_REGULAR(0));
        assert_se(!VSOCK_CID_IS_REGULAR(1));
        assert_se(!VSOCK_CID_IS_REGULAR(2));
        assert_se(VSOCK_CID_IS_REGULAR(3));
        assert_se(VSOCK_CID_IS_REGULAR(100));
        assert_se(VSOCK_CID_IS_REGULAR(UINT32_MAX - 1));
        assert_se(!VSOCK_CID_IS_REGULAR(UINT32_MAX));
}

TEST(socket_ipv6_is_supported_basic) {
        /* Just exercise the function; result depends on system */
        (void) socket_ipv6_is_supported();
        log_debug("socket_ipv6_is_supported: %s", socket_ipv6_is_supported() ? "yes" : "no");
}

TEST(sockaddr_pretty_basic) {
        _cleanup_free_ char *p = NULL;
        struct sockaddr_in sa = {
                .sin_family = AF_INET,
                .sin_addr.s_addr = htobe32((127 << 24) | 1),
                .sin_port = htobe16(80),
        };

        int r = sockaddr_pretty((struct sockaddr *) &sa, sizeof(sa), true, true, &p);
        assert_se(r >= 0);
        assert_se(p);
        log_debug("sockaddr_pretty IPv4: %s", p);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
