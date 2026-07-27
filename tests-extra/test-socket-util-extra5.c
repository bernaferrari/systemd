/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <net/if.h>
#include <netinet/in.h>

#include "in-addr-util.h"
#include "socket-util.h"
#include "string-util.h"
#include "tests.h"

TEST(ifname_valid_char_basic) {
        /* Valid characters */
        assert_se(ifname_valid_char('a'));
        assert_se(ifname_valid_char('Z'));
        assert_se(ifname_valid_char('0'));
        assert_se(ifname_valid_char('_'));
        assert_se(ifname_valid_char('-'));
        assert_se(ifname_valid_char('.'));

        /* Invalid characters */
        assert_se(!ifname_valid_char(':'));
        assert_se(!ifname_valid_char('/'));
        assert_se(!ifname_valid_char('%'));
        assert_se(!ifname_valid_char(' '));
        assert_se(!ifname_valid_char('\t'));
        assert_se(!ifname_valid_char('\n'));
        assert_se(!ifname_valid_char(127));  /* DEL */
        assert_se(!ifname_valid_char(0));    /* NUL */
}

TEST(ifname_valid_full_basic) {
        /* Valid names */
        assert_se(ifname_valid("eth0"));
        assert_se(ifname_valid("wlan0"));
        assert_se(ifname_valid("lo"));
        assert_se(ifname_valid("enp0s3"));
        assert_se(ifname_valid("a"));

        /* Invalid: empty */
        assert_se(!ifname_valid(""));

        /* Invalid: too long */
        char too_long[IFNAMSIZ + 1];
        memset(too_long, 'x', sizeof(too_long) - 1);
        too_long[sizeof(too_long) - 1] = '\0';
        assert_se(!ifname_valid(too_long));

        /* Invalid: contains colon */
        assert_se(!ifname_valid("eth0:1"));

        /* Invalid: contains slash */
        assert_se(!ifname_valid("eth/0"));

        /* Invalid: contains percent */
        assert_se(!ifname_valid("eth%0"));

        /* Invalid: . and .. */
        assert_se(!ifname_valid("."));
        assert_se(!ifname_valid(".."));

        /* Invalid: "all" and "default" */
        assert_se(!ifname_valid("all"));
        assert_se(!ifname_valid("default"));

        /* Valid with IFNAME_VALID_SPECIAL */
        assert_se(ifname_valid_full("all", IFNAME_VALID_SPECIAL));
        assert_se(ifname_valid_full("default", IFNAME_VALID_SPECIAL));
}

TEST(address_label_valid_basic) {
        assert_se(address_label_valid("test"));
        assert_se(address_label_valid("a"));

        /* Invalid: empty */
        assert_se(!address_label_valid(""));

        /* Invalid: too long */
        char too_long[IFNAMSIZ + 1];
        memset(too_long, 'x', sizeof(too_long) - 1);
        too_long[sizeof(too_long) - 1] = '\0';
        assert_se(!address_label_valid(too_long));
}

TEST(sockaddr_port_basic) {
        union sockaddr_union sa = {};
        unsigned port;
        int r;

        /* IPv4 */
        sa.in.sin_family = AF_INET;
        sa.in.sin_port = htobe16(80);
        r = sockaddr_port(&sa.sa, &port);
        assert_se(r >= 0);
        assert_se(port == 80);

        /* IPv6 */
        sa = (union sockaddr_union) {};
        sa.in6.sin6_family = AF_INET6;
        sa.in6.sin6_port = htobe16(443);
        r = sockaddr_port(&sa.sa, &port);
        assert_se(r >= 0);
        assert_se(port == 443);

        /* Unsupported family */
        sa = (union sockaddr_union) {};
        sa.sa.sa_family = AF_UNIX;
        r = sockaddr_port(&sa.sa, &port);
        assert_se(r == -EAFNOSUPPORT);
}

TEST(sockaddr_in_addr_basic) {
        union sockaddr_union sa = {};
        const union in_addr_union *addr;

        /* IPv4 */
        sa.in.sin_family = AF_INET;
        sa.in.sin_addr.s_addr = htobe32(0x7F000001);
        addr = sockaddr_in_addr(&sa.sa);
        assert_se(addr != NULL);
        assert_se(addr->in.s_addr == htobe32(0x7F000001));

        /* IPv6 */
        sa = (union sockaddr_union) {};
        sa.in6.sin6_family = AF_INET6;
        addr = sockaddr_in_addr(&sa.sa);
        assert_se(addr != NULL);

        /* NULL → NULL */
        assert_se(sockaddr_in_addr(NULL) == NULL);

        /* Unsupported family */
        sa = (union sockaddr_union) {};
        sa.sa.sa_family = AF_UNIX;
        addr = sockaddr_in_addr(&sa.sa);
        assert_se(addr == NULL);
}

TEST(sockaddr_set_in_addr_basic) {
        union sockaddr_union u = {};
        union in_addr_union a = {};
        int r;

        /* IPv4 */
        a.in.s_addr = htobe32(0x7F000001);
        r = sockaddr_set_in_addr(&u, AF_INET, &a, 80);
        assert_se(r >= 0);
        assert_se(u.in.sin_family == AF_INET);
        assert_se(u.in.sin_addr.s_addr == htobe32(0x7F000001));
        assert_se(be16toh(u.in.sin_port) == 80);

        /* IPv6 */
        u = (union sockaddr_union) {};
        r = sockaddr_set_in_addr(&u, AF_INET6, &a, 443);
        assert_se(r >= 0);
        assert_se(u.in6.sin6_family == AF_INET6);
        assert_se(be16toh(u.in6.sin6_port) == 443);
}

TEST(socket_address_can_accept_basic) {
        SocketAddress a = {};

        a.type = SOCK_STREAM;
        assert_se(socket_address_can_accept(&a));

        a.type = SOCK_DGRAM;
        assert_se(!socket_address_can_accept(&a));

        a.type = SOCK_SEQPACKET;
        assert_se(socket_address_can_accept(&a));
}

TEST(socket_address_get_path_basic) {
        SocketAddress a = {};

        /* AF_UNIX with path */
        a.sockaddr.sa.sa_family = AF_UNIX;
        strcpy(a.sockaddr.un.sun_path, "/tmp/test.sock");
        a.size = offsetof(struct sockaddr_un, sun_path) + strlen("/tmp/test.sock") + 1;
        assert_se(streq(socket_address_get_path(&a), "/tmp/test.sock"));

        /* Non-UNIX → NULL */
        a.sockaddr.sa.sa_family = AF_INET;
        assert_se(socket_address_get_path(&a) == NULL);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
