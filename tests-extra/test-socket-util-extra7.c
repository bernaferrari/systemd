/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <netinet/ip.h>

#include "socket-util.h"
#include "string-util.h"
#include "tests.h"

TEST(ip_tos_from_string_basic) {
        /* DECLARE_STRING_TABLE_LOOKUP_WITH_FALLBACK returns value directly */
        assert_se(ip_tos_from_string("low-delay") == IPTOS_LOWDELAY);
        assert_se(ip_tos_from_string("throughput") == IPTOS_THROUGHPUT);
        assert_se(ip_tos_from_string("reliability") == IPTOS_RELIABILITY);
}

TEST(netlink_family_from_string_basic) {
        /* DECLARE_STRING_TABLE_LOOKUP_WITH_FALLBACK returns value directly */
        assert_se(netlink_family_from_string("route") == NETLINK_ROUTE);
        assert_se(netlink_family_from_string("kobject-uevent") == NETLINK_KOBJECT_UEVENT);
}

TEST(socket_address_print_basic) {
        SocketAddress a = {};
        a.sockaddr.in.sin_family = AF_INET;
        a.sockaddr.in.sin_addr.s_addr = htobe32((UINT32_C(127) << 24) | 1);
        a.sockaddr.in.sin_port = htobe16(80);
        a.size = sizeof(struct sockaddr_in);
        a.type = SOCK_STREAM;

        _cleanup_free_ char *p = NULL;
        int r = socket_address_print(&a, &p);
        if (r >= 0) {
                assert_se(p);
                log_debug("socket_address_print: %s", p);
        }
}

TEST(socket_address_get_path_basic) {
        SocketAddress a = {};
        a.sockaddr.un.sun_family = AF_UNIX;
        strcpy(a.sockaddr.un.sun_path, "/tmp/test-socket");
        a.size = offsetof(struct sockaddr_un, sun_path) + strlen("/tmp/test-socket");
        a.type = SOCK_STREAM;

        const char *path = socket_address_get_path(&a);
        assert_se(path && streq(path, "/tmp/test-socket"));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
