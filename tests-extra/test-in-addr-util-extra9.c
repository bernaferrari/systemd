/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <netinet/in.h>
#include <string.h>

#include "in-addr-util.h"
#include "string-util.h"
#include "tests.h"

TEST(in_addr_from_string) {
        union in_addr_union u;
        int r;

        /* Valid IPv4 */
        r = in_addr_from_string(AF_INET, "192.168.1.1", &u);
        assert_se(r >= 0);
        assert_se(u.in.s_addr == htobe32(0xC0A80101));

        /* Valid IPv6 */
        r = in_addr_from_string(AF_INET6, "::1", &u);
        assert_se(r >= 0);
        assert_se(u.in6.s6_addr[15] == 1);

        r = in_addr_from_string(AF_INET6, "fe80::1", &u);
        assert_se(r >= 0);
        assert_se(u.in6.s6_addr[0] == 0xfe);
        assert_se(u.in6.s6_addr[1] == 0x80);

        /* Invalid address */
        assert_se(in_addr_from_string(AF_INET, "not.an.ip", &u) < 0);
        assert_se(in_addr_from_string(AF_INET6, "not::ipv6", &u) < 0);

        /* Unsupported family */
        assert_se(in_addr_from_string(AF_UNIX, "anything", &u) < 0);
}

TEST(in_addr_from_string_auto) {
        union in_addr_union u;
        int family;
        int r;

        /* Auto-detect IPv4 */
        r = in_addr_from_string_auto("10.0.0.1", &family, &u);
        assert_se(r >= 0);
        assert_se(family == AF_INET);
        assert_se(u.in.s_addr == htobe32(0x0A000001));

        /* Auto-detect IPv6 */
        r = in_addr_from_string_auto("::1", &family, &u);
        assert_se(r >= 0);
        assert_se(family == AF_INET6);

        /* Invalid */
        assert_se(in_addr_from_string_auto("not-an-address", &family, &u) < 0);
}

TEST(typesafe_inet_ntop4) {
        struct in_addr a;
        char buf[INET_ADDRSTRLEN];
        const char *r;

        a.s_addr = htobe32(0xC0A80101);
        r = typesafe_inet_ntop4(&a, buf, sizeof(buf));
        assert_se(r);
        assert_se(streq(r, "192.168.1.1"));

        a.s_addr = htobe32(0x7F000001);
        r = typesafe_inet_ntop4(&a, buf, sizeof(buf));
        assert_se(r);
        assert_se(streq(r, "127.0.0.1"));
}

TEST(typesafe_inet_ntop6) {
        struct in6_addr a = {};
        char buf[INET6_ADDRSTRLEN];
        const char *r;

        /* ::1 */
        a.s6_addr[15] = 1;
        r = typesafe_inet_ntop6(&a, buf, sizeof(buf));
        assert_se(r);
        assert_se(streq(r, "::1"));
}

TEST(in_addr_prefix_next_ipv4) {
        union in_addr_union u = {};
        int r;

        /* 192.168.1.0/24 → next is 192.168.2.0 */
        u.in.s_addr = htobe32(0xC0A80100);
        r = in_addr_prefix_next(AF_INET, &u, 24);
        assert_se(r >= 0);
        assert_se(u.in.s_addr == htobe32(0xC0A80200));

        /* 192.168.255.0/24 → next is 192.168.256.0 but that overflows to 192.169.0.0 */
        u.in.s_addr = htobe32(0xC0A8FF00);
        r = in_addr_prefix_next(AF_INET, &u, 24);
        /* 192.168.255 + 256 = wraps to 192.169.0, which is valid */
        assert_se(r >= 0);
        assert_se(u.in.s_addr == htobe32(0xC0A90000));

        /* 255.255.255.0/24 → next would overflow → -ERANGE */
        u.in.s_addr = htobe32(0xFFFFFF00);
        r = in_addr_prefix_next(AF_INET, &u, 24);
        assert_se(r == -ERANGE);

        /* /0 → -ERANGE (prefixlen <= 0) */
        u.in.s_addr = 0;
        r = in_addr_prefix_next(AF_INET, &u, 0);
        assert_se(r == -ERANGE);
}

TEST(in_addr_prefix_range_ipv4) {
        union in_addr_union in = {}, start, end;
        int r;

        /* 192.168.1.0/24 → start=192.168.1.0, end=192.168.2.0 (nth=1 = next prefix) */
        in.in.s_addr = htobe32(0xC0A80100);
        r = in_addr_prefix_range(AF_INET, &in, 24, &start, &end);
        assert_se(r >= 0);
        assert_se(start.in.s_addr == htobe32(0xC0A80100));
        assert_se(end.in.s_addr == htobe32(0xC0A80200));
}

TEST(in_addr_is_null_generic) {
        union in_addr_union u = {};

        assert_se(in_addr_is_null(AF_INET, &u));
        assert_se(in_addr_is_null(AF_INET6, &u));

        u.in.s_addr = htobe32(0x0A000001);
        assert_se(!in_addr_is_null(AF_INET, &u));

        assert_se(in_addr_is_null(AF_UNIX, &u) == -EAFNOSUPPORT);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
