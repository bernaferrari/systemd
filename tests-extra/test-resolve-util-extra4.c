/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "in-addr-util.h"
#include "resolve-util.h"
#include "string-util.h"
#include "tests.h"

TEST(dns_server_address_valid) {
        union in_addr_union a = {};

        /* Zero address is not valid */
        assert_se(!dns_server_address_valid(AF_INET, &a));
        assert_se(!dns_server_address_valid(AF_INET6, &a));

        /* 127.0.0.1 in network byte order is valid */
        a.in.s_addr = (in_addr_t) 0x0100007f;
        assert_se(dns_server_address_valid(AF_INET, &a));

        /* 127.0.0.53 (DNS stub) is NOT valid — function uses be32toh() so pass in network byte order */
        a.in.s_addr = htobe32(INADDR_DNS_STUB);
        assert_se(!dns_server_address_valid(AF_INET, &a));

        /* 127.0.0.54 (DNS proxy stub) is NOT valid */
        a.in.s_addr = htobe32(INADDR_DNS_PROXY_STUB);
        assert_se(!dns_server_address_valid(AF_INET, &a));

        /* Regular IPv4 is valid */
        a.in.s_addr = (in_addr_t) 0x04030201;
        assert_se(dns_server_address_valid(AF_INET, &a));

        /* ::1 is valid for IPv6 */
        a = (union in_addr_union) {};
        a.in6.s6_addr[15] = 1;
        assert_se(dns_server_address_valid(AF_INET6, &a));

        /* Regular IPv6 is valid */
        a = (union in_addr_union) {};
        a.in6.s6_addr[0] = 0x20;
        a.in6.s6_addr[1] = 0x01;
        a.in6.s6_addr[15] = 1;
        assert_se(dns_server_address_valid(AF_INET6, &a));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
