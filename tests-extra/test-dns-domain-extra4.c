/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <netinet/in.h>

#include "dns-domain.h"
#include "in-addr-util.h"
#include "tests.h"

TEST(dns_name_reverse_ipv4) {
        union in_addr_union a = {};
        _cleanup_free_ char *ret = NULL;

        a.in.s_addr = htobe32((127U << 24) | 1);
        assert_se(dns_name_reverse(AF_INET, &a, &ret) == 0);
        assert_se(streq(ret, "1.0.0.127.in-addr.arpa"));

        free(ret);
        a.in.s_addr = htobe32((192U << 24) | (168U << 16) | 1);
        assert_se(dns_name_reverse(AF_INET, &a, &ret) == 0);
        assert_se(streq(ret, "1.0.168.192.in-addr.arpa"));
}

TEST(dns_name_reverse_ipv6) {
        union in_addr_union a = {};
        _cleanup_free_ char *ret = NULL;

        /* ::1 loopback */
        a.in6.s6_addr[15] = 1;
        assert_se(dns_name_reverse(AF_INET6, &a, &ret) == 0);
        assert_se(endswith(ret, ".ip6.arpa"));
        assert_se(startswith(ret, "1.0.0.0."));
}

TEST(dns_name_reverse_invalid) {
        union in_addr_union a = {};
        _cleanup_free_ char *ret = NULL;

        assert_se(dns_name_reverse(AF_UNSPEC, &a, &ret) == -EAFNOSUPPORT);
}

TEST(dns_name_address_reverse) {
        int family;
        union in_addr_union addr;

        assert_se(dns_name_address("1.0.0.127.in-addr.arpa", &family, &addr) > 0);
        assert_se(family == AF_INET);

        assert_se(dns_name_address("example.com", &family, &addr) == 0);
}

TEST(dns_name_parent) {
        const char *p;

        p = "www.example.com";
        assert_se(dns_name_parent(&p) > 0);
        assert_se(streq(p, "example.com"));

        assert_se(dns_name_parent(&p) > 0);
        assert_se(streq(p, "com"));

        assert_se(dns_name_parent(&p) > 0);
        assert_se(streq(p, ""));

        assert_se(dns_name_parent(&p) == 0);
}

TEST(dns_name_dot_suffixed) {
        assert_se(dns_name_dot_suffixed("example.com.") == true);
        assert_se(dns_name_dot_suffixed("example.com") == false);
        assert_se(dns_name_dot_suffixed(".") == true);
}

TEST(dns_name_dont_resolve) {
        assert_se(dns_name_dont_resolve("10.0.0.0.in-addr.arpa"));
        assert_se(dns_name_dont_resolve("255.255.255.255.in-addr.arpa"));
        assert_se(dns_name_dont_resolve("something.invalid"));
        assert_se(dns_name_dont_resolve("something.alt"));
        assert_se(!dns_name_dont_resolve("example.com"));
}

TEST(dns_name_is_valid_or_address) {
        assert_se(dns_name_is_valid_or_address("127.0.0.1") > 0);
        assert_se(dns_name_is_valid_or_address("::1") > 0);
        assert_se(dns_name_is_valid_or_address("example.com") > 0);
        assert_se(dns_name_is_valid_or_address("") == 0);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
