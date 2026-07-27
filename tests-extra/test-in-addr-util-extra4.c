/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>

#include "in-addr-util.h"
#include "tests.h"

/* Generic address family tests using in_addr_from_string/in_addr_to_string */

TEST(in_addr_is_null_generic) {
        union in_addr_union u;

        assert_se(in_addr_from_string(AF_INET, "0.0.0.0", &u) >= 0);
        assert_se(in_addr_is_null(AF_INET, &u));

        assert_se(in_addr_from_string(AF_INET, "1.2.3.4", &u) >= 0);
        assert_se(!in_addr_is_null(AF_INET, &u));

        assert_se(in_addr_from_string(AF_INET6, "::", &u) >= 0);
        assert_se(in_addr_is_null(AF_INET6, &u));

        assert_se(in_addr_from_string(AF_INET6, "::1", &u) >= 0);
        assert_se(!in_addr_is_null(AF_INET6, &u));
}

TEST(in_addr_equal_generic) {
        union in_addr_union a, b;

        assert_se(in_addr_from_string(AF_INET, "10.0.0.1", &a) >= 0);
        assert_se(in_addr_from_string(AF_INET, "10.0.0.1", &b) >= 0);
        assert_se(in_addr_equal(AF_INET, &a, &b));

        assert_se(in_addr_from_string(AF_INET, "10.0.0.2", &b) >= 0);
        assert_se(!in_addr_equal(AF_INET, &a, &b));
}

TEST(in_addr_is_multicast_generic) {
        union in_addr_union u;

        assert_se(in_addr_from_string(AF_INET, "224.0.0.1", &u) >= 0);
        assert_se(in_addr_is_multicast(AF_INET, &u));

        assert_se(in_addr_from_string(AF_INET, "192.168.1.1", &u) >= 0);
        assert_se(!in_addr_is_multicast(AF_INET, &u));

        assert_se(in_addr_from_string(AF_INET6, "ff02::1", &u) >= 0);
        assert_se(in_addr_is_multicast(AF_INET6, &u));

        assert_se(in_addr_from_string(AF_INET6, "fe80::1", &u) >= 0);
        assert_se(!in_addr_is_multicast(AF_INET6, &u));
}

TEST(in_addr_is_link_local_generic) {
        union in_addr_union u;

        assert_se(in_addr_from_string(AF_INET, "169.254.1.1", &u) >= 0);
        assert_se(in_addr_is_link_local(AF_INET, &u));

        assert_se(in_addr_from_string(AF_INET, "192.168.1.1", &u) >= 0);
        assert_se(!in_addr_is_link_local(AF_INET, &u));

        assert_se(in_addr_from_string(AF_INET6, "fe80::1", &u) >= 0);
        assert_se(in_addr_is_link_local(AF_INET6, &u));

        assert_se(in_addr_from_string(AF_INET6, "2001:db8::1", &u) >= 0);
        assert_se(!in_addr_is_link_local(AF_INET6, &u));
}

TEST(in_addr_is_localhost_generic) {
        union in_addr_union u;

        assert_se(in_addr_from_string(AF_INET, "127.0.0.1", &u) >= 0);
        assert_se(in_addr_is_localhost(AF_INET, &u));

        assert_se(in_addr_from_string(AF_INET, "10.0.0.1", &u) >= 0);
        assert_se(!in_addr_is_localhost(AF_INET, &u));

        assert_se(in_addr_from_string(AF_INET6, "::1", &u) >= 0);
        assert_se(in_addr_is_localhost(AF_INET6, &u));

        assert_se(in_addr_from_string(AF_INET6, "2001:db8::1", &u) >= 0);
        assert_se(!in_addr_is_localhost(AF_INET6, &u));
}

TEST(in_addr_from_string_roundtrip) {
        union in_addr_union u;
        _cleanup_free_ char *s = NULL;

        assert_se(in_addr_from_string(AF_INET, "192.168.1.1", &u) >= 0);
        assert_se(in_addr_to_string(AF_INET, &u, &s) >= 0);
        assert_se(s);
        assert_se(streq(s, "192.168.1.1"));

        s = mfree(s);
        assert_se(in_addr_from_string(AF_INET6, "fe80::1", &u) >= 0);
        assert_se(in_addr_to_string(AF_INET6, &u, &s) >= 0);
        assert_se(s);
        assert_se(strstr(s, "fe80") != NULL);
}

TEST(in_addr_from_string_invalid) {
        union in_addr_union u;

        assert_se(in_addr_from_string(AF_INET, "not-an-ip", &u) < 0);
        assert_se(in_addr_from_string(AF_INET, "", &u) < 0);
        assert_se(in_addr_from_string(AF_INET6, "not-an-ipv6", &u) < 0);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
