/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Shadow test: C dns_server_address_valid vs Rust */

#include <arpa/inet.h>
#include <string.h>

#include "tests.h"
#include "in-addr-util.h"
#include "resolve-util.h"
#include "rust/shared_facades/lookups.h"

static void test_dns_server_address_valid_null(void) {
        /* C has ASSERT_PTR(sa) — only test Rust with NULL */
        assert_se(!rs_dns_server_address_valid(AF_INET, NULL));
        assert_se(!rs_dns_server_address_valid(AF_INET6, NULL));
}

static void test_dns_server_address_valid_zero(void) {
        union in_addr_union c_sa = {}, r_sa = {};

        assert_se(!dns_server_address_valid(AF_INET, &c_sa));
        assert_se(!rs_dns_server_address_valid(AF_INET, (const unsigned char *)&r_sa));

        assert_se(!dns_server_address_valid(AF_INET6, &c_sa));
        assert_se(!rs_dns_server_address_valid(AF_INET6, (const unsigned char *)&r_sa));
}

static void test_dns_server_address_valid_localhost(void) {
        union in_addr_union c_sa = {}, r_sa = {};

        inet_pton(AF_INET, "127.0.0.1", &c_sa);
        memcpy(&r_sa, &c_sa, sizeof(c_sa));

        bool c = dns_server_address_valid(AF_INET, &c_sa);
        bool r = rs_dns_server_address_valid(AF_INET, (const unsigned char *)&r_sa);
        assert_se(c == r);
        assert_se(c == true);
}

static void test_dns_server_address_valid_normal(void) {
        union in_addr_union c_sa = {}, r_sa = {};

        inet_pton(AF_INET, "8.8.8.8", &c_sa);
        memcpy(&r_sa, &c_sa, sizeof(c_sa));

        bool c = dns_server_address_valid(AF_INET, &c_sa);
        bool r = rs_dns_server_address_valid(AF_INET, (const unsigned char *)&r_sa);
        assert_se(c == r);
        assert_se(c == true);
}

static void test_dns_server_address_valid_dns_stub(void) {
        union in_addr_union c_sa = {}, r_sa = {};

        /* 127.0.0.53 = systemd-resolved stub listener */
        inet_pton(AF_INET, "127.0.0.53", &c_sa);
        memcpy(&r_sa, &c_sa, sizeof(c_sa));

        assert_se(!dns_server_address_valid(AF_INET, &c_sa));
        assert_se(!rs_dns_server_address_valid(AF_INET, (const unsigned char *)&r_sa));
}

static void test_dns_server_address_valid_dns_proxy(void) {
        union in_addr_union c_sa = {}, r_sa = {};

        /* 127.0.0.54 = systemd-resolved proxy listener */
        inet_pton(AF_INET, "127.0.0.54", &c_sa);
        memcpy(&r_sa, &c_sa, sizeof(c_sa));

        assert_se(!dns_server_address_valid(AF_INET, &c_sa));
        assert_se(!rs_dns_server_address_valid(AF_INET, (const unsigned char *)&r_sa));
}

static void test_dns_server_address_valid_ipv6(void) {
        union in_addr_union c_sa = {}, r_sa = {};

        inet_pton(AF_INET6, "2001:4860:4860::8888", &c_sa);
        memcpy(&r_sa, &c_sa, sizeof(c_sa));

        bool c = dns_server_address_valid(AF_INET6, &c_sa);
        bool r = rs_dns_server_address_valid(AF_INET6, (const unsigned char *)&r_sa);
        assert_se(c == r);
        assert_se(c == true);
}

static void test_dns_server_address_valid_ipv6_zero(void) {
        union in_addr_union c_sa = {}, r_sa = {};

        /* Zero IPv6 address */
        inet_pton(AF_INET6, "::", &c_sa);
        memcpy(&r_sa, &c_sa, sizeof(c_sa));

        assert_se(!dns_server_address_valid(AF_INET6, &c_sa));
        assert_se(!rs_dns_server_address_valid(AF_INET6, (const unsigned char *)&r_sa));
}

static void test_dns_server_address_valid_ipv6_localhost(void) {
        union in_addr_union c_sa = {}, r_sa = {};

        inet_pton(AF_INET6, "::1", &c_sa);
        memcpy(&r_sa, &c_sa, sizeof(c_sa));

        bool c = dns_server_address_valid(AF_INET6, &c_sa);
        bool r = rs_dns_server_address_valid(AF_INET6, (const unsigned char *)&r_sa);
        assert_se(c == r);
        assert_se(c == true);
}

static void test_dns_server_address_valid_other_addresses(void) {
        const char *addrs[] = {
                "1.1.1.1",
                "9.9.9.9",
                "192.168.1.1",
                "10.0.0.1",
        };
        for (int i = 0; i < (int)ELEMENTSOF(addrs); i++) {
                union in_addr_union c_sa = {}, r_sa = {};
                inet_pton(AF_INET, addrs[i], &c_sa);
                memcpy(&r_sa, &c_sa, sizeof(c_sa));

                bool c = dns_server_address_valid(AF_INET, &c_sa);
                bool r = rs_dns_server_address_valid(AF_INET, (const unsigned char *)&r_sa);
                assert_se(c == r);
                assert_se(c == true);
        }
}

int main(int argc, char *argv[]) {
        test_dns_server_address_valid_null();
        test_dns_server_address_valid_zero();
        test_dns_server_address_valid_localhost();
        test_dns_server_address_valid_normal();
        test_dns_server_address_valid_dns_stub();
        test_dns_server_address_valid_dns_proxy();
        test_dns_server_address_valid_ipv6();
        test_dns_server_address_valid_ipv6_zero();
        test_dns_server_address_valid_ipv6_localhost();
        test_dns_server_address_valid_other_addresses();

        return 0;
}
