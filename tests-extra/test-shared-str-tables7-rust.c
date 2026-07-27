/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Shadow test: C condition_type, dns_server_address_valid, netif_has_carrier vs Rust */

#include <assert.h>
#include <string.h>
#include <linux/if.h>
#include "tests.h"
#include "string-util.h"

/* C headers */
#include "condition.h"
#include "resolve-util.h"
#include "netif-util.h"
#include "in-addr-util.h"

/* Rust FFI */
#include "rust/shared_facades/lookups.h"

/* ── condition_type ─────────────────────────────────────────────────── */

static void test_condition_type(void) {
        const char *cs, *rs;
        ConditionType cv, rv;

        /* Valid values */
        for (int i = 0; i < _CONDITION_TYPE_MAX; i++) {
                cs = condition_type_to_string(i);
                rs = rs_condition_type_to_string(i);
                assert_se(streq_ptr(cs, rs));
        }

        /* Invalid values */
        cs = condition_type_to_string(-1);
        rs = rs_condition_type_to_string(-1);
        assert_se(streq_ptr(cs, rs));

        cs = condition_type_to_string(_CONDITION_TYPE_MAX);
        rs = rs_condition_type_to_string(_CONDITION_TYPE_MAX);
        assert_se(streq_ptr(cs, rs));

        /* from_string roundtrip for each value */
        for (int i = 0; i < _CONDITION_TYPE_MAX; i++) {
                cv = condition_type_from_string(condition_type_to_string(i));
                rv = rs_condition_type_from_string(rs_condition_type_to_string(i));
                assert_se(cv == rv);
                assert_se(cv == (ConditionType)i);
        }

        /* from_string invalid */
        cv = condition_type_from_string("NoSuchCondition");
        rv = rs_condition_type_from_string("NoSuchCondition");
        assert_se(cv == rv);

        cv = condition_type_from_string(NULL);
        rv = rs_condition_type_from_string(NULL);
        assert_se(cv == rv);
}

/* ── dns_server_address_valid ───────────────────────────────────────── */

static void test_dns_server_address_valid(void) {
        bool cv, rv;
        union in_addr_union addr;

        /* Zero IPv4 */
        memset(&addr, 0, sizeof(addr));
        cv = dns_server_address_valid(AF_INET, &addr);
        rv = rs_dns_server_address_valid(AF_INET, (const unsigned char *)&addr);
        assert_se(cv == rv);
        assert_se(!cv);

        /* 127.0.0.53 — our stub (INADDR_DNS_STUB is host-order, s_addr needs network-order bytes) */
        memset(&addr, 0, sizeof(addr));
        { uint8_t bytes[] = {127, 0, 0, 53}; memcpy(&addr.in.s_addr, bytes, 4); }
        cv = dns_server_address_valid(AF_INET, &addr);
        rv = rs_dns_server_address_valid(AF_INET, (const unsigned char *)&addr);
        assert_se(cv == rv);
        assert_se(!cv);

        /* 127.0.0.54 — our proxy stub */
        memset(&addr, 0, sizeof(addr));
        { uint8_t bytes[] = {127, 0, 0, 54}; memcpy(&addr.in.s_addr, bytes, 4); }
        cv = dns_server_address_valid(AF_INET, &addr);
        rv = rs_dns_server_address_valid(AF_INET, (const unsigned char *)&addr);
        assert_se(cv == rv);
        assert_se(!cv);

        /* Valid IPv4 — 8.8.8.8 */
        memset(&addr, 0, sizeof(addr));
        { uint8_t bytes[] = {8, 8, 8, 8}; memcpy(&addr.in.s_addr, bytes, 4); }
        cv = dns_server_address_valid(AF_INET, &addr);
        rv = rs_dns_server_address_valid(AF_INET, (const unsigned char *)&addr);
        assert_se(cv == rv);
        assert_se(cv);

        /* Valid IPv4 — 1.1.1.1 */
        memset(&addr, 0, sizeof(addr));
        { uint8_t bytes[] = {1, 1, 1, 1}; memcpy(&addr.in.s_addr, bytes, 4); }
        cv = dns_server_address_valid(AF_INET, &addr);
        rv = rs_dns_server_address_valid(AF_INET, (const unsigned char *)&addr);
        assert_se(cv == rv);
        assert_se(cv);

        /* Zero IPv6 */
        memset(&addr, 0, sizeof(addr));
        cv = dns_server_address_valid(AF_INET6, &addr);
        rv = rs_dns_server_address_valid(AF_INET6, (const unsigned char *)&addr);
        assert_se(cv == rv);
        assert_se(!cv);

        /* Valid IPv6 — ::1 */
        memset(&addr, 0, sizeof(addr));
        addr.in6.s6_addr[15] = 1;
        cv = dns_server_address_valid(AF_INET6, &addr);
        rv = rs_dns_server_address_valid(AF_INET6, (const unsigned char *)&addr);
        assert_se(cv == rv);
        assert_se(cv);

        /* Valid IPv6 — 2001:4860:4860::8888 */
        memset(&addr, 0, sizeof(addr));
        addr.in6.s6_addr[0] = 0x20;
        addr.in6.s6_addr[1] = 0x01;
        addr.in6.s6_addr[2] = 0x48;
        addr.in6.s6_addr[3] = 0x60;
        addr.in6.s6_addr[4] = 0x48;
        addr.in6.s6_addr[5] = 0x60;
        addr.in6.s6_addr[14] = 0x88;
        addr.in6.s6_addr[15] = 0x88;
        cv = dns_server_address_valid(AF_INET6, &addr);
        rv = rs_dns_server_address_valid(AF_INET6, (const unsigned char *)&addr);
        assert_se(cv == rv);
        assert_se(cv);

        /* Unsupported family */
        memset(&addr, 0, sizeof(addr));
        cv = dns_server_address_valid(99, &addr);
        rv = rs_dns_server_address_valid(99, (const unsigned char *)&addr);
        assert_se(cv == rv);
}

/* ── netif_has_carrier ──────────────────────────────────────────────── */

static void test_netif_has_carrier(void) {
        bool cv, rv;

        /* IF_OPER_UP */
        cv = netif_has_carrier(IF_OPER_UP, 0);
        rv = rs_netif_has_carrier(IF_OPER_UP, 0);
        assert_se(cv == rv);
        assert_se(cv);

        /* IF_OPER_DOWN — not up, not unknown */
        cv = netif_has_carrier(2 /* IF_OPER_DOWN */, 0);
        rv = rs_netif_has_carrier(2, 0);
        assert_se(cv == rv);
        assert_se(!cv);

        /* IF_OPER_UNKNOWN with no flags */
        cv = netif_has_carrier(IF_OPER_UNKNOWN, 0);
        rv = rs_netif_has_carrier(IF_OPER_UNKNOWN, 0);
        assert_se(cv == rv);
        assert_se(!cv);

        /* IF_OPER_UNKNOWN with LOWER_UP|RUNNING */
        cv = netif_has_carrier(IF_OPER_UNKNOWN, IFF_LOWER_UP | IFF_RUNNING);
        rv = rs_netif_has_carrier(IF_OPER_UNKNOWN, IFF_LOWER_UP | IFF_RUNNING);
        assert_se(cv == rv);
        assert_se(cv);

        /* IF_OPER_UNKNOWN with LOWER_UP only */
        cv = netif_has_carrier(IF_OPER_UNKNOWN, IFF_LOWER_UP);
        rv = rs_netif_has_carrier(IF_OPER_UNKNOWN, IFF_LOWER_UP);
        assert_se(cv == rv);
        assert_se(!cv);

        /* IF_OPER_UNKNOWN with LOWER_UP|RUNNING|DORMANT */
        cv = netif_has_carrier(IF_OPER_UNKNOWN, IFF_LOWER_UP | IFF_RUNNING | IFF_DORMANT);
        rv = rs_netif_has_carrier(IF_OPER_UNKNOWN, IFF_LOWER_UP | IFF_RUNNING | IFF_DORMANT);
        assert_se(cv == rv);
        assert_se(!cv);
}

int main(int argc, char **argv) {
        test_condition_type();
        test_dns_server_address_valid();
        test_netif_has_carrier();
        return 0;
}
