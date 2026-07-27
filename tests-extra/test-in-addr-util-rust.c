/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Shadow test: C in-addr-util vs Rust rs_in_addr_util */

#include <arpa/inet.h>
#include <endian.h>
#include <string.h>

#include "in-addr-util.h"
#include "rust/in_addr_util.h"
#include "string-util.h"

/* ── Helpers ────────────────────────────────────────────────────────────── */

static struct in_addr make_in4(uint32_t a, uint32_t b, uint32_t c, uint32_t d) {
        struct in_addr addr;
        inet_pton(AF_INET, "0.0.0.0", &addr);
        uint32_t h = (a << 24) | (b << 16) | (c << 8) | d;
        addr.s_addr = htobe32(h);
        return addr;
}

static struct in6_addr make_in6_zero(void) {
        struct in6_addr a;
        memset(&a, 0, sizeof(a));
        return a;
}

static struct in6_addr make_in6_loopback(void) {
        /* ::1 */
        struct in6_addr a = {};
        a.s6_addr[15] = 1;
        return a;
}

static struct in6_addr make_in6_link_local(void) {
        /* fe80::1 */
        struct in6_addr a = {};
        a.s6_addr[0] = 0xfe;
        a.s6_addr[1] = 0x80;
        a.s6_addr[15] = 1;
        return a;
}

static struct in6_addr make_in6_multicast(void) {
        /* ff02::1 */
        struct in6_addr a = {};
        a.s6_addr[0] = 0xff;
        a.s6_addr[1] = 0x02;
        a.s6_addr[15] = 1;
        return a;
}

static struct in6_addr make_in6_ipv4_mapped(void) {
        /* ::ffff:192.0.2.1 */
        struct in6_addr a = {};
        a.s6_addr[10] = 0xff;
        a.s6_addr[11] = 0xff;
        a.s6_addr[12] = 192;
        a.s6_addr[13] = 0;
        a.s6_addr[14] = 2;
        a.s6_addr[15] = 1;
        return a;
}

static union in_addr_union make_union4(struct in_addr a) {
        union in_addr_union u;
        memset(&u, 0, sizeof(u));
        u.in = a;
        return u;
}

/* ── Null checks ────────────────────────────────────────────────────────── */

static void test_in4_addr_is_null(void) {
        struct in_addr zero = make_in4(0, 0, 0, 0);
        struct in_addr one = make_in4(1, 0, 0, 0);

        assert_se(in4_addr_is_null(&zero) == rs_in4_addr_is_null((const struct rs_InAddr*)&zero));
        assert_se(in4_addr_is_null(&zero));
        assert_se(in4_addr_is_null(&one) == rs_in4_addr_is_null((const struct rs_InAddr*)&one));
        assert_se(!in4_addr_is_null(&one));
}

static void test_in6_addr_is_null(void) {
        struct in6_addr zero = make_in6_zero();
        struct in6_addr loop = make_in6_loopback();

        assert_se(in6_addr_is_null(&zero) == rs_in6_addr_is_null((const struct rs_In6Addr*)&zero));
        assert_se(in6_addr_is_null(&zero));
        assert_se(in6_addr_is_null(&loop) == rs_in6_addr_is_null((const struct rs_In6Addr*)&loop));
        assert_se(!in6_addr_is_null(&loop));
}

static void test_in_addr_is_null(void) {
        struct in_addr a4 = make_in4(0, 0, 0, 0);
        struct in6_addr a6 = make_in6_zero();
        union in_addr_union u4 = make_union4(a4);
        union in_addr_union u6;
        memset(&u6, 0, sizeof(u6));
        u6.in6 = a6;

        assert_se(in_addr_is_null(AF_INET, &u4) == rs_in_addr_is_null(AF_INET, (const union rs_InAddrUnion*)&u4));
        assert_se(in_addr_is_null(AF_INET6, &u6) == rs_in_addr_is_null(AF_INET6, (const union rs_InAddrUnion*)&u6));
        assert_se(in_addr_is_null(AF_UNSPEC, &u4) == rs_in_addr_is_null(AF_UNSPEC, (const union rs_InAddrUnion*)&u4));
}

/* ── Link-local ─────────────────────────────────────────────────────────── */

static void test_in4_addr_is_link_local(void) {
        struct in_addr ll = make_in4(169, 254, 1, 1);
        struct in_addr not_ll = make_in4(192, 168, 1, 1);

        assert_se(in4_addr_is_link_local(&ll) == rs_in4_addr_is_link_local((const struct rs_InAddr*)&ll));
        assert_se(in4_addr_is_link_local(&ll));
        assert_se(in4_addr_is_link_local(&not_ll) == rs_in4_addr_is_link_local((const struct rs_InAddr*)&not_ll));
        assert_se(!in4_addr_is_link_local(&not_ll));
}

static void test_in4_addr_is_link_local_dynamic(void) {
        /* 169.254.1.1 = dynamic (middle range) */
        struct in_addr dyn = make_in4(169, 254, 1, 1);
        /* 169.254.0.1 = reserved (first 256) */
        struct in_addr reserved_lo = make_in4(169, 254, 0, 1);
        /* 169.254.255.1 = reserved (last 256) */
        struct in_addr reserved_hi = make_in4(169, 254, 255, 1);
        struct in_addr not_ll = make_in4(10, 0, 0, 1);

        assert_se(in4_addr_is_link_local_dynamic(&dyn) == rs_in4_addr_is_link_local_dynamic((const struct rs_InAddr*)&dyn));
        assert_se(in4_addr_is_link_local_dynamic(&dyn));
        assert_se(in4_addr_is_link_local_dynamic(&reserved_lo) == rs_in4_addr_is_link_local_dynamic((const struct rs_InAddr*)&reserved_lo));
        assert_se(!in4_addr_is_link_local_dynamic(&reserved_lo));
        assert_se(in4_addr_is_link_local_dynamic(&reserved_hi) == rs_in4_addr_is_link_local_dynamic((const struct rs_InAddr*)&reserved_hi));
        assert_se(!in4_addr_is_link_local_dynamic(&reserved_hi));
        assert_se(in4_addr_is_link_local_dynamic(&not_ll) == rs_in4_addr_is_link_local_dynamic((const struct rs_InAddr*)&not_ll));
        assert_se(!in4_addr_is_link_local_dynamic(&not_ll));
}

static void test_in6_addr_is_link_local(void) {
        struct in6_addr ll = make_in6_link_local();
        struct in6_addr not_ll = make_in6_loopback();

        assert_se(in6_addr_is_link_local(&ll) == rs_in6_addr_is_link_local((const struct rs_In6Addr*)&ll));
        assert_se(in6_addr_is_link_local(&ll));
        assert_se(in6_addr_is_link_local(&not_ll) == rs_in6_addr_is_link_local((const struct rs_In6Addr*)&not_ll));
        assert_se(!in6_addr_is_link_local(&not_ll));
}

static void test_in_addr_is_link_local(void) {
        struct in_addr a4 = make_in4(169, 254, 1, 1);
        struct in6_addr a6 = make_in6_link_local();
        union in_addr_union u4 = make_union4(a4);
        union in_addr_union u6;
        memset(&u6, 0, sizeof(u6));
        u6.in6 = a6;

        assert_se(in_addr_is_link_local(AF_INET, &u4) == rs_in_addr_is_link_local(AF_INET, (const union rs_InAddrUnion*)&u4));
        assert_se(in_addr_is_link_local(AF_INET6, &u6) == rs_in_addr_is_link_local(AF_INET6, (const union rs_InAddrUnion*)&u6));
}

static void test_in6_addr_is_link_local_all_nodes(void) {
        struct in6_addr all_nodes = make_in6_multicast(); /* ff02::1 */
        struct in6_addr other = make_in6_link_local();    /* fe80::1 */

        assert_se(in6_addr_is_link_local_all_nodes(&all_nodes) == rs_in6_addr_is_link_local_all_nodes((const struct rs_In6Addr*)&all_nodes));
        assert_se(in6_addr_is_link_local_all_nodes(&all_nodes));
        assert_se(in6_addr_is_link_local_all_nodes(&other) == rs_in6_addr_is_link_local_all_nodes((const struct rs_In6Addr*)&other));
        assert_se(!in6_addr_is_link_local_all_nodes(&other));
}

/* ── Multicast ──────────────────────────────────────────────────────────── */

static void test_in4_addr_is_multicast(void) {
        struct in_addr mcast = make_in4(224, 0, 0, 1);
        struct in_addr not_mcast = make_in4(10, 0, 0, 1);

        assert_se(in4_addr_is_multicast(&mcast) == rs_in4_addr_is_multicast((const struct rs_InAddr*)&mcast));
        assert_se(in4_addr_is_multicast(&mcast));
        assert_se(in4_addr_is_multicast(&not_mcast) == rs_in4_addr_is_multicast((const struct rs_InAddr*)&not_mcast));
        assert_se(!in4_addr_is_multicast(&not_mcast));
}

static void test_in6_addr_is_multicast(void) {
        struct in6_addr mcast = make_in6_multicast();
        struct in6_addr not_mcast = make_in6_loopback();

        assert_se(in6_addr_is_multicast(&mcast) == rs_in6_addr_is_multicast((const struct rs_In6Addr*)&mcast));
        assert_se(in6_addr_is_multicast(&mcast));
        assert_se(in6_addr_is_multicast(&not_mcast) == rs_in6_addr_is_multicast((const struct rs_In6Addr*)&not_mcast));
        assert_se(!in6_addr_is_multicast(&not_mcast));
}

static void test_in_addr_is_multicast(void) {
        struct in_addr a4 = make_in4(224, 0, 0, 1);
        struct in6_addr a6 = make_in6_multicast();
        union in_addr_union u4 = make_union4(a4);
        union in_addr_union u6;
        memset(&u6, 0, sizeof(u6));
        u6.in6 = a6;

        assert_se(in_addr_is_multicast(AF_INET, &u4) == rs_in_addr_is_multicast(AF_INET, (const union rs_InAddrUnion*)&u4));
        assert_se(in_addr_is_multicast(AF_INET6, &u6) == rs_in_addr_is_multicast(AF_INET6, (const union rs_InAddrUnion*)&u6));
}

static void test_in4_addr_is_local_multicast(void) {
        /* 224.0.0.1 = local multicast */
        struct in_addr local = make_in4(224, 0, 0, 1);
        /* 224.1.0.1 = non-local multicast */
        struct in_addr not_local = make_in4(224, 1, 0, 1);
        struct in_addr not_mcast = make_in4(10, 0, 0, 1);

        assert_se(in4_addr_is_local_multicast(&local) == rs_in4_addr_is_local_multicast((const struct rs_InAddr*)&local));
        assert_se(in4_addr_is_local_multicast(&local));
        assert_se(in4_addr_is_local_multicast(&not_local) == rs_in4_addr_is_local_multicast((const struct rs_InAddr*)&not_local));
        assert_se(!in4_addr_is_local_multicast(&not_local));
        assert_se(in4_addr_is_local_multicast(&not_mcast) == rs_in4_addr_is_local_multicast((const struct rs_InAddr*)&not_mcast));
        assert_se(!in4_addr_is_local_multicast(&not_mcast));
}

/* ── Localhost ──────────────────────────────────────────────────────────── */

static void test_in4_addr_is_localhost(void) {
        struct in_addr lo = make_in4(127, 0, 0, 1);
        struct in_addr lo2 = make_in4(127, 255, 255, 255);
        struct in_addr not_lo = make_in4(128, 0, 0, 1);

        assert_se(in4_addr_is_localhost(&lo) == rs_in4_addr_is_localhost((const struct rs_InAddr*)&lo));
        assert_se(in4_addr_is_localhost(&lo));
        assert_se(in4_addr_is_localhost(&lo2) == rs_in4_addr_is_localhost((const struct rs_InAddr*)&lo2));
        assert_se(in4_addr_is_localhost(&lo2));
        assert_se(in4_addr_is_localhost(&not_lo) == rs_in4_addr_is_localhost((const struct rs_InAddr*)&not_lo));
        assert_se(!in4_addr_is_localhost(&not_lo));
}

static void test_in4_addr_is_non_local(void) {
        struct in_addr zero = make_in4(0, 0, 0, 0);
        struct in_addr lo = make_in4(127, 0, 0, 1);
        struct in_addr pub = make_in4(8, 8, 8, 8);

        assert_se(in4_addr_is_non_local(&zero) == rs_in4_addr_is_non_local((const struct rs_InAddr*)&zero));
        assert_se(!in4_addr_is_non_local(&zero));
        assert_se(in4_addr_is_non_local(&lo) == rs_in4_addr_is_non_local((const struct rs_InAddr*)&lo));
        assert_se(!in4_addr_is_non_local(&lo));
        assert_se(in4_addr_is_non_local(&pub) == rs_in4_addr_is_non_local((const struct rs_InAddr*)&pub));
        assert_se(in4_addr_is_non_local(&pub));
}

static void test_in_addr_is_localhost(void) {
        struct in_addr a4 = make_in4(127, 0, 0, 1);
        struct in6_addr a6 = make_in6_loopback();
        struct in_addr not_lo = make_in4(10, 0, 0, 1);
        union in_addr_union u4 = make_union4(a4);
        union in_addr_union u6;
        memset(&u6, 0, sizeof(u6));
        u6.in6 = a6;
        union in_addr_union u4n = make_union4(not_lo);

        assert_se(in_addr_is_localhost(AF_INET, &u4) == rs_in_addr_is_localhost(AF_INET, (const union rs_InAddrUnion*)&u4));
        assert_se(in_addr_is_localhost(AF_INET, &u4));
        assert_se(in_addr_is_localhost(AF_INET6, &u6) == rs_in_addr_is_localhost(AF_INET6, (const union rs_InAddrUnion*)&u6));
        assert_se(in_addr_is_localhost(AF_INET6, &u6));
        assert_se(in_addr_is_localhost(AF_INET, &u4n) == rs_in_addr_is_localhost(AF_INET, (const union rs_InAddrUnion*)&u4n));
        assert_se(!in_addr_is_localhost(AF_INET, &u4n));
}

static void test_in_addr_is_localhost_one(void) {
        /* 127.0.0.1 = localhost_one for IPv4 */
        struct in_addr a4 = make_in4(127, 0, 0, 1);
        /* 127.0.0.2 = NOT localhost_one */
        struct in_addr a4b = make_in4(127, 0, 0, 2);
        /* ::1 = localhost_one for IPv6 */
        struct in6_addr a6 = make_in6_loopback();
        union in_addr_union u4 = make_union4(a4);
        union in_addr_union u4b = make_union4(a4b);
        union in_addr_union u6;
        memset(&u6, 0, sizeof(u6));
        u6.in6 = a6;

        assert_se(in_addr_is_localhost_one(AF_INET, &u4) == rs_in_addr_is_localhost_one(AF_INET, (const union rs_InAddrUnion*)&u4));
        assert_se(in_addr_is_localhost_one(AF_INET, &u4));
        assert_se(in_addr_is_localhost_one(AF_INET, &u4b) == rs_in_addr_is_localhost_one(AF_INET, (const union rs_InAddrUnion*)&u4b));
        assert_se(!in_addr_is_localhost_one(AF_INET, &u4b));
        assert_se(in_addr_is_localhost_one(AF_INET6, &u6) == rs_in_addr_is_localhost_one(AF_INET6, (const union rs_InAddrUnion*)&u6));
        assert_se(in_addr_is_localhost_one(AF_INET6, &u6));
}

/* ── Equality ────────────────────────────────────────────────────────────── */

static void test_in4_addr_equal(void) {
        struct in_addr a = make_in4(192, 168, 1, 1);
        struct in_addr b = make_in4(192, 168, 1, 1);
        struct in_addr c = make_in4(192, 168, 1, 2);

        assert_se(in4_addr_equal(&a, &b) == rs_in4_addr_equal((const struct rs_InAddr*)&a, (const struct rs_InAddr*)&b));
        assert_se(in4_addr_equal(&a, &b));
        assert_se(in4_addr_equal(&a, &c) == rs_in4_addr_equal((const struct rs_InAddr*)&a, (const struct rs_InAddr*)&c));
        assert_se(!in4_addr_equal(&a, &c));
}

static void test_in6_addr_equal(void) {
        struct in6_addr a = make_in6_link_local();
        struct in6_addr b = make_in6_link_local();
        struct in6_addr c = make_in6_loopback();

        assert_se(in6_addr_equal(&a, &b) == rs_in6_addr_equal((const struct rs_In6Addr*)&a, (const struct rs_In6Addr*)&b));
        assert_se(in6_addr_equal(&a, &b));
        assert_se(in6_addr_equal(&a, &c) == rs_in6_addr_equal((const struct rs_In6Addr*)&a, (const struct rs_In6Addr*)&c));
        assert_se(!in6_addr_equal(&a, &c));
}

static void test_in_addr_equal(void) {
        struct in_addr a4 = make_in4(10, 0, 0, 1);
        struct in_addr b4 = make_in4(10, 0, 0, 2);
        struct in6_addr a6 = make_in6_loopback();
        struct in6_addr b6 = make_in6_loopback();
        union in_addr_union u4a = make_union4(a4);
        union in_addr_union u4b = make_union4(b4);
        union in_addr_union u6a;
        union in_addr_union u6b;
        memset(&u6a, 0, sizeof(u6a));
        u6a.in6 = a6;
        memset(&u6b, 0, sizeof(u6b));
        u6b.in6 = b6;

        assert_se(in_addr_equal(AF_INET, &u4a, &u4a) == rs_in_addr_equal(AF_INET, (const union rs_InAddrUnion*)&u4a, (const union rs_InAddrUnion*)&u4a));
        assert_se(!in_addr_equal(AF_INET, &u4a, &u4b));
        assert_se(in_addr_equal(AF_INET6, &u6a, &u6b) == rs_in_addr_equal(AF_INET6, (const union rs_InAddrUnion*)&u6a, (const union rs_InAddrUnion*)&u6b));
        assert_se(in_addr_equal(AF_INET6, &u6a, &u6b));
}

static void test_in6_addr_is_ipv4_mapped(void) {
        struct in6_addr mapped = make_in6_ipv4_mapped();
        struct in6_addr not_mapped = make_in6_loopback();
        struct in6_addr zero = make_in6_zero();

        assert_se(in6_addr_is_ipv4_mapped_address(&mapped) == rs_in6_addr_is_ipv4_mapped_address((const struct rs_In6Addr*)&mapped));
        assert_se(in6_addr_is_ipv4_mapped_address(&mapped));
        assert_se(in6_addr_is_ipv4_mapped_address(&not_mapped) == rs_in6_addr_is_ipv4_mapped_address((const struct rs_In6Addr*)&not_mapped));
        assert_se(!in6_addr_is_ipv4_mapped_address(&not_mapped));
        assert_se(in6_addr_is_ipv4_mapped_address(&zero) == rs_in6_addr_is_ipv4_mapped_address((const struct rs_In6Addr*)&zero));
        assert_se(!in6_addr_is_ipv4_mapped_address(&zero));
}

/* ── Prefix intersection ────────────────────────────────────────────────── */

static void test_in4_addr_prefix_intersect(void) {
        struct in_addr a = make_in4(192, 168, 1, 0);
        struct in_addr b = make_in4(192, 168, 1, 100);
        struct in_addr c = make_in4(10, 0, 0, 1);

        /* Same /24 prefix → intersect */
        assert_se(in4_addr_prefix_intersect(&a, 24, &b, 24) == rs_in4_addr_prefix_intersect((const struct rs_InAddr*)&a, 24, (const struct rs_InAddr*)&b, 24));
        assert_se(in4_addr_prefix_intersect(&a, 24, &b, 24));
        /* Different /24 prefixes → no intersect */
        assert_se(!in4_addr_prefix_intersect(&a, 24, &c, 24));
        /* Different /16 prefixes → no intersect */
        assert_se(in4_addr_prefix_intersect(&a, 16, &c, 16) == rs_in4_addr_prefix_intersect((const struct rs_InAddr*)&a, 16, (const struct rs_InAddr*)&c, 16));
        assert_se(!in4_addr_prefix_intersect(&a, 16, &c, 16));
        /* /0 always intersects */
        assert_se(in4_addr_prefix_intersect(&a, 0, &c, 0) == rs_in4_addr_prefix_intersect((const struct rs_InAddr*)&a, 0, (const struct rs_InAddr*)&c, 0));
        assert_se(in4_addr_prefix_intersect(&a, 0, &c, 0));
}

static void test_in6_addr_prefix_intersect(void) {
        struct in6_addr a = make_in6_link_local();
        struct in6_addr b = {};
        b.s6_addr[0] = 0xfe;
        b.s6_addr[1] = 0x80;
        b.s6_addr[15] = 2;
        struct in6_addr c = make_in6_loopback();

        assert_se(in6_addr_prefix_intersect(&a, 64, &b, 64) == rs_in6_addr_prefix_intersect((const struct rs_In6Addr*)&a, 64, (const struct rs_In6Addr*)&b, 64));
        assert_se(in6_addr_prefix_intersect(&a, 64, &b, 64));
        assert_se(in6_addr_prefix_intersect(&a, 128, &b, 128) == rs_in6_addr_prefix_intersect((const struct rs_In6Addr*)&a, 128, (const struct rs_In6Addr*)&b, 128));
        assert_se(!in6_addr_prefix_intersect(&a, 128, &b, 128));
        assert_se(in6_addr_prefix_intersect(&a, 0, &c, 0) == rs_in6_addr_prefix_intersect((const struct rs_In6Addr*)&a, 0, (const struct rs_In6Addr*)&c, 0));
        assert_se(in6_addr_prefix_intersect(&a, 0, &c, 0));
}

static void test_in_addr_prefix_intersect(void) {
        struct in_addr a4 = make_in4(192, 168, 1, 0);
        struct in_addr b4 = make_in4(192, 168, 2, 0);
        struct in6_addr a6 = make_in6_link_local();
        struct in6_addr b6 = {};
        b6.s6_addr[0] = 0xfe;
        b6.s6_addr[1] = 0x80;
        b6.s6_addr[15] = 2;
        union in_addr_union u4a = make_union4(a4);
        union in_addr_union u4b = make_union4(b4);
        union in_addr_union u6a;
        union in_addr_union u6b;
        memset(&u6a, 0, sizeof(u6a));
        u6a.in6 = a6;
        memset(&u6b, 0, sizeof(u6b));
        u6b.in6 = b6;

        assert_se(in_addr_prefix_intersect(AF_INET, &u4a, 24, &u4b, 24) ==
                   rs_in_addr_prefix_intersect(AF_INET, (const union rs_InAddrUnion*)&u4a, 24, (const union rs_InAddrUnion*)&u4b, 24));
        assert_se(in_addr_prefix_intersect(AF_INET6, &u6a, 64, &u6b, 64) ==
                   rs_in_addr_prefix_intersect(AF_INET6, (const union rs_InAddrUnion*)&u6a, 64, (const union rs_InAddrUnion*)&u6b, 64));
}

/* ── Prefix nth / next ──────────────────────────────────────────────────── */

static void test_in_addr_prefix_nth(void) {
        /* 10.0.0.0/8, nth=0 → 10.0.0.0 */
        struct in_addr a = make_in4(10, 0, 0, 0);
        union in_addr_union u = make_union4(a);
        union rs_InAddrUnion ru;
        memset(&ru, 0, sizeof(ru));
        ru.in4.s_addr = a.s_addr;

        int rc = in_addr_prefix_nth(AF_INET, &u, 8, 0);
        int rrc = rs_in_addr_prefix_nth(AF_INET, &ru, 8, 0);
        assert_se(rc == rrc);
        assert_se(rc == 0);

        /* 10.0.0.0/8, nth=1 → 11.0.0.0 */
        u = make_union4(a);
        memset(&ru, 0, sizeof(ru));
        ru.in4.s_addr = a.s_addr;
        rc = in_addr_prefix_nth(AF_INET, &u, 8, 1);
        rrc = rs_in_addr_prefix_nth(AF_INET, &ru, 8, 1);
        assert_se(rc == rrc);
        assert_se(rc == 0);

        /* Verify C and Rust produce same result */
        assert_se(u.in.s_addr == ru.in4.s_addr);
        assert_se(be32toh(u.in.s_addr) == 0x0B000000u);

        /* 10.0.0.0/8, nth=255 → overflow */
        u = make_union4(a);
        memset(&ru, 0, sizeof(ru));
        ru.in4.s_addr = a.s_addr;
        rc = in_addr_prefix_nth(AF_INET, &u, 8, 255);
        rrc = rs_in_addr_prefix_nth(AF_INET, &ru, 8, 255);
        assert_se(rc == rrc);
        assert_se(rc == -ERANGE);
}

static void test_in_addr_prefix_next(void) {
        struct in_addr a = make_in4(192, 168, 0, 0);
        union in_addr_union u = make_union4(a);
        union rs_InAddrUnion ru;
        memset(&ru, 0, sizeof(ru));
        ru.in4.s_addr = a.s_addr;

        int rc = in_addr_prefix_next(AF_INET, &u, 24);
        int rrc = rs_in_addr_prefix_next(AF_INET, &ru, 24);
        assert_se(rc == rrc);
        assert_se(rc == 0);
        assert_se(u.in.s_addr == ru.in4.s_addr);
}

/* ── Netmask ────────────────────────────────────────────────────────────── */

static void test_in4_addr_netmask_to_prefixlen(void) {
        /* /24 = 255.255.255.0 */
        struct in_addr m24 = make_in4(255, 255, 255, 0);
        assert_se(in4_addr_netmask_to_prefixlen(&m24) == rs_in4_addr_netmask_to_prefixlen((const struct rs_InAddr*)&m24));
        assert_se(in4_addr_netmask_to_prefixlen(&m24) == 24);

        /* /16 */
        struct in_addr m16 = make_in4(255, 255, 0, 0);
        assert_se(in4_addr_netmask_to_prefixlen(&m16) == rs_in4_addr_netmask_to_prefixlen((const struct rs_InAddr*)&m16));
        assert_se(in4_addr_netmask_to_prefixlen(&m16) == 16);

        /* /0 */
        struct in_addr m0 = make_in4(0, 0, 0, 0);
        assert_se(in4_addr_netmask_to_prefixlen(&m0) == rs_in4_addr_netmask_to_prefixlen((const struct rs_InAddr*)&m0));
        assert_se(in4_addr_netmask_to_prefixlen(&m0) == 0);

        /* /32 */
        struct in_addr m32 = make_in4(255, 255, 255, 255);
        assert_se(in4_addr_netmask_to_prefixlen(&m32) == rs_in4_addr_netmask_to_prefixlen((const struct rs_InAddr*)&m32));
        assert_se(in4_addr_netmask_to_prefixlen(&m32) == 32);
}

static void test_in4_addr_prefixlen_to_netmask(void) {
        struct in_addr addr = {};
        struct rs_InAddr raddr = {};

        struct in_addr *ret_c = in4_addr_prefixlen_to_netmask(&addr, 24);
        struct rs_InAddr *ret_r = rs_in4_addr_prefixlen_to_netmask(&raddr, 24);
        assert_se(ret_c == &addr);
        assert_se(ret_r == &raddr);
        assert_se(addr.s_addr == raddr.s_addr);

        /* /0 */
        memset(&addr, 0, sizeof(addr));
        memset(&raddr, 0, sizeof(raddr));
        ret_c = in4_addr_prefixlen_to_netmask(&addr, 0);
        ret_r = rs_in4_addr_prefixlen_to_netmask(&raddr, 0);
        assert_se(addr.s_addr == raddr.s_addr);

        /* /32 */
        memset(&addr, 0, sizeof(addr));
        memset(&raddr, 0, sizeof(raddr));
        ret_c = in4_addr_prefixlen_to_netmask(&addr, 32);
        ret_r = rs_in4_addr_prefixlen_to_netmask(&raddr, 32);
        assert_se(addr.s_addr == raddr.s_addr);
}

static void test_in6_addr_prefixlen_to_netmask(void) {
        struct in6_addr addr = {};
        struct rs_In6Addr raddr = {};

        struct in6_addr *ret_c = in6_addr_prefixlen_to_netmask(&addr, 64);
        struct rs_In6Addr *ret_r = rs_in6_addr_prefixlen_to_netmask(&raddr, 64);
        assert_se(ret_c == &addr);
        assert_se(ret_r == &raddr);
        assert_se(memcmp(&addr, &raddr, 16) == 0);

        /* Check specific bytes: first 8 should be 0xFF, rest 0 */
        assert_se(addr.s6_addr[7] == 0xFF);
        assert_se(addr.s6_addr[8] == 0x00);

        /* /0 */
        memset(&addr, 0, sizeof(addr));
        memset(&raddr, 0, sizeof(raddr));
        in6_addr_prefixlen_to_netmask(&addr, 0);
        rs_in6_addr_prefixlen_to_netmask(&raddr, 0);
        assert_se(memcmp(&addr, &raddr, 16) == 0);

        /* /128 */
        memset(&addr, 0, sizeof(addr));
        memset(&raddr, 0, sizeof(raddr));
        in6_addr_prefixlen_to_netmask(&addr, 128);
        rs_in6_addr_prefixlen_to_netmask(&raddr, 128);
        assert_se(memcmp(&addr, &raddr, 16) == 0);
}

static void test_in_addr_prefixlen_to_netmask(void) {
        union in_addr_union u = {};
        union rs_InAddrUnion ru = {};

        int rc = in_addr_prefixlen_to_netmask(AF_INET, &u, 24);
        int rrc = rs_in_addr_prefixlen_to_netmask(AF_INET, &ru, 24);
        assert_se(rc == rrc);
        assert_se(rc == 0);

        rc = in_addr_prefixlen_to_netmask(AF_INET6, &u, 64);
        rrc = rs_in_addr_prefixlen_to_netmask(AF_INET6, &ru, 64);
        assert_se(rc == rrc);
        assert_se(rc == 0);

        rc = in_addr_prefixlen_to_netmask(AF_UNSPEC, &u, 24);
        rrc = rs_in_addr_prefixlen_to_netmask(AF_UNSPEC, &ru, 24);
        assert_se(rc == rrc);
}

/* ── Default prefix length ─────────────────────────────────────────────── */

static void test_in4_addr_default_prefixlen(void) {
        /* Class A: 10.x.x.x → /8 */
        struct in_addr a = make_in4(10, 0, 0, 1);
        unsigned char pl_c = 0, pl_r = 0;
        int rc = in4_addr_default_prefixlen(&a, &pl_c);
        int rrc = rs_in4_addr_default_prefixlen((const struct rs_InAddr*)&a, &pl_r);
        assert_se(rc == rrc);
        assert_se(rc == 0);
        assert_se(pl_c == pl_r);
        assert_se(pl_c == 8);

        /* Class B: 172.16.0.1 → /16 */
        a = make_in4(172, 16, 0, 1);
        rc = in4_addr_default_prefixlen(&a, &pl_c);
        rrc = rs_in4_addr_default_prefixlen((const struct rs_InAddr*)&a, &pl_r);
        assert_se(rc == rrc);
        assert_se(pl_c == 16);

        /* Class C: 192.168.1.1 → /24 */
        a = make_in4(192, 168, 1, 1);
        rc = in4_addr_default_prefixlen(&a, &pl_c);
        rrc = rs_in4_addr_default_prefixlen((const struct rs_InAddr*)&a, &pl_r);
        assert_se(rc == rrc);
        assert_se(pl_c == 24);

        /* Class D: 224.0.0.1 → -ERANGE */
        a = make_in4(224, 0, 0, 1);
        rc = in4_addr_default_prefixlen(&a, &pl_c);
        rrc = rs_in4_addr_default_prefixlen((const struct rs_InAddr*)&a, &pl_r);
        assert_se(rc == rrc);
        assert_se(rc == -ERANGE);
}

/* ── Mask ────────────────────────────────────────────────────────────────── */

static void test_in4_addr_mask(void) {
        struct in_addr a = make_in4(192, 168, 1, 100);
        struct in_addr ac = a;
        struct in_addr ar = a;

        int rc = in4_addr_mask(&ac, 24);
        int rrc = rs_in4_addr_mask((struct rs_InAddr*)&ar, 24);
        assert_se(rc == rrc);
        assert_se(rc == 0);
        assert_se(ac.s_addr == ar.s_addr);

        struct in_addr expected = make_in4(192, 168, 1, 0);
        assert_se(ac.s_addr == expected.s_addr);

        /* The C helper rejects an IPv4 prefix larger than 32 rather than
         * silently treating it as an all-ones mask. Keep the error and the
         * input mutation behavior locked to the Rust ABI facade. */
        ac = a;
        ar = a;
        rc = in4_addr_mask(&ac, 33);
        rrc = rs_in4_addr_mask((struct rs_InAddr*)&ar, 33);
        assert_se(rc == rrc);
        assert_se(rc == -EINVAL);
        assert_se(ac.s_addr == ar.s_addr);
}

static void test_in6_addr_mask(void) {
        struct in6_addr a = make_in6_link_local();
        /* fe80::1, mask to /64 → fe80:: */
        struct in6_addr ac = a;
        struct rs_In6Addr ar;
        memcpy(&ar, &a, sizeof(a));

        int rc = in6_addr_mask(&ac, 64);
        int rrc = rs_in6_addr_mask(&ar, 64);
        assert_se(rc == rrc);
        assert_se(rc == 0);
        assert_se(memcmp(&ac, &ar, 16) == 0);

        /* After masking, last 8 bytes should be zero */
        bool all_zero = true;
        for (int i = 8; i < 16; i++)
                if (ac.s6_addr[i] != 0)
                        all_zero = false;
        assert_se(all_zero);
}

static void test_in_addr_mask(void) {
        struct in_addr a4 = make_in4(192, 168, 1, 100);
        union in_addr_union u4 = make_union4(a4);
        union rs_InAddrUnion ru4;
        memset(&ru4, 0, sizeof(ru4));
        ru4.in4.s_addr = a4.s_addr;

        int rc = in_addr_mask(AF_INET, &u4, 24);
        int rrc = rs_in_addr_mask(AF_INET, &ru4, 24);
        assert_se(rc == rrc);
        assert_se(u4.in.s_addr == ru4.in4.s_addr);
}

/* ── Prefix covers ──────────────────────────────────────────────────────── */

static void test_in4_addr_prefix_covers(void) {
        struct in_addr prefix = make_in4(192, 168, 1, 0);
        struct in_addr addr1 = make_in4(192, 168, 1, 100);
        struct in_addr addr2 = make_in4(192, 168, 2, 1);

        assert_se(in4_addr_prefix_covers(&prefix, 24, &addr1) ==
                   rs_in4_addr_prefix_covers((const struct rs_InAddr*)&prefix, 24, (const struct rs_InAddr*)&addr1));
        assert_se(in4_addr_prefix_covers(&prefix, 24, &addr1));
        assert_se(in4_addr_prefix_covers(&prefix, 24, &addr2) ==
                   rs_in4_addr_prefix_covers((const struct rs_InAddr*)&prefix, 24, (const struct rs_InAddr*)&addr2));
        assert_se(!in4_addr_prefix_covers(&prefix, 24, &addr2));
}

static void test_in6_addr_prefix_covers(void) {
        struct in6_addr prefix = make_in6_link_local();
        struct in6_addr addr = {};
        addr.s6_addr[0] = 0xfe;
        addr.s6_addr[1] = 0x80;
        addr.s6_addr[15] = 42;
        struct in6_addr other = make_in6_loopback();

        assert_se(in6_addr_prefix_covers(&prefix, 64, &addr) ==
                   rs_in6_addr_prefix_covers((const struct rs_In6Addr*)&prefix, 64, (const struct rs_In6Addr*)&addr));
        assert_se(in6_addr_prefix_covers(&prefix, 64, &addr));
        assert_se(in6_addr_prefix_covers(&prefix, 64, &other) ==
                   rs_in6_addr_prefix_covers((const struct rs_In6Addr*)&prefix, 64, (const struct rs_In6Addr*)&other));
        assert_se(!in6_addr_prefix_covers(&prefix, 64, &other));
}

static void test_in_addr_prefix_covers(void) {
        struct in_addr p4 = make_in4(10, 0, 0, 0);
        struct in_addr a4 = make_in4(10, 255, 255, 255);
        struct in6_addr p6 = make_in6_link_local();
        struct in6_addr a6 = {};
        a6.s6_addr[0] = 0xfe;
        a6.s6_addr[1] = 0x80;
        a6.s6_addr[15] = 99;
        union in_addr_union u4p = make_union4(p4);
        union in_addr_union u4a = make_union4(a4);
        union in_addr_union u6p;
        union in_addr_union u6a;
        memset(&u6p, 0, sizeof(u6p));
        u6p.in6 = p6;
        memset(&u6a, 0, sizeof(u6a));
        u6a.in6 = a6;

        assert_se(in_addr_prefix_covers(AF_INET, &u4p, 8, &u4a) ==
                   rs_in_addr_prefix_covers(AF_INET, (const union rs_InAddrUnion*)&u4p, 8, (const union rs_InAddrUnion*)&u4a));
        assert_se(in_addr_prefix_covers(AF_INET, &u4p, 8, &u4a));
        assert_se(in_addr_prefix_covers(AF_INET6, &u6p, 64, &u6a) ==
                   rs_in_addr_prefix_covers(AF_INET6, (const union rs_InAddrUnion*)&u6p, 64, (const union rs_InAddrUnion*)&u6a));
        assert_se(in_addr_prefix_covers(AF_INET6, &u6p, 64, &u6a));
}

/* ── in_addr_from_string ──────────────────────────────────────────────── */

static void test_in_addr_from_string(void) {
        union in_addr_union c_buf, rs_buf;
        int rc, rrs;

        /* Valid IPv4 */
        rc = in_addr_from_string(AF_INET, "192.168.1.1", &c_buf);
        rrs = rs_in_addr_from_string(AF_INET, "192.168.1.1", (union rs_InAddrUnion *)&rs_buf);
        assert_se(rc == rrs);
        assert_se(rc == 0);

        /* Valid IPv6 */
        rc = in_addr_from_string(AF_INET6, "::1", &c_buf);
        rrs = rs_in_addr_from_string(AF_INET6, "::1", (union rs_InAddrUnion *)&rs_buf);
        assert_se(rc == rrs);
        assert_se(rc == 0);

        /* Invalid address */
        rc = in_addr_from_string(AF_INET, "not-an-ip", &c_buf);
        rrs = rs_in_addr_from_string(AF_INET, "not-an-ip", (union rs_InAddrUnion *)&rs_buf);
        assert_se(rc == rrs);
        assert_se(rc < 0);

        /* Wrong family */
        rc = in_addr_from_string(99, "1.2.3.4", &c_buf);
        rrs = rs_in_addr_from_string(99, "1.2.3.4", (union rs_InAddrUnion *)&rs_buf);
        assert_se(rc == rrs);
        assert_se(rc < 0);

        /* Verify IPv4 byte layout matches */
        rc = in_addr_from_string(AF_INET, "10.0.0.1", &c_buf);
        rrs = rs_in_addr_from_string(AF_INET, "10.0.0.1", (union rs_InAddrUnion *)&rs_buf);
        assert_se(rc == 0 && rrs == 0);
        assert_se(memcmp(&c_buf, &rs_buf, 4) == 0);

        /* Verify IPv6 byte layout matches */
        rc = in_addr_from_string(AF_INET6, "2001:db8::1", &c_buf);
        rrs = rs_in_addr_from_string(AF_INET6, "2001:db8::1", (union rs_InAddrUnion *)&rs_buf);
        assert_se(rc == 0 && rrs == 0);
        assert_se(memcmp(&c_buf, &rs_buf, 16) == 0);
}

/* ── in_addr_from_string_auto ─────────────────────────────────────────── */

static void test_in_addr_from_string_auto(void) {
        union in_addr_union c_buf, rs_buf;
        int c_family, rs_family;
        int rc, rrs;

        /* Auto-detect IPv4 */
        rc = in_addr_from_string_auto("127.0.0.1", &c_family, &c_buf);
        rrs = rs_in_addr_from_string_auto("127.0.0.1", &rs_family, (union rs_InAddrUnion *)&rs_buf);
        assert_se(rc == rrs);
        assert_se(rc == 0);
        assert_se(c_family == rs_family);
        assert_se(c_family == AF_INET);

        /* Auto-detect IPv6 */
        rc = in_addr_from_string_auto("::1", &c_family, &c_buf);
        rrs = rs_in_addr_from_string_auto("::1", &rs_family, (union rs_InAddrUnion *)&rs_buf);
        assert_se(rc == rrs);
        assert_se(rc == 0);
        assert_se(c_family == rs_family);
        assert_se(c_family == AF_INET6);

        /* Invalid string */
        rc = in_addr_from_string_auto("not-valid", &c_family, &c_buf);
        rrs = rs_in_addr_from_string_auto("not-valid", &rs_family, (union rs_InAddrUnion *)&rs_buf);
        assert_se(rc == rrs);
        assert_se(rc < 0);

        /* NULL ret_family */
        rc = in_addr_from_string_auto("10.0.0.1", NULL, &c_buf);
        rrs = rs_in_addr_from_string_auto("10.0.0.1", NULL, (union rs_InAddrUnion *)&rs_buf);
        assert_se(rc == rrs);
        assert_se(rc == 0);
}

/* ── in_addr_to_string ────────────────────────────────────────────────── */

static void test_in_addr_to_string(void) {
        union in_addr_union addr;
        char *c_str = NULL, *rs_str = NULL;
        int rc, rrs;

        /* IPv4 */
        assert_se(in_addr_from_string(AF_INET, "192.168.1.1", &addr) == 0);
        rc = in_addr_to_string(AF_INET, &addr, &c_str);
        rrs = rs_in_addr_to_string(AF_INET, (union rs_InAddrUnion *)&addr, &rs_str);
        assert_se(rc == rrs);
        assert_se(rc == 0);
        assert_se(streq(c_str, rs_str));
        free(c_str); c_str = NULL;
        free(rs_str); rs_str = NULL;

        /* IPv6 */
        assert_se(in_addr_from_string(AF_INET6, "2001:db8::1", &addr) == 0);
        rc = in_addr_to_string(AF_INET6, &addr, &c_str);
        rrs = rs_in_addr_to_string(AF_INET6, (union rs_InAddrUnion *)&addr, &rs_str);
        assert_se(rc == rrs);
        assert_se(rc == 0);
        assert_se(streq(c_str, rs_str));
        free(c_str); c_str = NULL;
        free(rs_str); rs_str = NULL;

        /* IPv4 loopback */
        assert_se(in_addr_from_string(AF_INET, "127.0.0.1", &addr) == 0);
        rc = in_addr_to_string(AF_INET, &addr, &c_str);
        rrs = rs_in_addr_to_string(AF_INET, (union rs_InAddrUnion *)&addr, &rs_str);
        assert_se(rc == rrs);
        assert_se(rc == 0);
        assert_se(streq(c_str, "127.0.0.1"));
        free(c_str); c_str = NULL;
        free(rs_str); rs_str = NULL;

        /* Wrong family */
        rc = in_addr_to_string(99, &addr, &c_str);
        rrs = rs_in_addr_to_string(99, (union rs_InAddrUnion *)&addr, &rs_str);
        assert_se(rc == rrs);
        assert_se(rc < 0);
}

/* ── in_addr_prefix_from_string ───────────────────────────────────────── */

static void test_in_addr_prefix_from_string(void) {
        union in_addr_union c_prefix, rs_prefix;
        unsigned char c_plen, rs_plen;
        int rc, rrs;

        /* IPv4 with prefix */
        rc = in_addr_prefix_from_string("192.168.1.0/24", AF_INET, &c_prefix, &c_plen);
        rrs = rs_in_addr_prefix_from_string("192.168.1.0/24", AF_INET,
                                             (union rs_InAddrUnion *)&rs_prefix, &rs_plen);
        assert_se(rc == rrs);
        assert_se(rc == 0);
        assert_se(c_plen == rs_plen);
        assert_se(c_plen == 24);
        assert_se(memcmp(&c_prefix, &rs_prefix, 4) == 0);

        /* IPv4 without prefix (defaults to /32) */
        rc = in_addr_prefix_from_string("10.0.0.1", AF_INET, &c_prefix, &c_plen);
        rrs = rs_in_addr_prefix_from_string("10.0.0.1", AF_INET,
                                             (union rs_InAddrUnion *)&rs_prefix, &rs_plen);
        assert_se(rc == rrs);
        assert_se(rc == 0);
        assert_se(c_plen == rs_plen);
        assert_se(c_plen == 32);

        /* IPv6 with prefix */
        rc = in_addr_prefix_from_string("2001:db8::/32", AF_INET6, &c_prefix, &c_plen);
        rrs = rs_in_addr_prefix_from_string("2001:db8::/32", AF_INET6,
                                             (union rs_InAddrUnion *)&rs_prefix, &rs_plen);
        assert_se(rc == rrs);
        assert_se(rc == 0);
        assert_se(c_plen == rs_plen);
        assert_se(c_plen == 32);
        assert_se(memcmp(&c_prefix, &rs_prefix, 16) == 0);

        /* IPv6 without prefix (defaults to /128) */
        rc = in_addr_prefix_from_string("::1", AF_INET6, &c_prefix, &c_plen);
        rrs = rs_in_addr_prefix_from_string("::1", AF_INET6,
                                             (union rs_InAddrUnion *)&rs_prefix, &rs_plen);
        assert_se(rc == rrs);
        assert_se(rc == 0);
        assert_se(c_plen == rs_plen);
        assert_se(c_plen == 128);

        /* Invalid address */
        rc = in_addr_prefix_from_string("not-valid/24", AF_INET, &c_prefix, &c_plen);
        rrs = rs_in_addr_prefix_from_string("not-valid/24", AF_INET,
                                             (union rs_InAddrUnion *)&rs_prefix, &rs_plen);
        assert_se(rc == rrs);
        assert_se(rc < 0);

        /* Invalid prefix length */
        rc = in_addr_prefix_from_string("10.0.0.1/99", AF_INET, &c_prefix, &c_plen);
        rrs = rs_in_addr_prefix_from_string("10.0.0.1/99", AF_INET,
                                             (union rs_InAddrUnion *)&rs_prefix, &rs_plen);
        assert_se(rc == rrs);
        assert_se(rc < 0);
}

/* ── in_addr_prefix_from_string_auto_full ─────────────────────────────── */

static void test_in_addr_prefix_from_string_auto_full(void) {
        union in_addr_union c_prefix, rs_prefix;
        unsigned char c_plen, rs_plen;
        int c_family, rs_family;
        int rc, rrs;

        /* IPv4 with prefix, auto-detect */
        rc = in_addr_prefix_from_string_auto_full("192.168.1.0/24", PREFIXLEN_FULL,
                                                   &c_family, &c_prefix, &c_plen);
        rrs = rs_in_addr_prefix_from_string_auto_full("192.168.1.0/24", PREFIXLEN_FULL,
                                                       &rs_family, (union rs_InAddrUnion *)&rs_prefix, &rs_plen);
        assert_se(rc == rrs);
        assert_se(rc == 0);
        assert_se(c_family == rs_family);
        assert_se(c_family == AF_INET);
        assert_se(c_plen == rs_plen);
        assert_se(c_plen == 24);

        /* IPv6 with prefix, auto-detect */
        rc = in_addr_prefix_from_string_auto_full("2001:db8::/32", PREFIXLEN_FULL,
                                                   &c_family, &c_prefix, &c_plen);
        rrs = rs_in_addr_prefix_from_string_auto_full("2001:db8::/32", PREFIXLEN_FULL,
                                                       &rs_family, (union rs_InAddrUnion *)&rs_prefix, &rs_plen);
        assert_se(rc == rrs);
        assert_se(rc == 0);
        assert_se(c_family == rs_family);
        assert_se(c_family == AF_INET6);
        assert_se(c_plen == rs_plen);
        assert_se(c_plen == 32);
        assert_se(memcmp(&c_prefix, &rs_prefix, 16) == 0);

        /* No prefix, PREFIXLEN_FULL mode */
        rc = in_addr_prefix_from_string_auto_full("10.0.0.1", PREFIXLEN_FULL,
                                                   &c_family, &c_prefix, &c_plen);
        rrs = rs_in_addr_prefix_from_string_auto_full("10.0.0.1", PREFIXLEN_FULL,
                                                       &rs_family, (union rs_InAddrUnion *)&rs_prefix, &rs_plen);
        assert_se(rc == rrs);
        assert_se(rc == 0);
        assert_se(c_family == rs_family);
        assert_se(c_plen == rs_plen);
        assert_se(c_plen == 32);

        /* No prefix, PREFIXLEN_REFUSE mode */
        rc = in_addr_prefix_from_string_auto_full("10.0.0.1", PREFIXLEN_REFUSE,
                                                   &c_family, &c_prefix, &c_plen);
        rrs = rs_in_addr_prefix_from_string_auto_full("10.0.0.1", PREFIXLEN_REFUSE,
                                                       &rs_family, (union rs_InAddrUnion *)&rs_prefix, &rs_plen);
        assert_se(rc == rrs);
        assert_se(rc < 0);

        /* Invalid address */
        rc = in_addr_prefix_from_string_auto_full("not-valid/24", PREFIXLEN_FULL,
                                                   &c_family, &c_prefix, &c_plen);
        rrs = rs_in_addr_prefix_from_string_auto_full("not-valid/24", PREFIXLEN_FULL,
                                                       &rs_family, (union rs_InAddrUnion *)&rs_prefix, &rs_plen);
        assert_se(rc == rrs);
        assert_se(rc < 0);
}

/* ── in_addr_prefix_range ─────────────────────────────────────────────── */

static void test_in_addr_prefix_range(void) {
        union in_addr_union c_start, c_end, rs_start, rs_end;
        union in_addr_union addr;
        int rc, rrs;

        /* IPv4 /24 */
        assert_se(in_addr_from_string(AF_INET, "192.168.1.50", &addr) == 0);
        rc = in_addr_prefix_range(AF_INET, &addr, 24, &c_start, &c_end);
        rrs = rs_in_addr_prefix_range(AF_INET, (union rs_InAddrUnion *)&addr, 24,
                                       (union rs_InAddrUnion *)&rs_start, (union rs_InAddrUnion *)&rs_end);
        assert_se(rc == rrs);
        assert_se(rc == 0);
        assert_se(memcmp(&c_start, &rs_start, 4) == 0);
        assert_se(memcmp(&c_end, &rs_end, 4) == 0);

        /* IPv6 /64 */
        assert_se(in_addr_from_string(AF_INET6, "2001:db8::1", &addr) == 0);
        rc = in_addr_prefix_range(AF_INET6, &addr, 64, &c_start, &c_end);
        rrs = rs_in_addr_prefix_range(AF_INET6, (union rs_InAddrUnion *)&addr, 64,
                                       (union rs_InAddrUnion *)&rs_start, (union rs_InAddrUnion *)&rs_end);
        assert_se(rc == rrs);
        assert_se(rc == 0);
        assert_se(memcmp(&c_start, &rs_start, 16) == 0);
        assert_se(memcmp(&c_end, &rs_end, 16) == 0);

        /* NULL ret_start */
        rc = in_addr_prefix_range(AF_INET, &addr, 24, NULL, &c_end);
        rrs = rs_in_addr_prefix_range(AF_INET, (union rs_InAddrUnion *)&addr, 24,
                                       NULL, (union rs_InAddrUnion *)&rs_end);
        assert_se(rc == rrs);
        assert_se(rc == 0);

        /* NULL ret_end */
        rc = in_addr_prefix_range(AF_INET, &addr, 24, &c_start, NULL);
        rrs = rs_in_addr_prefix_range(AF_INET, (union rs_InAddrUnion *)&addr, 24,
                                       (union rs_InAddrUnion *)&rs_start, NULL);
        assert_se(rc == rrs);
        assert_se(rc == 0);

        /* The C implementation computes both local results before publishing
         * either one. An overflow while calculating the end must therefore
         * leave both caller outputs intact. */
        assert_se(in_addr_from_string(AF_INET, "255.255.255.0", &addr) == 0);
        memset(&c_start, 0xa5, sizeof(c_start));
        memset(&c_end, 0x5a, sizeof(c_end));
        memset(&rs_start, 0xa5, sizeof(rs_start));
        memset(&rs_end, 0x5a, sizeof(rs_end));
        rc = in_addr_prefix_range(AF_INET, &addr, 24, &c_start, &c_end);
        rrs = rs_in_addr_prefix_range(AF_INET, (union rs_InAddrUnion *)&addr, 24,
                                       (union rs_InAddrUnion *)&rs_start, (union rs_InAddrUnion *)&rs_end);
        assert_se(rc == rrs);
        assert_se(rc == -ERANGE);
        assert_se(memcmp(&c_start, &rs_start, sizeof(c_start)) == 0);
        assert_se(memcmp(&c_end, &rs_end, sizeof(c_end)) == 0);
}

/* ── in_addr_prefix_to_string ─────────────────────────────────────────── */

static void test_in_addr_prefix_to_string(void) {
        union in_addr_union addr;
        char c_buf[128], rs_buf[128];
        int rc, rrs;

        /* IPv4 /24 */
        assert_se(in_addr_from_string(AF_INET, "192.168.1.0", &addr) == 0);
        rc = in_addr_prefix_to_string(AF_INET, &addr, 24, c_buf, sizeof(c_buf));
        rrs = rs_in_addr_prefix_to_string(AF_INET, (union rs_InAddrUnion *)&addr, 24, rs_buf, sizeof(rs_buf));
        assert_se(rc == rrs);
        assert_se(rc == 0);
        assert_se(streq(c_buf, rs_buf));
        assert_se(streq(c_buf, "192.168.1.0/24"));

        /* IPv6 /32 */
        assert_se(in_addr_from_string(AF_INET6, "2001:db8::", &addr) == 0);
        rc = in_addr_prefix_to_string(AF_INET6, &addr, 32, c_buf, sizeof(c_buf));
        rrs = rs_in_addr_prefix_to_string(AF_INET6, (union rs_InAddrUnion *)&addr, 32, rs_buf, sizeof(rs_buf));
        assert_se(rc == rrs);
        assert_se(rc == 0);
        assert_se(streq(c_buf, rs_buf));

        /* IPv4 /32 */
        assert_se(in_addr_from_string(AF_INET, "10.0.0.1", &addr) == 0);
        rc = in_addr_prefix_to_string(AF_INET, &addr, 32, c_buf, sizeof(c_buf));
        rrs = rs_in_addr_prefix_to_string(AF_INET, (union rs_InAddrUnion *)&addr, 32, rs_buf, sizeof(rs_buf));
        assert_se(rc == rrs);
        assert_se(rc == 0);
        assert_se(streq(c_buf, "10.0.0.1/32"));

        /* Buffer too small */
        rc = in_addr_prefix_to_string(AF_INET, &addr, 32, c_buf, 5);
        rrs = rs_in_addr_prefix_to_string(AF_INET, (union rs_InAddrUnion *)&addr, 32, rs_buf, 5);
        assert_se(rc == rrs);
        assert_se(rc < 0);
}

/* ── in_addr_prefix_covers_full ───────────────────────────────────────── */

static void test_in_addr_prefix_covers_full(void) {
        struct in_addr c_p4, c_a4;
        struct rs_InAddr rs_p4, rs_a4;
        int rc, rrs;

        /* IPv4: 10.0.0.0/8 covers 10.1.2.3/32 */
        inet_pton(AF_INET, "10.0.0.0", &c_p4);
        inet_pton(AF_INET, "10.1.2.3", &c_a4);
        rc = in4_addr_prefix_covers_full(&c_p4, 8, &c_a4, 32);
        rrs = rs_in4_addr_prefix_covers_full(&rs_p4, 8, &rs_a4, 32);
        /* Use same memory layout — cast from C to Rust type */
        rrs = rs_in4_addr_prefix_covers_full((const struct rs_InAddr *)&c_p4, 8,
                                              (const struct rs_InAddr *)&c_a4, 32);
        assert_se(rc == rrs);
        assert_se(rc > 0);

        /* IPv4: 192.168.1.0/24 does NOT cover 192.168.2.0/24 */
        inet_pton(AF_INET, "192.168.1.0", &c_p4);
        inet_pton(AF_INET, "192.168.2.0", &c_a4);
        rc = in4_addr_prefix_covers_full(&c_p4, 24, &c_a4, 24);
        rrs = rs_in4_addr_prefix_covers_full((const struct rs_InAddr *)&c_p4, 24,
                                              (const struct rs_InAddr *)&c_a4, 24);
        assert_se(rc == rrs);
        assert_se(rc == 0);

        /* prefixlen > address_prefixlen: false */
        rc = in4_addr_prefix_covers_full(&c_p4, 32, &c_a4, 24);
        rrs = rs_in4_addr_prefix_covers_full((const struct rs_InAddr *)&c_p4, 32,
                                              (const struct rs_InAddr *)&c_a4, 24);
        assert_se(rc == rrs);
        assert_se(rc == 0);

        /* union version */
        union in_addr_union u_prefix, u_addr;
        assert_se(in_addr_from_string(AF_INET, "10.0.0.0", &u_prefix) == 0);
        assert_se(in_addr_from_string(AF_INET, "10.200.0.0", &u_addr) == 0);
        rc = in_addr_prefix_covers_full(AF_INET, &u_prefix, 8, &u_addr, 32);
        rrs = rs_in_addr_prefix_covers_full(AF_INET, (const union rs_InAddrUnion *)&u_prefix, 8,
                                              (const union rs_InAddrUnion *)&u_addr, 32);
        assert_se(rc == rrs);
        assert_se(rc > 0);

        /* IPv6 */
        assert_se(in_addr_from_string(AF_INET6, "2001:db8::", &u_prefix) == 0);
        assert_se(in_addr_from_string(AF_INET6, "2001:db8::1", &u_addr) == 0);
        rc = in_addr_prefix_covers_full(AF_INET6, &u_prefix, 32, &u_addr, 128);
        rrs = rs_in_addr_prefix_covers_full(AF_INET6, (const union rs_InAddrUnion *)&u_prefix, 32,
                                              (const union rs_InAddrUnion *)&u_addr, 128);
        assert_se(rc == rrs);
        assert_se(rc > 0);
}

/* ── in6_addr_compare_func ─────────────────────────────────────────────── */

static void test_in6_addr_compare_func(void) {
        struct in6_addr a, b;
        int rc, rrs;

        memset(&a, 0, sizeof(a));
        memset(&b, 0, sizeof(b));

        /* Equal */
        rc = in6_addr_compare_func(&a, &b);
        rrs = rs_in6_addr_compare_func((const struct rs_In6Addr *)&a, (const struct rs_In6Addr *)&b);
        assert_se(rc == rrs);
        assert_se(rc == 0);

        /* a < b */
        a.s6_addr[15] = 1;
        b.s6_addr[15] = 2;
        rc = in6_addr_compare_func(&a, &b);
        rrs = rs_in6_addr_compare_func((const struct rs_In6Addr *)&a, (const struct rs_In6Addr *)&b);
        assert_se(rc == rrs);
        assert_se(rc < 0);

        /* a > b */
        a.s6_addr[15] = 255;
        rc = in6_addr_compare_func(&a, &b);
        rrs = rs_in6_addr_compare_func((const struct rs_In6Addr *)&a, (const struct rs_In6Addr *)&b);
        assert_se(rc == rrs);
        assert_se(rc > 0);
}

/* ── in_addr_data_compare_func ─────────────────────────────────────────── */

static void test_in_addr_data_compare_func(void) {
        struct in_addr_data c_x, c_y;
        int rc, rrs;

        memset(&c_x, 0, sizeof(c_x));
        memset(&c_y, 0, sizeof(c_y));

        /* Equal */
        c_x.family = AF_INET;
        c_y.family = AF_INET;
        inet_pton(AF_INET, "10.0.0.1", &c_x.address.in);
        inet_pton(AF_INET, "10.0.0.1", &c_y.address.in);
        rc = in_addr_data_compare_func(&c_x, &c_y);
        rrs = rs_in_addr_data_compare_func((const struct rs_InAddrData *)&c_x,
                                            (const struct rs_InAddrData *)&c_y);
        assert_se(rc == rrs);
        assert_se(rc == 0);

        /* Different family */
        c_y.family = AF_INET6;
        rc = in_addr_data_compare_func(&c_x, &c_y);
        rrs = rs_in_addr_data_compare_func((const struct rs_InAddrData *)&c_x,
                                            (const struct rs_InAddrData *)&c_y);
        assert_se(rc == rrs);
        assert_se(rc < 0);

        /* Same family, different address */
        c_y.family = AF_INET;
        inet_pton(AF_INET, "10.0.0.2", &c_y.address.in);
        rc = in_addr_data_compare_func(&c_x, &c_y);
        rrs = rs_in_addr_data_compare_func((const struct rs_InAddrData *)&c_x,
                                            (const struct rs_InAddrData *)&c_y);
        assert_se(rc == rrs);
        assert_se(rc < 0);

        /* Same family, different address (reverse) */
        rc = in_addr_data_compare_func(&c_y, &c_x);
        rrs = rs_in_addr_data_compare_func((const struct rs_InAddrData *)&c_y,
                                            (const struct rs_InAddrData *)&c_x);
        assert_se(rc == rrs);
        assert_se(rc > 0);
}

/* ── Main ───────────────────────────────────────────────────────────────── */

static void test_PTR_TO_IN4_ADDR(void) {
        struct in_addr c_addr;
        struct rs_InAddr rs_addr;
        void *ptr = (void *)(uintptr_t)0xC0A80001;

        PTR_TO_IN4_ADDR(ptr, &c_addr);
        rs_PTR_TO_IN4_ADDR(ptr, &rs_addr);
        assert_se(c_addr.s_addr == rs_addr.s_addr);
}

static void test_IN4_ADDR_TO_PTR(void) {
        struct in_addr addr = { .s_addr = 0x0A000002 };
        void *c_ptr = IN4_ADDR_TO_PTR(&addr);
        void *rs_ptr = rs_IN4_ADDR_TO_PTR((const struct rs_InAddr*)&addr);
        assert_se(c_ptr == rs_ptr);
}

static void test_IN4_ADDR_TO_PTR_NULL(void) {
        void *rs_ptr = rs_IN4_ADDR_TO_PTR(NULL);
        assert_se(rs_ptr == NULL);
}

static void test_FAMILY_ADDRESS_SIZE(void) {
        assert_se(FAMILY_ADDRESS_SIZE(AF_INET) == rs_FAMILY_ADDRESS_SIZE(AF_INET));
        assert_se(FAMILY_ADDRESS_SIZE(AF_INET) == 4);
        assert_se(FAMILY_ADDRESS_SIZE(AF_INET6) == rs_FAMILY_ADDRESS_SIZE(AF_INET6));
        assert_se(FAMILY_ADDRESS_SIZE(AF_INET6) == 16);
}

int main(int argc, char **argv) {
        test_in4_addr_is_null();
        test_in6_addr_is_null();
        test_in_addr_is_null();
        test_in4_addr_is_link_local();
        test_in4_addr_is_link_local_dynamic();
        test_in6_addr_is_link_local();
        test_in_addr_is_link_local();
        test_in6_addr_is_link_local_all_nodes();
        test_in4_addr_is_multicast();
        test_in6_addr_is_multicast();
        test_in_addr_is_multicast();
        test_in4_addr_is_local_multicast();
        test_in4_addr_is_localhost();
        test_in4_addr_is_non_local();
        test_in_addr_is_localhost();
        test_in_addr_is_localhost_one();
        test_in4_addr_equal();
        test_in6_addr_equal();
        test_in_addr_equal();
        test_in6_addr_is_ipv4_mapped();
        test_in4_addr_prefix_intersect();
        test_in6_addr_prefix_intersect();
        test_in_addr_prefix_intersect();
        test_in_addr_prefix_nth();
        test_in_addr_prefix_next();
        test_in4_addr_netmask_to_prefixlen();
        test_in4_addr_prefixlen_to_netmask();
        test_in6_addr_prefixlen_to_netmask();
        test_in_addr_prefixlen_to_netmask();
        test_in4_addr_default_prefixlen();
        test_in4_addr_mask();
        test_in6_addr_mask();
        test_in_addr_mask();
        test_in4_addr_prefix_covers();
        test_in6_addr_prefix_covers();
        test_in_addr_prefix_covers();
        test_PTR_TO_IN4_ADDR();
        test_IN4_ADDR_TO_PTR();
        test_IN4_ADDR_TO_PTR_NULL();
        test_FAMILY_ADDRESS_SIZE();
        test_in_addr_from_string();
        test_in_addr_from_string_auto();
        test_in_addr_to_string();
        test_in_addr_prefix_from_string();
        test_in_addr_prefix_from_string_auto_full();
        test_in_addr_prefix_range();
        test_in_addr_prefix_to_string();
        test_in_addr_prefix_covers_full();
        test_in6_addr_compare_func();
        test_in_addr_data_compare_func();

        return 0;
}
