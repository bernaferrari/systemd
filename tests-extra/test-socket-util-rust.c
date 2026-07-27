/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Shadow test: C socket-util functions vs Rust */

#include "tests.h"
#include "in-addr-util.h"
#include "socket-util.h"
#include <linux/if.h>

/* Rust FFI */
#include "rust/socket_util.h"

/* ── ifname_valid_char ─────────────────────────────────────────────────── */

static void test_ifname_valid_char(void) {
        bool cb, rb;

        /* Valid characters */
        cb = ifname_valid_char('a'); rb = rs_ifname_valid_char('a');
        assert_se(cb == rb); assert_se(cb == true);

        cb = ifname_valid_char('Z'); rb = rs_ifname_valid_char('Z');
        assert_se(cb == rb); assert_se(cb == true);

        cb = ifname_valid_char('0'); rb = rs_ifname_valid_char('0');
        assert_se(cb == rb); assert_se(cb == true);

        cb = ifname_valid_char('9'); rb = rs_ifname_valid_char('9');
        assert_se(cb == rb); assert_se(cb == true);

        cb = ifname_valid_char('-'); rb = rs_ifname_valid_char('-');
        assert_se(cb == rb); assert_se(cb == true);

        cb = ifname_valid_char('_'); rb = rs_ifname_valid_char('_');
        assert_se(cb == rb); assert_se(cb == true);

        cb = ifname_valid_char('.'); rb = rs_ifname_valid_char('.');
        assert_se(cb == rb); assert_se(cb == true);

        /* Invalid characters */
        cb = ifname_valid_char(':'); rb = rs_ifname_valid_char(':');
        assert_se(cb == rb); assert_se(cb == false);

        cb = ifname_valid_char('/'); rb = rs_ifname_valid_char('/');
        assert_se(cb == rb); assert_se(cb == false);

        cb = ifname_valid_char('%'); rb = rs_ifname_valid_char('%');
        assert_se(cb == rb); assert_se(cb == false);

        cb = ifname_valid_char(' '); rb = rs_ifname_valid_char(' ');
        assert_se(cb == rb); assert_se(cb == false);

        cb = ifname_valid_char('\t'); rb = rs_ifname_valid_char('\t');
        assert_se(cb == rb); assert_se(cb == false);

        cb = ifname_valid_char('\n'); rb = rs_ifname_valid_char('\n');
        assert_se(cb == rb); assert_se(cb == false);

        cb = ifname_valid_char(127); rb = rs_ifname_valid_char(127);
        assert_se(cb == rb); assert_se(cb == false);

        cb = ifname_valid_char(128); rb = rs_ifname_valid_char(128);
        assert_se(cb == rb); assert_se(cb == false);

        cb = ifname_valid_char(0); rb = rs_ifname_valid_char(0);
        assert_se(cb == rb); assert_se(cb == false);
}

/* ── ifname_valid_full ─────────────────────────────────────────────────── */

static void test_ifname_valid_full(void) {
        bool cb, rb;

        /* Valid names */
        cb = ifname_valid("eth0"); rb = rs_ifname_valid_full("eth0", 0);
        assert_se(cb == rb); assert_se(cb == true);

        cb = ifname_valid("wlan0"); rb = rs_ifname_valid_full("wlan0", 0);
        assert_se(cb == rb); assert_se(cb == true);

        cb = ifname_valid("lo"); rb = rs_ifname_valid_full("lo", 0);
        assert_se(cb == rb); assert_se(cb == true);

        cb = ifname_valid("enp0s3"); rb = rs_ifname_valid_full("enp0s3", 0);
        assert_se(cb == rb); assert_se(cb == true);

        cb = ifname_valid("a"); rb = rs_ifname_valid_full("a", 0);
        assert_se(cb == rb); assert_se(cb == true);

        /* Invalid: empty */
        cb = ifname_valid(""); rb = rs_ifname_valid_full("", 0);
        assert_se(cb == rb); assert_se(cb == false);

        /* Invalid: too long */
        char too_long[IFNAMSIZ + 2];
        memset(too_long, 'a', IFNAMSIZ + 1);
        too_long[IFNAMSIZ + 1] = '\0';
        cb = ifname_valid(too_long); rb = rs_ifname_valid_full(too_long, 0);
        assert_se(cb == rb); assert_se(cb == false);

        /* Invalid: colon */
        cb = ifname_valid("eth0:1"); rb = rs_ifname_valid_full("eth0:1", 0);
        assert_se(cb == rb); assert_se(cb == false);

        /* Invalid: slash */
        cb = ifname_valid("eth/0"); rb = rs_ifname_valid_full("eth/0", 0);
        assert_se(cb == rb); assert_se(cb == false);

        /* Invalid: percent */
        cb = ifname_valid("eth%0"); rb = rs_ifname_valid_full("eth%0", 0);
        assert_se(cb == rb); assert_se(cb == false);

        /* Invalid: dot and dot-dot */
        cb = ifname_valid("."); rb = rs_ifname_valid_full(".", 0);
        assert_se(cb == rb); assert_se(cb == false);

        cb = ifname_valid(".."); rb = rs_ifname_valid_full("..", 0);
        assert_se(cb == rb); assert_se(cb == false);

        /* Invalid: "all" and "default" without IFNAME_VALID_SPECIAL */
        cb = ifname_valid("all"); rb = rs_ifname_valid_full("all", 0);
        assert_se(cb == rb); assert_se(cb == false);

        cb = ifname_valid("default"); rb = rs_ifname_valid_full("default", 0);
        assert_se(cb == rb); assert_se(cb == false);

        /* Valid: "all" and "default" WITH IFNAME_VALID_SPECIAL */
        cb = ifname_valid_full("all", IFNAME_VALID_SPECIAL);
        rb = rs_ifname_valid_full("all", IFNAME_VALID_SPECIAL);
        assert_se(cb == rb); assert_se(cb == true);

        cb = ifname_valid_full("default", IFNAME_VALID_SPECIAL);
        rb = rs_ifname_valid_full("default", IFNAME_VALID_SPECIAL);
        assert_se(cb == rb); assert_se(cb == true);

        /* Numeric: valid ifindex */
        cb = ifname_valid_full("1", IFNAME_VALID_NUMERIC);
        rb = rs_ifname_valid_full("1", IFNAME_VALID_NUMERIC);
        assert_se(cb == rb); assert_se(cb == true);

        /* Numeric: not allowed without IFNAME_VALID_NUMERIC */
        cb = ifname_valid_full("1", 0);
        rb = rs_ifname_valid_full("1", 0);
        assert_se(cb == rb); assert_se(cb == false);

        /* Invalid: purely numeric but too large for ifindex */
        cb = ifname_valid_full("9999999999", 0);
        rb = rs_ifname_valid_full("9999999999", 0);
        assert_se(cb == rb); assert_se(cb == false);

        /* Invalid: purely numeric zero */
        cb = ifname_valid_full("0", 0);
        rb = rs_ifname_valid_full("0", 0);
        assert_se(cb == rb); assert_se(cb == false);

        /* Alternative name: shorter limit */
        char alt_long[ALTIFNAMSIZ + 2];
        memset(alt_long, 'a', ALTIFNAMSIZ + 1);
        alt_long[ALTIFNAMSIZ + 1] = '\0';
        cb = ifname_valid_full(alt_long, IFNAME_VALID_ALTERNATIVE);
        rb = rs_ifname_valid_full(alt_long, IFNAME_VALID_ALTERNATIVE);
        assert_se(cb == rb); assert_se(cb == false);
}

/* ── vsock_parse_port ──────────────────────────────────────────────────── */

static void test_vsock_parse_port(void) {
        unsigned cr, rr;
        int rc, rrr;

        /* Valid ports */
        rc = vsock_parse_port("80", &cr); rrr = rs_vsock_parse_port("80", &rr);
        assert_se(rc == rrr); assert_se(rc == 0); assert_se(cr == rr);

        rc = vsock_parse_port("0", &cr); rrr = rs_vsock_parse_port("0", &rr);
        assert_se(rc == rrr); assert_se(rc == 0); assert_se(cr == rr);

        rc = vsock_parse_port("4294967294", &cr); rrr = rs_vsock_parse_port("4294967294", &rr);
        assert_se(rc == rrr); assert_se(rc == 0); assert_se(cr == rr);

        /* Invalid: UINT32_MAX = VMADDR_PORT_ANY */
        rc = vsock_parse_port("4294967295", &cr); rrr = rs_vsock_parse_port("4294967295", &rr);
        assert_se(rc == rrr); assert_se(rc < 0);

        /* Invalid: negative / non-numeric */
        rc = vsock_parse_port("-1", &cr); rrr = rs_vsock_parse_port("-1", &rr);
        assert_se(rc == rrr); assert_se(rc < 0);

        rc = vsock_parse_port("abc", &cr); rrr = rs_vsock_parse_port("abc", &rr);
        assert_se(rc == rrr); assert_se(rc < 0);

        rc = vsock_parse_port("", &cr); rrr = rs_vsock_parse_port("", &rr);
        assert_se(rc == rrr); assert_se(rc < 0);
}

/* ── vsock_parse_cid ───────────────────────────────────────────────────── */

static void test_vsock_parse_cid(void) {
        unsigned cr, rr;
        int rc, rrr;

        /* Named CIDs */
        rc = vsock_parse_cid("hypervisor", &cr); rrr = rs_vsock_parse_cid("hypervisor", &rr);
        assert_se(rc == rrr); assert_se(rc == 0); assert_se(cr == rr);
        assert_se(cr == VMADDR_CID_HYPERVISOR);

        rc = vsock_parse_cid("local", &cr); rrr = rs_vsock_parse_cid("local", &rr);
        assert_se(rc == rrr); assert_se(rc == 0); assert_se(cr == rr);
        assert_se(cr == VMADDR_CID_LOCAL);

        rc = vsock_parse_cid("host", &cr); rrr = rs_vsock_parse_cid("host", &rr);
        assert_se(rc == rrr); assert_se(rc == 0); assert_se(cr == rr);
        assert_se(cr == VMADDR_CID_HOST);

        /* Numeric CID */
        rc = vsock_parse_cid("42", &cr); rrr = rs_vsock_parse_cid("42", &rr);
        assert_se(rc == rrr); assert_se(rc == 0); assert_se(cr == rr);

        /* Invalid: non-numeric */
        rc = vsock_parse_cid("abc", &cr); rrr = rs_vsock_parse_cid("abc", &rr);
        assert_se(rc == rrr); assert_se(rc < 0);

        rc = vsock_parse_cid("", &cr); rrr = rs_vsock_parse_cid("", &rr);
        assert_se(rc == rrr); assert_se(rc < 0);

        rc = vsock_parse_cid("-1", &cr); rrr = rs_vsock_parse_cid("-1", &rr);
        assert_se(rc == rrr); assert_se(rc < 0);
}

/* ── sockaddr_port ─────────────────────────────────────────────────────── */

static void test_sockaddr_port(void) {
        union sockaddr_union sa;
        unsigned cr, rr;
        int rc, rrr;

        /* AF_INET */
        memset(&sa, 0, sizeof(sa));
        sa.in.sin_family = AF_INET;
        sa.in.sin_port = htobe16(8080);

        rc = sockaddr_port(&sa.sa, &cr);
        rrr = rs_sockaddr_port(&sa, &rr);
        assert_se(rc == rrr); assert_se(rc == 0); assert_se(cr == rr);
        assert_se(cr == 8080);

        /* AF_INET6 */
        memset(&sa, 0, sizeof(sa));
        sa.in6.sin6_family = AF_INET6;
        sa.in6.sin6_port = htobe16(443);

        rc = sockaddr_port(&sa.sa, &cr);
        rrr = rs_sockaddr_port(&sa, &rr);
        assert_se(rc == rrr); assert_se(rc == 0); assert_se(cr == rr);
        assert_se(cr == 443);

        /* AF_VSOCK */
        memset(&sa, 0, sizeof(sa));
        sa.vm.svm_family = AF_VSOCK;
        sa.vm.svm_cid = 3;
        sa.vm.svm_port = 1234;

        rc = sockaddr_port(&sa.sa, &cr);
        rrr = rs_sockaddr_port(&sa, &rr);
        assert_se(rc == rrr); assert_se(rc == 0); assert_se(cr == rr);
        assert_se(cr == 1234);

        /* AF_UNIX — unsupported */
        memset(&sa, 0, sizeof(sa));
        sa.un.sun_family = AF_UNIX;

        rc = sockaddr_port(&sa.sa, &cr);
        rrr = rs_sockaddr_port(&sa, &rr);
        assert_se(rc == rrr); assert_se(rc < 0);
}

/* ── sockaddr_in_addr ──────────────────────────────────────────────────── */

static void test_sockaddr_in_addr(void) {
        union sockaddr_union sa;
        const union in_addr_union *cr, *rr;

        /* AF_INET */
        memset(&sa, 0, sizeof(sa));
        sa.in.sin_family = AF_INET;
        sa.in.sin_addr.s_addr = htobe32(0xC0A80001); /* 192.168.0.1 */

        cr = sockaddr_in_addr(&sa.sa);
        rr = rs_sockaddr_in_addr(&sa);
        assert_se(cr != NULL);
        assert_se(rr != NULL);
        assert_se(memcmp(cr, rr, sizeof(struct in_addr)) == 0);

        /* AF_INET6 */
        memset(&sa, 0, sizeof(sa));
        sa.in6.sin6_family = AF_INET6;
        sa.in6.sin6_addr.s6_addr[0] = 0x20;
        sa.in6.sin6_addr.s6_addr[1] = 0x01;

        cr = sockaddr_in_addr(&sa.sa);
        rr = rs_sockaddr_in_addr(&sa);
        assert_se(cr != NULL);
        assert_se(rr != NULL);
        assert_se(memcmp(&cr->in6, rr, sizeof(struct in6_addr)) == 0);

        /* AF_UNIX — unsupported */
        memset(&sa, 0, sizeof(sa));
        sa.un.sun_family = AF_UNIX;

        cr = sockaddr_in_addr(&sa.sa);
        rr = rs_sockaddr_in_addr(&sa);
        assert_se(cr == NULL);
        assert_se(rr == NULL);

        /* NULL */
        cr = sockaddr_in_addr(NULL);
        rr = rs_sockaddr_in_addr(NULL);
        assert_se(cr == NULL);
        assert_se(rr == NULL);
}

/* ── sockaddr_set_in_addr ──────────────────────────────────────────────── */

static void test_sockaddr_set_in_addr(void) {
        union sockaddr_union sa_c, sa_r;
        union in_addr_union addr;
        int rc, rrr;

        /* AF_INET */
        memset(&addr, 0, sizeof(addr));
        addr.in.s_addr = htobe32(0x0A000001); /* 10.0.0.1 */

        memset(&sa_c, 0, sizeof(sa_c));
        memset(&sa_r, 0, sizeof(sa_r));
        rc = sockaddr_set_in_addr(&sa_c, AF_INET, &addr, 1234);
        rrr = rs_sockaddr_set_in_addr(&sa_r, AF_INET, &addr, 1234);
        assert_se(rc == rrr); assert_se(rc == 0);
        assert_se(sa_c.in.sin_family == sa_r.in.sin_family);
        assert_se(sa_c.in.sin_port == sa_r.in.sin_port);
        assert_se(sa_c.in.sin_addr.s_addr == sa_r.in.sin_addr.s_addr);

        /* AF_INET6 */
        memset(&addr, 0, sizeof(addr));
        addr.in6.s6_addr[0] = 0xFE;
        addr.in6.s6_addr[1] = 0x80;

        memset(&sa_c, 0, sizeof(sa_c));
        memset(&sa_r, 0, sizeof(sa_r));
        rc = sockaddr_set_in_addr(&sa_c, AF_INET6, &addr, 5678);
        rrr = rs_sockaddr_set_in_addr(&sa_r, AF_INET6, &addr, 5678);
        assert_se(rc == rrr); assert_se(rc == 0);
        assert_se(sa_c.in6.sin6_family == sa_r.in6.sin6_family);
        assert_se(sa_c.in6.sin6_port == sa_r.in6.sin6_port);
        assert_se(memcmp(&sa_c.in6.sin6_addr, &sa_r.in6.sin6_addr, 16) == 0);

        /* Unsupported family */
        rc = sockaddr_set_in_addr(&sa_c, AF_UNIX, &addr, 80);
        rrr = rs_sockaddr_set_in_addr(&sa_r, AF_UNIX, &addr, 80);
        assert_se(rc == rrr); assert_se(rc < 0);
}

/* ── ifname_valid ───────────────────────────────────────────────────────── */

static void test_ifname_valid(void) {
        bool cb, rb;

        cb = ifname_valid("eth0"); rb = rs_ifname_valid("eth0");
        assert_se(cb == rb); assert_se(cb == true);

        cb = ifname_valid("lo"); rb = rs_ifname_valid("lo");
        assert_se(cb == rb); assert_se(cb == true);

        cb = ifname_valid("wlan1"); rb = rs_ifname_valid("wlan1");
        assert_se(cb == rb); assert_se(cb == true);

        /* Invalid: empty */
        cb = ifname_valid(""); rb = rs_ifname_valid("");
        assert_se(cb == rb); assert_se(cb == false);

        /* Invalid: NULL */
        rb = rs_ifname_valid(NULL);
        assert_se(rb == false);

        /* Invalid: "all" and "default" */
        cb = ifname_valid("all"); rb = rs_ifname_valid("all");
        assert_se(cb == rb); assert_se(cb == false);

        cb = ifname_valid("default"); rb = rs_ifname_valid("default");
        assert_se(cb == rb); assert_se(cb == false);

        /* Invalid: fully numeric */
        cb = ifname_valid("1"); rb = rs_ifname_valid("1");
        assert_se(cb == rb); assert_se(cb == false);

        /* Invalid: colon, slash, percent */
        cb = ifname_valid("eth:0"); rb = rs_ifname_valid("eth:0");
        assert_se(cb == rb); assert_se(cb == false);

        cb = ifname_valid("eth/0"); rb = rs_ifname_valid("eth/0");
        assert_se(cb == rb); assert_se(cb == false);

        cb = ifname_valid("eth%0"); rb = rs_ifname_valid("eth%0");
        assert_se(cb == rb); assert_se(cb == false);
}

/* ── address_label_valid ───────────────────────────────────────────────── */

static void test_address_label_valid(void) {
        bool cb, rb;
        const char high_byte[] = { (char) 0x80, 0 };

        cb = address_label_valid("eth0"); rb = rs_address_label_valid("eth0");
        assert_se(cb == rb); assert_se(cb == true);

        cb = address_label_valid("lo"); rb = rs_address_label_valid("lo");
        assert_se(cb == rb); assert_se(cb == true);

        /* Invalid: empty */
        cb = address_label_valid(""); rb = rs_address_label_valid("");
        assert_se(cb == rb); assert_se(cb == false);

        /* Invalid: NULL */
        rb = rs_address_label_valid(NULL);
        assert_se(rb == false);

        /* Invalid: too long (>= IFNAMSIZ = 16) */
        cb = address_label_valid("aaaaaaaaaaaaaaaa"); rb = rs_address_label_valid("aaaaaaaaaaaaaaaa");
        assert_se(cb == rb); assert_se(cb == false);

        /* Valid: 15 chars (just under limit) */
        cb = address_label_valid("aaaaaaaaaaaaaaa"); rb = rs_address_label_valid("aaaaaaaaaaaaaaa");
        assert_se(cb == rb); assert_se(cb == true);

        /* Valid: single char */
        cb = address_label_valid("a"); rb = rs_address_label_valid("a");
        assert_se(cb == rb); assert_se(cb == true);

        /* Invalid: control char (0x01) */
        cb = address_label_valid("eth\x01"); rb = rs_address_label_valid("eth\x01");
        assert_se(cb == rb); assert_se(cb == false);

        /* Invalid: DEL (0x7F) */
        cb = address_label_valid("eth\x7f"); rb = rs_address_label_valid("eth\x7f");
        assert_se(cb == rb); assert_se(cb == false);

        cb = address_label_valid(high_byte); rb = rs_address_label_valid(high_byte);
        assert_se(cb == rb); assert_se(cb == false);

        /* Valid: space (0x20) — C checks <= 31, so space is valid */
        cb = address_label_valid("eth 0"); rb = rs_address_label_valid("eth 0");
        assert_se(cb == rb);
}

/* ── sockaddr_equal ────────────────────────────────────────────────────── */

static void test_sockaddr_equal(void) {
        union sockaddr_union a, b;
        bool cb, rb;

        /* AF_INET: equal */
        memset(&a, 0, sizeof(a));
        memset(&b, 0, sizeof(b));
        a.in.sin_family = AF_INET;
        b.in.sin_family = AF_INET;
        a.in.sin_addr.s_addr = htobe32(0xC0A80001);
        b.in.sin_addr.s_addr = htobe32(0xC0A80001);

        cb = sockaddr_equal(&a, &b);
        rb = rs_sockaddr_equal(&a, &b);
        assert_se(cb == rb); assert_se(cb == true);

        /* AF_INET: different address */
        b.in.sin_addr.s_addr = htobe32(0xC0A80002);
        cb = sockaddr_equal(&a, &b);
        rb = rs_sockaddr_equal(&a, &b);
        assert_se(cb == rb); assert_se(cb == false);

        /* AF_INET: different family */
        b.in.sin_family = AF_INET6;
        cb = sockaddr_equal(&a, &b);
        rb = rs_sockaddr_equal(&a, &b);
        assert_se(cb == rb); assert_se(cb == false);

        /* AF_INET6: equal */
        memset(&a, 0, sizeof(a));
        memset(&b, 0, sizeof(b));
        a.in6.sin6_family = AF_INET6;
        b.in6.sin6_family = AF_INET6;
        a.in6.sin6_addr.s6_addr[0] = 0x20;
        a.in6.sin6_addr.s6_addr[1] = 0x01;
        b.in6.sin6_addr.s6_addr[0] = 0x20;
        b.in6.sin6_addr.s6_addr[1] = 0x01;

        cb = sockaddr_equal(&a, &b);
        rb = rs_sockaddr_equal(&a, &b);
        assert_se(cb == rb); assert_se(cb == true);

        /* AF_INET6: different */
        b.in6.sin6_addr.s6_addr[1] = 0x02;
        cb = sockaddr_equal(&a, &b);
        rb = rs_sockaddr_equal(&a, &b);
        assert_se(cb == rb); assert_se(cb == false);

        /* AF_VSOCK: equal */
        memset(&a, 0, sizeof(a));
        memset(&b, 0, sizeof(b));
        a.vm.svm_family = AF_VSOCK;
        b.vm.svm_family = AF_VSOCK;
        a.vm.svm_cid = 3;
        b.vm.svm_cid = 3;

        cb = sockaddr_equal(&a, &b);
        rb = rs_sockaddr_equal(&a, &b);
        assert_se(cb == rb); assert_se(cb == true);

        /* AF_VSOCK: different CID */
        b.vm.svm_cid = 4;
        cb = sockaddr_equal(&a, &b);
        rb = rs_sockaddr_equal(&a, &b);
        assert_se(cb == rb); assert_se(cb == false);

        /* AF_UNIX: unsupported — returns false */
        memset(&a, 0, sizeof(a));
        memset(&b, 0, sizeof(b));
        a.un.sun_family = AF_UNIX;
        b.un.sun_family = AF_UNIX;

        cb = sockaddr_equal(&a, &b);
        rb = rs_sockaddr_equal(&a, &b);
        assert_se(cb == rb); assert_se(cb == false);
}

int main(int argc, char **argv) {
        test_ifname_valid_char();
        test_ifname_valid_full();
        test_ifname_valid();
        test_address_label_valid();
        test_vsock_parse_port();
        test_vsock_parse_cid();
        test_sockaddr_port();
        test_sockaddr_in_addr();
        test_sockaddr_set_in_addr();
        test_sockaddr_equal();
        return 0;
}
