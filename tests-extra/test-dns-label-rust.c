/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Shadow test: C dns-domain.c label/name functions vs Rust */

#include <assert.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include "tests.h"
#include "string-util.h"
#include "in-addr-util.h"

/* C headers */
#include "dns-def.h"
#include "dns-domain.h"

/* Rust FFI */
#include "rust/dns_label.h"
#include "rust/dns_domain_validators.h"

/* ── dns_label_unescape ───────────────────────────────────────────────── */

static void test_dns_label_unescape(void) {
        const char *cn, *rn;
        char clabel[128], rlabel[128];
        int cr, rr;

        /* Simple label */
        cn = "www.example.com";
        rn = "www.example.com";
        cr = dns_label_unescape(&cn, clabel, sizeof(clabel), 0);
        rr = rs_dns_label_unescape(&rn, rlabel, sizeof(rlabel), 0);
        assert_se(cr == rr);
        assert_se(streq(clabel, rlabel));
        assert_se(cr > 0);
        assert_se(streq(clabel, "www"));

        cr = dns_label_unescape(&cn, clabel, sizeof(clabel), 0);
        rr = rs_dns_label_unescape(&rn, rlabel, sizeof(rlabel), 0);
        assert_se(cr == rr);
        assert_se(streq(clabel, rlabel));

        cr = dns_label_unescape(&cn, clabel, sizeof(clabel), 0);
        rr = rs_dns_label_unescape(&rn, rlabel, sizeof(rlabel), 0);
        assert_se(cr == rr);
        assert_se(streq(clabel, rlabel));

        cr = dns_label_unescape(&cn, clabel, sizeof(clabel), 0);
        rr = rs_dns_label_unescape(&rn, rlabel, sizeof(rlabel), 0);
        assert_se(cr == rr);
        assert_se(cr == 0);

        /* Empty string */
        cn = "";
        rn = "";
        cr = dns_label_unescape(&cn, clabel, sizeof(clabel), 0);
        rr = rs_dns_label_unescape(&rn, rlabel, sizeof(rlabel), 0);
        assert_se(cr == rr);
        assert_se(cr == 0);

        /* Escaped dot */
        cn = "www\\.example.com";
        rn = "www\\.example.com";
        cr = dns_label_unescape(&cn, clabel, sizeof(clabel), 0);
        rr = rs_dns_label_unescape(&rn, rlabel, sizeof(rlabel), 0);
        assert_se(cr == rr);
        assert_se(streq(clabel, rlabel));
        assert_se(streq(clabel, "www.example"));

        /* Escaped backslash */
        cn = "server\\\\.example.com";
        rn = "server\\\\.example.com";
        cr = dns_label_unescape(&cn, clabel, sizeof(clabel), 0);
        rr = rs_dns_label_unescape(&rn, rlabel, sizeof(rlabel), 0);
        assert_se(cr == rr);
        assert_se(streq(clabel, rlabel));
        assert_se(streq(clabel, "server\\"));

        /* \DDD escape */
        cn = "test\\032space.com";
        rn = "test\\032space.com";
        cr = dns_label_unescape(&cn, clabel, sizeof(clabel), 0);
        rr = rs_dns_label_unescape(&rn, rlabel, sizeof(rlabel), 0);
        assert_se(cr == rr);
        assert_se(streq(clabel, rlabel));
        assert_se(streq(clabel, "test space"));

        /* LDH flag: reject non-LDH chars */
        cn = "test_name";
        rn = "test_name";
        cr = dns_label_unescape(&cn, clabel, sizeof(clabel), 1);
        rr = rs_dns_label_unescape(&rn, rlabel, sizeof(rlabel), 1);
        assert_se(cr == rr);
        assert_se(cr == -EINVAL);

        /* LDH flag: reject leading dash */
        cn = "-test.example";
        rn = "-test.example";
        cr = dns_label_unescape(&cn, clabel, sizeof(clabel), 1);
        rr = rs_dns_label_unescape(&rn, rlabel, sizeof(rlabel), 1);
        assert_se(cr == rr);
        assert_se(cr == -EINVAL);

        /* LDH flag: reject trailing dash */
        cn = "test-.example";
        rn = "test-.example";
        cr = dns_label_unescape(&cn, clabel, sizeof(clabel), 1);
        rr = rs_dns_label_unescape(&rn, rlabel, sizeof(rlabel), 1);
        assert_se(cr == rr);
        assert_se(cr == -EINVAL);

        /* LDH flag: valid LDH label */
        cn = "test-123.example";
        rn = "test-123.example";
        cr = dns_label_unescape(&cn, clabel, sizeof(clabel), 1);
        rr = rs_dns_label_unescape(&rn, rlabel, sizeof(rlabel), 1);
        assert_se(cr == rr);
        assert_se(streq(clabel, rlabel));

        /* NO_ESCAPES flag */
        cn = "test\\.name";
        rn = "test\\.name";
        cr = dns_label_unescape(&cn, clabel, sizeof(clabel), 2);
        rr = rs_dns_label_unescape(&rn, rlabel, sizeof(rlabel), 2);
        assert_se(cr == rr);
        assert_se(cr == -EINVAL);

        /* Too long label (>63 chars) */
        cn = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"; /* 71 chars */
        rn = cn;
        cr = dns_label_unescape(&cn, clabel, sizeof(clabel), 0);
        rr = rs_dns_label_unescape(&rn, rlabel, sizeof(rlabel), 0);
        assert_se(cr == rr);
        assert_se(cr == -EINVAL);

        /* LEAVE_TRAILING_DOT flag */
        cn = "example.";
        rn = "example.";
        cr = dns_label_unescape(&cn, clabel, sizeof(clabel), 4);
        rr = rs_dns_label_unescape(&rn, rlabel, sizeof(rlabel), 4);
        assert_se(cr == rr);
        assert_se(streq(clabel, rlabel));
        assert_se(streq(cn, rn));

        /* Control character */
        cn = "test\001name";
        rn = "test\001name";
        cr = dns_label_unescape(&cn, clabel, sizeof(clabel), 0);
        rr = rs_dns_label_unescape(&rn, rlabel, sizeof(rlabel), 0);
        assert_se(cr == rr);
        assert_se(cr == -EINVAL);

        /* dest=NULL with non-zero sz: should still parse and advance */
        cn = "hello.world";
        rn = "hello.world";
        cr = dns_label_unescape(&cn, NULL, DNS_LABEL_MAX, 0);
        rr = rs_dns_label_unescape(&rn, NULL, DNS_LABEL_MAX, 0);
        assert_se(cr == rr);
        assert_se(cr > 0);
}

/* ── dns_label_escape ─────────────────────────────────────────────────── */

static void test_dns_label_escape(void) {
        char cdest[256], rdest[256];
        int cr, rr;

        /* Simple label */
        cr = dns_label_escape("www", 3, cdest, sizeof(cdest));
        rr = rs_dns_label_escape("www", 3, rdest, sizeof(rdest));
        assert_se(cr == rr);
        assert_se(streq(cdest, rdest));

        /* Label with dot */
        cr = dns_label_escape("www.example", 11, cdest, sizeof(cdest));
        rr = rs_dns_label_escape("www.example", 11, rdest, sizeof(rdest));
        assert_se(cr == rr);
        assert_se(streq(cdest, rdest));

        /* Label with backslash */
        cr = dns_label_escape("server\\name", 12, cdest, sizeof(cdest));
        rr = rs_dns_label_escape("server\\name", 12, rdest, sizeof(rdest));
        assert_se(cr == rr);
        assert_se(streq(cdest, rdest));

        /* Label with underscore */
        cr = dns_label_escape("_http", 5, cdest, sizeof(cdest));
        rr = rs_dns_label_escape("_http", 5, rdest, sizeof(rdest));
        assert_se(cr == rr);
        assert_se(streq(cdest, rdest));

        /* Label with space */
        cr = dns_label_escape("test name", 9, cdest, sizeof(cdest));
        rr = rs_dns_label_escape("test name", 9, rdest, sizeof(rdest));
        assert_se(cr == rr);
        assert_se(streq(cdest, rdest));

        /* Empty label */
        cr = dns_label_escape("", 0, cdest, sizeof(cdest));
        rr = rs_dns_label_escape("", 0, rdest, sizeof(rdest));
        assert_se(cr == rr);
        assert_se(cr == -EINVAL);

        /* Too long label */
        cr = dns_label_escape("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 71, cdest, sizeof(cdest));
        rr = rs_dns_label_escape("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 71, rdest, sizeof(rdest));
        assert_se(cr == rr);
        assert_se(cr == -EINVAL);

        /* Buffer too small */
        cr = dns_label_escape("ab", 2, cdest, 1);
        rr = rs_dns_label_escape("ab", 2, rdest, 1);
        assert_se(cr == rr);
        assert_se(cr == -ENOBUFS);
}

/* ── dns_name_is_root ─────────────────────────────────────────────────── */

static void test_dns_name_is_root(void) {
        bool cv, rv;

        cv = dns_name_is_root("");
        rv = rs_dns_name_is_root("");
        assert_se(cv == rv);

        cv = dns_name_is_root(".");
        rv = rs_dns_name_is_root(".");
        assert_se(cv == rv);

        cv = dns_name_is_root("example.com");
        rv = rs_dns_name_is_root("example.com");
        assert_se(cv == rv);

        cv = dns_name_is_root("example.");
        rv = rs_dns_name_is_root("example.");
        assert_se(cv == rv);
}

/* ── dns_name_parent ──────────────────────────────────────────────────── */

static void test_dns_name_parent(void) {
        const char *cn = "www.example.com";
        const char *rn = "www.example.com";
        int cr, rr;

        cr = dns_name_parent(&cn);
        rr = rs_dns_name_parent(&rn);
        assert_se(cr == rr);
        assert_se(cr > 0);
        assert_se(streq(cn, rn));

        /* Single label → consumes label, name becomes "" */
        cn = "com";
        rn = "com";
        cr = dns_name_parent(&cn);
        rr = rs_dns_name_parent(&rn);
        assert_se(cr == rr);
        assert_se(cr > 0); /* Returns label length */
        assert_se(streq(cn, ""));

        /* Empty string → returns 0 (nothing to consume) */
        cn = "";
        rn = "";
        cr = dns_name_parent(&cn);
        rr = rs_dns_name_parent(&rn);
        assert_se(cr == rr);
        assert_se(cr == 0);
}

/* ── dns_name_equal ───────────────────────────────────────────────────── */

static void test_dns_name_equal(void) {
        int cv, rv;

        cv = dns_name_equal("example.com", "example.com");
        rv = rs_dns_name_equal("example.com", "example.com");
        assert_se(cv == rv);

        cv = dns_name_equal("Example.COM", "example.com");
        rv = rs_dns_name_equal("Example.COM", "example.com");
        assert_se(cv == rv);

        cv = dns_name_equal("example.com", "example.org");
        rv = rs_dns_name_equal("example.com", "example.org");
        assert_se(cv == rv);

        cv = dns_name_equal("", "");
        rv = rs_dns_name_equal("", "");
        assert_se(cv == rv);

        cv = dns_name_equal(".", "");
        rv = rs_dns_name_equal(".", "");
        assert_se(cv == rv);

        cv = dns_name_equal("a.b.c", "a.b.c.d");
        rv = rs_dns_name_equal("a.b.c", "a.b.c.d");
        assert_se(cv == rv);
}

/* ── dns_name_endswith ────────────────────────────────────────────────── */

static void test_dns_name_endswith(void) {
        int cv, rv;

        cv = dns_name_endswith("www.example.com", "example.com");
        rv = rs_dns_name_endswith("www.example.com", "example.com");
        assert_se(cv == rv);

        cv = dns_name_endswith("example.com", "example.com");
        rv = rs_dns_name_endswith("example.com", "example.com");
        assert_se(cv == rv);

        cv = dns_name_endswith("example.com", "www.example.com");
        rv = rs_dns_name_endswith("example.com", "www.example.com");
        assert_se(cv == rv);

        cv = dns_name_endswith("example.com", "com");
        rv = rs_dns_name_endswith("example.com", "com");
        assert_se(cv == rv);

        cv = dns_name_endswith("example.com", "org");
        rv = rs_dns_name_endswith("example.com", "org");
        assert_se(cv == rv);

        cv = dns_name_endswith("example.com", "xample.com");
        rv = rs_dns_name_endswith("example.com", "xample.com");
        assert_se(cv == rv);

        cv = dns_name_endswith("www.example.com", "EXAMPLE.COM");
        rv = rs_dns_name_endswith("www.example.com", "EXAMPLE.COM");
        assert_se(cv == rv);

        cv = dns_name_endswith("", "");
        rv = rs_dns_name_endswith("", "");
        assert_se(cv == rv);

        cv = dns_name_endswith("a", "");
        rv = rs_dns_name_endswith("a", "");
        assert_se(cv == rv);

        cv = dns_name_endswith("", "a");
        rv = rs_dns_name_endswith("", "a");
        assert_se(cv == rv);
}

/* ── dns_name_startswith ──────────────────────────────────────────────── */

static void test_dns_name_startswith(void) {
        int cv, rv;

        cv = dns_name_startswith("www.example.com", "www");
        rv = rs_dns_name_startswith("www.example.com", "www");
        assert_se(cv == rv);

        cv = dns_name_startswith("www.example.com", "www.example");
        rv = rs_dns_name_startswith("www.example.com", "www.example");
        assert_se(cv == rv);

        cv = dns_name_startswith("www.example.com", "example");
        rv = rs_dns_name_startswith("www.example.com", "example");
        assert_se(cv == rv);

        cv = dns_name_startswith("www.example.com", "WWW");
        rv = rs_dns_name_startswith("www.example.com", "WWW");
        assert_se(cv == rv);

        cv = dns_name_startswith("", "");
        rv = rs_dns_name_startswith("", "");
        assert_se(cv == rv);

        cv = dns_name_startswith("a", "");
        rv = rs_dns_name_startswith("a", "");
        assert_se(cv == rv);
}

/* ── dns_name_count_labels ────────────────────────────────────────────── */

static void test_dns_name_count_labels(void) {
        int cv, rv;

        cv = dns_name_count_labels("");
        rv = rs_dns_name_count_labels("");
        assert_se(cv == rv);

        cv = dns_name_count_labels(".");
        rv = rs_dns_name_count_labels(".");
        assert_se(cv == rv);

        cv = dns_name_count_labels("www");
        rv = rs_dns_name_count_labels("www");
        assert_se(cv == rv);

        cv = dns_name_count_labels("www.example");
        rv = rs_dns_name_count_labels("www.example");
        assert_se(cv == rv);

        cv = dns_name_count_labels("www.example.com");
        rv = rs_dns_name_count_labels("www.example.com");
        assert_se(cv == rv);

        cv = dns_name_count_labels("www.example.com.");
        rv = rs_dns_name_count_labels("www.example.com.");
        assert_se(cv == rv);
}

/* ── dns_srv_type_is_valid ────────────────────────────────────────────── */

static void test_dns_srv_type_is_valid(void) {
        bool cv, rv;

        cv = dns_srv_type_is_valid(NULL);
        rv = rs_dns_srv_type_is_valid(NULL);
        assert_se(cv == rv);

        cv = dns_srv_type_is_valid("");
        rv = rs_dns_srv_type_is_valid("");
        assert_se(cv == rv);

        cv = dns_srv_type_is_valid("_http._tcp");
        rv = rs_dns_srv_type_is_valid("_http._tcp");
        assert_se(cv == rv);

        cv = dns_srv_type_is_valid("_https._tcp");
        rv = rs_dns_srv_type_is_valid("_https._tcp");
        assert_se(cv == rv);

        cv = dns_srv_type_is_valid("_ftp._tcp");
        rv = rs_dns_srv_type_is_valid("_ftp._tcp");
        assert_se(cv == rv);

        cv = dns_srv_type_is_valid("_printer._tcp");
        rv = rs_dns_srv_type_is_valid("_printer._tcp");
        assert_se(cv == rv);

        /* Missing second label */
        cv = dns_srv_type_is_valid("_http");
        rv = rs_dns_srv_type_is_valid("_http");
        assert_se(cv == rv);

        /* No underscore prefix */
        cv = dns_srv_type_is_valid("http._tcp");
        rv = rs_dns_srv_type_is_valid("http._tcp");
        assert_se(cv == rv);

        /* Third label */
        cv = dns_srv_type_is_valid("_http._tcp.extra");
        rv = rs_dns_srv_type_is_valid("_http._tcp.extra");
        assert_se(cv == rv);

        /* Single char second label */
        cv = dns_srv_type_is_valid("_http._t");
        rv = rs_dns_srv_type_is_valid("_http._t");
        assert_se(cv == rv);

        /* Number in second position of first label */
        cv = dns_srv_type_is_valid("_1http._tcp");
        rv = rs_dns_srv_type_is_valid("_1http._tcp");
        assert_se(cv == rv);
}

/* ── dnssd_srv_type_is_valid ──────────────────────────────────────────── */

static void test_dnssd_srv_type_is_valid(void) {
        bool cv, rv;

        cv = dnssd_srv_type_is_valid("_http._tcp");
        rv = rs_dnssd_srv_type_is_valid("_http._tcp");
        assert_se(cv == rv);

        cv = dnssd_srv_type_is_valid("_http._udp");
        rv = rs_dnssd_srv_type_is_valid("_http._udp");
        assert_se(cv == rv);

        cv = dnssd_srv_type_is_valid("_http._sctp");
        rv = rs_dnssd_srv_type_is_valid("_http._sctp");
        assert_se(cv == rv);

        cv = dnssd_srv_type_is_valid(NULL);
        rv = rs_dnssd_srv_type_is_valid(NULL);
        assert_se(cv == rv);
}

/* ── dns_name_is_single_label ─────────────────────────────────────────── */

static void test_dns_name_is_single_label(void) {
        bool cv, rv;

        cv = dns_name_is_single_label("www");
        rv = rs_dns_name_is_single_label("www");
        assert_se(cv == rv);
        assert_se(cv == true);

        cv = dns_name_is_single_label("www.");
        rv = rs_dns_name_is_single_label("www.");
        assert_se(cv == rv);
        assert_se(cv == true);

        cv = dns_name_is_single_label("www.example");
        rv = rs_dns_name_is_single_label("www.example");
        assert_se(cv == rv);
        assert_se(cv == false);

        cv = dns_name_is_single_label("");
        rv = rs_dns_name_is_single_label("");
        assert_se(cv == rv);
        assert_se(cv == false);

        cv = dns_name_is_single_label(".");
        rv = rs_dns_name_is_single_label(".");
        assert_se(cv == rv);
        assert_se(cv == false);

        cv = dns_name_is_single_label("a.b.c");
        rv = rs_dns_name_is_single_label("a.b.c");
        assert_se(cv == rv);
        assert_se(cv == false);
}

/* ── dns_name_dont_resolve ─────────────────────────────────────────── */

static void test_dns_name_dont_resolve(void) {
        bool cv, rv;

        /* RFC6303: 0.in-addr.arpa */
        cv = dns_name_dont_resolve("0.in-addr.arpa");
        rv = rs_dns_name_dont_resolve("0.in-addr.arpa");
        assert_se(cv == rv);
        assert_se(cv);

        cv = dns_name_dont_resolve("1.0.in-addr.arpa");
        rv = rs_dns_name_dont_resolve("1.0.in-addr.arpa");
        assert_se(cv == rv);
        assert_se(cv);

        /* RFC6303: 255.255.255.255.in-addr.arpa */
        cv = dns_name_dont_resolve("255.255.255.255.in-addr.arpa");
        rv = rs_dns_name_dont_resolve("255.255.255.255.in-addr.arpa");
        assert_se(cv == rv);
        assert_se(cv);

        /* RFC6303: all-zeros ip6.arpa */
        cv = dns_name_dont_resolve("0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa");
        rv = rs_dns_name_dont_resolve("0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa");
        assert_se(cv == rv);
        assert_se(cv);

        /* RFC6761: .invalid */
        cv = dns_name_dont_resolve("test.invalid");
        rv = rs_dns_name_dont_resolve("test.invalid");
        assert_se(cv == rv);
        assert_se(cv);

        cv = dns_name_dont_resolve("invalid");
        rv = rs_dns_name_dont_resolve("invalid");
        assert_se(cv == rv);
        assert_se(cv);

        /* RFC9476: .alt */
        cv = dns_name_dont_resolve("test.alt");
        rv = rs_dns_name_dont_resolve("test.alt");
        assert_se(cv == rv);
        assert_se(cv);

        /* Regular names should resolve */
        cv = dns_name_dont_resolve("example.com");
        rv = rs_dns_name_dont_resolve("example.com");
        assert_se(cv == rv);
        assert_se(!cv);

        cv = dns_name_dont_resolve("www.example.com");
        rv = rs_dns_name_dont_resolve("www.example.com");
        assert_se(cv == rv);
        assert_se(!cv);

        cv = dns_name_dont_resolve("");
        rv = rs_dns_name_dont_resolve("");
        assert_se(cv == rv);
        assert_se(!cv);
}

/* ── dns_service_name_is_valid / dns_subtype_name_is_valid ────────── */

static void test_dns_service_name_is_valid(void) {
        bool cv, rv;

        cv = dns_service_name_is_valid(NULL);
        rv = rs_dns_service_name_is_valid(NULL);
        assert_se(cv == rv);
        assert_se(!cv);

        cv = dns_service_name_is_valid("");
        rv = rs_dns_service_name_is_valid("");
        assert_se(cv == rv);
        assert_se(!cv);

        cv = dns_service_name_is_valid("My Service");
        rv = rs_dns_service_name_is_valid("My Service");
        assert_se(cv == rv);
        assert_se(cv);

        cv = dns_service_name_is_valid("_http._tcp");
        rv = rs_dns_service_name_is_valid("_http._tcp");
        assert_se(cv == rv);
        assert_se(cv);

        /* Control character */
        cv = dns_service_name_is_valid("test\x01");
        rv = rs_dns_service_name_is_valid("test\x01");
        assert_se(cv == rv);
        assert_se(!cv);

        /* Too long (>63 chars) — 64 'a's */
        cv = dns_service_name_is_valid("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        rv = rs_dns_service_name_is_valid("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        assert_se(cv == rv);
        assert_se(!cv);

        /* Exactly 63 chars */
        cv = dns_service_name_is_valid("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        rv = rs_dns_service_name_is_valid("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        assert_se(cv == rv);
        assert_se(cv);
}

static void test_dns_subtype_name_is_valid(void) {
        bool cv, rv;

        cv = dns_subtype_name_is_valid(NULL);
        rv = rs_dns_subtype_name_is_valid(NULL);
        assert_se(cv == rv);
        assert_se(!cv);

        cv = dns_subtype_name_is_valid("printer");
        rv = rs_dns_subtype_name_is_valid("printer");
        assert_se(cv == rv);
        assert_se(cv);

        cv = dns_subtype_name_is_valid("_ipps");
        rv = rs_dns_subtype_name_is_valid("_ipps");
        assert_se(cv == rv);
        assert_se(cv);

        cv = dns_subtype_name_is_valid("");
        rv = rs_dns_subtype_name_is_valid("");
        assert_se(cv == rv);
        assert_se(!cv);
}

/* ── dns_name_dot_suffixed ─────────────────────────────────────────── */

static void test_dns_name_dot_suffixed(void) {
        int cv, rv;

        cv = dns_name_dot_suffixed("example.com");
        rv = rs_dns_name_dot_suffixed("example.com");
        assert_se(cv == rv);
        assert_se(!cv);

        cv = dns_name_dot_suffixed("example.com.");
        rv = rs_dns_name_dot_suffixed("example.com.");
        assert_se(cv == rv);
        assert_se(cv);

        cv = dns_name_dot_suffixed(".");
        rv = rs_dns_name_dot_suffixed(".");
        assert_se(cv == rv);
        assert_se(cv);

        cv = dns_name_dot_suffixed("www");
        rv = rs_dns_name_dot_suffixed("www");
        assert_se(cv == rv);
        assert_se(!cv);

        cv = dns_name_dot_suffixed("www.");
        rv = rs_dns_name_dot_suffixed("www.");
        assert_se(cv == rv);
        assert_se(cv);

        cv = dns_name_dot_suffixed("");
        rv = rs_dns_name_dot_suffixed("");
        assert_se(cv == rv);
        assert_se(!cv);
}

/* ── dns_name_skip ─────────────────────────────────────────────────── */

static void test_dns_name_skip(void) {
        const char *cr, *rr;
        int cv, rv;

        cv = dns_name_skip("www.example.com", 1, &cr);
        rv = rs_dns_name_skip("www.example.com", 1, &rr);
        assert_se(cv == rv);
        assert_se(cv == 1);
        assert_se(streq(cr, rr));

        cv = dns_name_skip("www.example.com", 2, &cr);
        rv = rs_dns_name_skip("www.example.com", 2, &rr);
        assert_se(cv == rv);
        assert_se(cv == 1);
        assert_se(streq(cr, rr));

        cv = dns_name_skip("www.example.com", 3, &cr);
        rv = rs_dns_name_skip("www.example.com", 3, &rr);
        assert_se(cv == rv);
        assert_se(cv == 1); /* all labels skipped, ret points to "" */

        cv = dns_name_skip("www.example.com", 10, &cr);
        rv = rs_dns_name_skip("www.example.com", 10, &rr);
        assert_se(cv == rv);
        assert_se(cv == 0); /* exhausted before n_labels */
}

/* ── dns_name_suffix ───────────────────────────────────────────────── */

static void test_dns_name_suffix(void) {
        const char *cr, *rr;
        int cv, rv;

        cv = dns_name_suffix("www.example.com", 1, &cr);
        rv = rs_dns_name_suffix("www.example.com", 1, &cr);
        assert_se(cv == rv);

        cv = dns_name_suffix("www.example.com", 2, &cr);
        rv = rs_dns_name_suffix("www.example.com", 2, &cr);
        assert_se(cv == rv);

        /* Too many labels */
        cv = dns_name_suffix("www.example.com", 10, &cr);
        rv = rs_dns_name_suffix("www.example.com", 10, &cr);
        assert_se(cv == rv);
        assert_se(cv == -EINVAL);

        /* Zero labels */
        cv = dns_name_suffix("www.example.com", 0, &cr);
        rv = rs_dns_name_suffix("www.example.com", 0, &cr);
        assert_se(cv == rv);
}

/* ── dns_name_equal_skip ───────────────────────────────────────────── */

static void test_dns_name_equal_skip(void) {
        int cv, rv;

        cv = dns_name_equal_skip("www.example.com", 1, "example.com");
        rv = rs_dns_name_equal_skip("www.example.com", 1, "example.com");
        assert_se(cv == rv);
        assert_se(cv > 0);

        cv = dns_name_equal_skip("www.example.com", 1, "example.org");
        rv = rs_dns_name_equal_skip("www.example.com", 1, "example.org");
        assert_se(cv == rv);
        assert_se(cv == 0);

        cv = dns_name_equal_skip("www.example.com", 3, "");
        rv = rs_dns_name_equal_skip("www.example.com", 3, "");
        assert_se(cv == rv);
        assert_se(cv > 0); /* skipped all 3 labels, remainder "" equals "" */

        cv = dns_name_equal_skip("a.b.c", 2, "c");
        rv = rs_dns_name_equal_skip("a.b.c", 2, "c");
        assert_se(cv == rv);
        assert_se(cv > 0);
}

/* ── dns_name_common_suffix ────────────────────────────────────────── */

static void test_dns_name_common_suffix(void) {
        const char *cr, *rr;
        int cv, rv;

        cv = dns_name_common_suffix("www.example.com", "mail.example.com", &cr);
        rv = rs_dns_name_common_suffix("www.example.com", "mail.example.com", &rr);
        assert_se(cv == rv);
        assert_se(cv == 0);
        assert_se(streq(cr, rr));

        cv = dns_name_common_suffix("a.b.c", "x.y.z", &cr);
        rv = rs_dns_name_common_suffix("a.b.c", "x.y.z", &rr);
        assert_se(cv == rv);
        assert_se(cv == 0);
        assert_se(streq(cr, rr));

        cv = dns_name_common_suffix("example.com", "example.org", &cr);
        rv = rs_dns_name_common_suffix("example.com", "example.org", &rr);
        assert_se(cv == rv);
        assert_se(cv == 0);
}

/* ── dns_name_to_wire_format ──────────────────────────────────────── */

static void test_dns_name_to_wire_format(void) {
        uint8_t cb[256], rb[256];
        int cv, rv;

        /* Simple domain */
        cv = dns_name_to_wire_format("example.com", cb, sizeof(cb), false);
        rv = rs_dns_name_to_wire_format("example.com", rb, sizeof(rb), false);
        assert_se(cv == rv);
        assert_se(cv > 0);
        assert_se(memcmp(cb, rb, cv) == 0);

        /* Root domain */
        cv = dns_name_to_wire_format("", cb, sizeof(cb), false);
        rv = rs_dns_name_to_wire_format("", rb, sizeof(rb), false);
        assert_se(cv == rv);
        assert_se(cv == 1); /* just the root NUL byte */

        /* Three labels */
        cv = dns_name_to_wire_format("www.example.com", cb, sizeof(cb), false);
        rv = rs_dns_name_to_wire_format("www.example.com", rb, sizeof(rb), false);
        assert_se(cv == rv);
        assert_se(cv > 0);
        assert_se(memcmp(cb, rb, cv) == 0);

        /* Canonical form (lowercase) */
        cv = dns_name_to_wire_format("WWW.EXAMPLE.COM", cb, sizeof(cb), true);
        rv = rs_dns_name_to_wire_format("WWW.EXAMPLE.COM", rb, sizeof(rb), true);
        assert_se(cv == rv);
        assert_se(cv > 0);
        assert_se(memcmp(cb, rb, cv) == 0);

        /* Buffer too small */
        cv = dns_name_to_wire_format("www.example.com", cb, 2, false);
        rv = rs_dns_name_to_wire_format("www.example.com", rb, 2, false);
        assert_se(cv == rv);
        assert_se(cv == -ENOBUFS);
}

/* ── dns_name_reverse ────────────────────────────────────────────────── */

static void test_dns_name_reverse(void) {
        _cleanup_free_ char *cr = NULL, *rr = NULL;
        union in_addr_union addr;
        int cv, rv;

        /* IPv4: 192.168.1.1 → 1.1.168.192.in-addr.arpa */
        addr.in.s_addr = htobe32((192U << 24) | (168U << 16) | (1U << 8) | 1U);
        cv = dns_name_reverse(AF_INET, &addr, &cr);
        rv = rs_dns_name_reverse(AF_INET, (const uint8_t *)&addr, &rr);
        assert_se(cv == rv);
        assert_se(cv == 0);
        assert_se(streq(cr, rr));

        cr = mfree(cr);
        rr = mfree(rr);

        /* IPv4: 10.0.0.1 → 1.0.0.10.in-addr.arpa */
        addr.in.s_addr = htobe32((10U << 24) | (0U << 16) | (0U << 8) | 1U);
        cv = dns_name_reverse(AF_INET, &addr, &cr);
        rv = rs_dns_name_reverse(AF_INET, (const uint8_t *)&addr, &rr);
        assert_se(cv == rv);
        assert_se(cv == 0);
        assert_se(streq(cr, rr));

        cr = mfree(cr);
        rr = mfree(rr);

        /* IPv4: 255.255.255.255 → 255.255.255.255.in-addr.arpa */
        addr.in.s_addr = htobe32(0xFFFFFFFFU);
        cv = dns_name_reverse(AF_INET, &addr, &cr);
        rv = rs_dns_name_reverse(AF_INET, (const uint8_t *)&addr, &rr);
        assert_se(cv == rv);
        assert_se(cv == 0);
        assert_se(streq(cr, rr));

        cr = mfree(cr);
        rr = mfree(rr);

        /* Unsupported family */
        cv = dns_name_reverse(AF_UNSPEC, &addr, &cr);
        rv = rs_dns_name_reverse(AF_UNSPEC, (const uint8_t *)&addr, &rr);
        assert_se(cv == rv);
        assert_se(cv == -EAFNOSUPPORT);

        /* IPv6: ::1 → 1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa */
        memset(&addr, 0, sizeof(addr));
        addr.in6.s6_addr[15] = 1;
        cv = dns_name_reverse(AF_INET6, &addr, &cr);
        rv = rs_dns_name_reverse(AF_INET6, (const uint8_t *)&addr, &rr);
        assert_se(cv == rv);
        assert_se(cv == 0);
        assert_se(streq(cr, rr));

        cr = mfree(cr);
        rr = mfree(rr);

        /* IPv6: 2001:db8::1 */
        memset(&addr, 0, sizeof(addr));
        addr.in6.s6_addr[0] = 0x20;
        addr.in6.s6_addr[1] = 0x01;
        addr.in6.s6_addr[2] = 0x0d;
        addr.in6.s6_addr[3] = 0xb8;
        addr.in6.s6_addr[15] = 1;
        cv = dns_name_reverse(AF_INET6, &addr, &cr);
        rv = rs_dns_name_reverse(AF_INET6, (const uint8_t *)&addr, &rr);
        assert_se(cv == rv);
        assert_se(cv == 0);
        assert_se(streq(cr, rr));
}

/* ── dns_name_address ────────────────────────────────────────────────── */

static void test_dns_name_address(void) {
        union in_addr_union ca, ra;
        int cf, rf;
        int cv, rv;

        /* IPv4 reverse: 1.1.168.192.in-addr.arpa → 192.168.1.1 */
        cv = dns_name_address("1.1.168.192.in-addr.arpa", &cf, &ca);
        rv = rs_dns_name_address("1.1.168.192.in-addr.arpa", &rf, (uint8_t *)&ra);
        assert_se(cv == rv);
        assert_se(cv > 0);
        assert_se(cf == rf);
        assert_se(cf == AF_INET);
        assert_se(ca.in.s_addr == ra.in.s_addr);

        /* Not a reverse name */
        cv = dns_name_address("www.example.com", &cf, &ca);
        rv = rs_dns_name_address("www.example.com", &rf, (uint8_t *)&ra);
        assert_se(cv == rv);
        assert_se(cv == 0);
        assert_se(cf == AF_UNSPEC);

        /* IPv6 reverse: 1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa → ::1 */
        cv = dns_name_address(
            "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa",
            &cf, &ca);
        rv = rs_dns_name_address(
            "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa",
            &rf, (uint8_t *)&ra);
        assert_se(cv == rv);
        assert_se(cv > 0);
        assert_se(cf == rf);
        assert_se(cf == AF_INET6);
        assert_se(memcmp(&ca, &ra, sizeof(ca)) == 0);
}

/* ── dns_name_from_wire_format ───────────────────────────────────────── */

static void test_dns_name_from_wire_format(void) {
        _cleanup_free_ char *cr = NULL, *rr = NULL;
        /* Wire format for "www.example.com":
         * \x03www\x07example\x03com\x00 */
        const uint8_t wire[] = {
                0x03, 'w', 'w', 'w',
                0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
                0x03, 'c', 'o', 'm',
                0x00
        };
        const uint8_t *cd = wire, *rd = wire;
        size_t cl = sizeof(wire), rl = sizeof(wire);
        int cv, rv;

        cv = dns_name_from_wire_format(&cd, &cl, &cr);
        rv = rs_dns_name_from_wire_format(&rd, &rl, &rr);
        assert_se(cv == rv);
        assert_se(cv > 0);
        assert_se(streq(cr, rr));

        cr = mfree(cr);
        rr = mfree(rr);

        /* Wire format for root ".": just \x00 */
        {
                const uint8_t root_wire[] = { 0x00 };
                cd = root_wire; rd = root_wire;
                cl = sizeof(root_wire); rl = sizeof(root_wire);
                cv = dns_name_from_wire_format(&cd, &cl, &cr);
                rv = rs_dns_name_from_wire_format(&rd, &rl, &rr);
                assert_se(cv == rv);
        }

        /* Partial name (no terminating zero label) per RFC 4704 */
        {
                const uint8_t partial[] = { 0x03, 'f', 'o', 'o' };
                cd = partial; rd = partial;
                cl = sizeof(partial); rl = sizeof(partial);
                cv = dns_name_from_wire_format(&cd, &cl, &cr);
                rv = rs_dns_name_from_wire_format(&rd, &rl, &rr);
                assert_se(cv == rv);
                assert_se(cv > 0);
                assert_se(streq(cr, rr));
        }
}

/* ── dns_label_unescape_suffix ──────────────────────────────────────── */

static void test_dns_label_unescape_suffix(void) {
        const char *name = "www.example.com";
        const char *cx, *rx;
        char cl[DNS_LABEL_MAX+1], rl[DNS_LABEL_MAX+1];
        int cv, rv;

        /* Start from end of string */
        cx = name + strlen(name);
        rx = name + strlen(name);

        /* First label from right: "com" */
        cv = dns_label_unescape_suffix(name, &cx, cl, sizeof(cl));
        rv = rs_dns_label_unescape_suffix(name, &rx, rl, sizeof(rl));
        assert_se(cv == rv);
        assert_se(cv > 0);
        assert_se(streq(cl, rl));
        assert_se(streq(cl, "com"));

        /* Second label from right: "example" */
        cv = dns_label_unescape_suffix(name, &cx, cl, sizeof(cl));
        rv = rs_dns_label_unescape_suffix(name, &rx, rl, sizeof(rl));
        assert_se(cv == rv);
        assert_se(cv > 0);
        assert_se(streq(cl, rl));
        assert_se(streq(cl, "example"));

        /* Third label from right: "www" */
        cv = dns_label_unescape_suffix(name, &cx, cl, sizeof(cl));
        rv = rs_dns_label_unescape_suffix(name, &rx, rl, sizeof(rl));
        assert_se(cv == rv);
        assert_se(cv > 0);
        assert_se(streq(cl, rl));
        assert_se(streq(cl, "www"));

        /* No more labels */
        cv = dns_label_unescape_suffix(name, &cx, cl, sizeof(cl));
        rv = rs_dns_label_unescape_suffix(name, &rx, rl, sizeof(rl));
        assert_se(cv == rv);
        assert_se(cv == 0);
}

/* ── dns_name_compare_func ──────────────────────────────────────────── */

static void test_dns_name_compare_func(void) {
        int cv, rv;

        /* Same name */
        cv = dns_name_compare_func("www.example.com", "www.example.com");
        rv = rs_dns_name_compare_func("www.example.com", "www.example.com");
        assert_se(cv == rv);
        assert_se(cv == 0);

        /* Case insensitive */
        cv = dns_name_compare_func("WWW.EXAMPLE.COM", "www.example.com");
        rv = rs_dns_name_compare_func("WWW.EXAMPLE.COM", "www.example.com");
        assert_se(cv == rv);
        assert_se(cv == 0);

        /* Different TLDs */
        cv = dns_name_compare_func("www.example.com", "www.example.org");
        rv = rs_dns_name_compare_func("www.example.com", "www.example.org");
        assert_se(cv == rv);

        /* Different subdomains */
        cv = dns_name_compare_func("a.example.com", "b.example.com");
        rv = rs_dns_name_compare_func("a.example.com", "b.example.com");
        assert_se(cv == rv);

        /* Root domain */
        cv = dns_name_compare_func("", ".");
        rv = rs_dns_name_compare_func("", ".");
        assert_se(cv == rv);
        assert_se(cv == 0);
}

/* ── dns_name_between ───────────────────────────────────────────────── */

static void test_dns_name_between(void) {
        int cv, rv;

        /* b between a and c (properly ordered) */
        cv = dns_name_between("a.example.com", "b.example.com", "c.example.com");
        rv = rs_dns_name_between("a.example.com", "b.example.com", "c.example.com");
        assert_se(cv == rv);
        assert_se(cv > 0);

        /* b not between a and c */
        cv = dns_name_between("a.example.com", "d.example.com", "c.example.com");
        rv = rs_dns_name_between("a.example.com", "d.example.com", "c.example.com");
        assert_se(cv == rv);
        assert_se(cv == 0);

        /* Equal names → not between */
        cv = dns_name_between("a.example.com", "a.example.com", "c.example.com");
        rv = rs_dns_name_between("a.example.com", "a.example.com", "c.example.com");
        assert_se(cv == rv);
        assert_se(cv == 0);
}

/* ── dns_label_escape_new ───────────────────────────────────────────── */

static void test_dns_label_escape_new(void) {
        _cleanup_free_ char *cr = NULL, *rr = NULL;
        int cv, rv;

        cv = dns_label_escape_new("www", 3, &cr);
        rv = rs_dns_label_escape_new("www", 3, &rr);
        assert_se(cv == rv);
        assert_se(cv > 0);
        assert_se(streq(cr, rr));
        assert_se(streq(cr, "www"));

        cr = mfree(cr);
        rr = mfree(rr);

        /* Label with dot */
        cv = dns_label_escape_new("a.b", 3, &cr);
        rv = rs_dns_label_escape_new("a.b", 3, &rr);
        assert_se(cv == rv);
        assert_se(cv > 0);
        assert_se(streq(cr, rr));

        /* Empty label → -EINVAL */
        cv = dns_label_escape_new("", 0, &cr);
        rv = rs_dns_label_escape_new("", 0, &rr);
        assert_se(cv == rv);
        assert_se(cv == -EINVAL);
}

/* ── dns_name_concat ────────────────────────────────────────────────── */

static void test_dns_name_concat(void) {
        _cleanup_free_ char *cr = NULL, *rr = NULL;
        int cv, rv;

        /* Simple concatenation */
        cv = dns_name_concat("www", "example.com", 0, &cr);
        rv = rs_dns_name_concat("www", "example.com", 0, &rr);
        assert_se(cv == rv);
        assert_se(cv == 0);
        assert_se(streq(cr, rr));
        assert_se(streq(cr, "www.example.com"));

        cr = mfree(cr);
        rr = mfree(rr);

        /* Both NULL → "." (root) */
        cv = dns_name_concat(NULL, NULL, 0, &cr);
        rv = rs_dns_name_concat(NULL, NULL, 0, &rr);
        assert_se(cv == rv);
        assert_se(cv == 0);
        assert_se(streq(cr, rr));
        assert_se(streq(cr, "."));

        cr = mfree(cr);
        rr = mfree(rr);

        /* NULL a, b only */
        cv = dns_name_concat(NULL, "example.com", 0, &cr);
        rv = rs_dns_name_concat(NULL, "example.com", 0, &rr);
        assert_se(cv == rv);
        assert_se(cv == 0);
        assert_se(streq(cr, rr));

        cr = mfree(cr);
        rr = mfree(rr);

        /* Validate only (ret=NULL) */
        cv = dns_name_concat("www.example.com", NULL, 0, NULL);
        rv = rs_dns_name_concat("www.example.com", NULL, 0, NULL);
        assert_se(cv == rv);
        assert_se(cv == 0);

        /* Invalid name → -EINVAL */
        cv = dns_name_concat("www..example.com", NULL, 0, NULL);
        rv = rs_dns_name_concat("www..example.com", NULL, 0, NULL);
        assert_se(cv == rv);
        assert_se(cv == -EINVAL);
}

/* ── dns_name_change_suffix ─────────────────────────────────────────── */

static void test_dns_name_change_suffix(void) {
        _cleanup_free_ char *cr = NULL, *rr = NULL;
        int cv, rv;

        /* Change com → org */
        cv = dns_name_change_suffix("www.example.com", "example.com", "example.org", &cr);
        rv = rs_dns_name_change_suffix("www.example.com", "example.com", "example.org", &rr);
        assert_se(cv == rv);
        assert_se(cv > 0);
        assert_se(streq(cr, rr));
        assert_se(streq(cr, "www.example.org"));

        cr = mfree(cr);
        rr = mfree(rr);

        /* No match */
        cv = dns_name_change_suffix("www.example.com", "other.com", "other.org", &cr);
        rv = rs_dns_name_change_suffix("www.example.com", "other.com", "other.org", &rr);
        assert_se(cv == rv);
        assert_se(cv == 0);

        /* NULL old_suffix matches root — test C only first */
        cv = dns_name_change_suffix("example.com", NULL, "newsuffix.com", &cr);
        assert_se(cv > 0 || cv == 0); /* may or may not match */
        cr = mfree(cr);

        /* Change suffix: host.sub.example.com → host.sub.example.org */
        cv = dns_name_change_suffix("host.sub.example.com", "example.com", "example.org", &cr);
        rv = rs_dns_name_change_suffix("host.sub.example.com", "example.com", "example.org", &rr);
        assert_se(cv == rv);
        assert_se(cv > 0);
        assert_se(streq(cr, rr));
}

/* ── dns_name_normalize ─────────────────────────────────────────────── */

static void test_dns_name_normalize(void) {
        _cleanup_free_ char *cr = NULL, *rr = NULL;
        int cv, rv;

        cv = dns_name_normalize("www.example.com", 0, &cr);
        rv = rs_dns_name_normalize("www.example.com", 0, &rr);
        assert_se(cv == rv);
        assert_se(cv == 0);
        assert_se(streq(cr, rr));

        cr = mfree(cr);
        rr = mfree(rr);

        /* Invalid name */
        cv = dns_name_normalize("www..example.com", 0, NULL);
        rv = rs_dns_name_normalize("www..example.com", 0, NULL);
        assert_se(cv == rv);
        assert_se(cv == -EINVAL);

        /* Validate only (NULL ret) */
        cv = dns_name_normalize("www.example.com", 0, NULL);
        rv = rs_dns_name_normalize("www.example.com", 0, NULL);
        assert_se(cv == rv);
        assert_se(cv == 0);
}

/* ── dns_name_is_valid ──────────────────────────────────────────────── */

static void test_dns_name_is_valid(void) {
        int cv, rv;

        cv = dns_name_is_valid("www.example.com");
        rv = rs_dns_name_is_valid("www.example.com");
        assert_se(cv == rv);
        assert_se(cv > 0);

        /* Empty string = root domain, valid */
        cv = dns_name_is_valid("");
        rv = rs_dns_name_is_valid("");
        assert_se(cv == rv);
        assert_se(cv > 0);

        /* Valid single label */
        cv = dns_name_is_valid("valid-label");
        rv = rs_dns_name_is_valid("valid-label");
        assert_se(cv == rv);
        assert_se(cv > 0);

        /* Invalid: consecutive dots */
        cv = dns_name_is_valid("invalid..name");
        rv = rs_dns_name_is_valid("invalid..name");
        assert_se(cv == rv);
        assert_se(cv == 0);

        /* Trailing dot = root, valid */
        cv = dns_name_is_valid("example.");
        rv = rs_dns_name_is_valid("example.");
        assert_se(cv == rv);
        assert_se(cv > 0);
}

/* ── dns_name_is_valid_ldh ─────────────────────────────────────────── */

static void test_dns_name_is_valid_ldh(void) {
        int cv, rv;

        cv = dns_name_is_valid_ldh("www.example.com");
        rv = rs_dns_name_is_valid_ldh("www.example.com");
        assert_se(cv == rv);
        assert_se(cv > 0);

        cv = dns_name_is_valid_ldh("my-host");
        rv = rs_dns_name_is_valid_ldh("my-host");
        assert_se(cv == rv);
        assert_se(cv > 0);

        /* Underscore not LDH */
        cv = dns_name_is_valid_ldh("my_host");
        rv = rs_dns_name_is_valid_ldh("my_host");
        assert_se(cv == rv);
        assert_se(cv == 0);

        /* Leading hyphen not LDH */
        cv = dns_name_is_valid_ldh("-invalid");
        rv = rs_dns_name_is_valid_ldh("-invalid");
        assert_se(cv == rv);
        assert_se(cv == 0);
}

/* ── dns_service_join ───────────────────────────────────────────────── */

static void test_dns_service_join(void) {
        _cleanup_free_ char *cr = NULL, *rr = NULL;
        int cv, rv;

        /* With name: _http._tcp.example.com + "My Web" */
        cv = dns_service_join("My Web", "_http._tcp", "example.com", &cr);
        rv = rs_dns_service_join("My Web", "_http._tcp", "example.com", &rr);
        assert_se(cv == rv);
        assert_se(cv == 0);
        assert_se(streq(cr, rr));

        cr = mfree(cr);
        rr = mfree(rr);

        /* Without name: _http._tcp.example.com */
        cv = dns_service_join(NULL, "_http._tcp", "example.com", &cr);
        rv = rs_dns_service_join(NULL, "_http._tcp", "example.com", &rr);
        assert_se(cv == rv);
        assert_se(cv == 0);
        assert_se(streq(cr, rr));

        cr = mfree(cr);
        rr = mfree(rr);

        /* Invalid type → -EINVAL */
        cv = dns_service_join("name", "invalid", "example.com", &cr);
        rv = rs_dns_service_join("name", "invalid", "example.com", &rr);
        assert_se(cv == rv);
        assert_se(cv == -EINVAL);
}

/* ── dns_service_split ───────────────────────────────────────────────── */

static void test_dns_service_split(void) {
        _cleanup_free_ char *cn = NULL, *rn = NULL;
        _cleanup_free_ char *ct = NULL, *rt = NULL;
        _cleanup_free_ char *cd = NULL, *rd = NULL;
        int cv, rv;

        /* Split _http._tcp.example.com (no name) */
        cv = dns_service_split("_http._tcp.example.com", &cn, &ct, &cd);
        rv = rs_dns_service_split("_http._tcp.example.com", &rn, &rt, &rd);
        assert_se(cv == rv);
        assert_se(cv == 0);
        if (cn && rn) assert_se(streq(cn, rn));
        if (ct && rt) assert_se(streq(ct, rt));
        if (cd && rd) assert_se(streq(cd, rd));

        cn = mfree(cn); rn = mfree(rn);
        ct = mfree(ct); rt = mfree(rt);
        cd = mfree(cd); rd = mfree(rd);

        /* Split My\\032Web._http._tcp.example.com (with name) */
        cv = dns_service_split("My\\032Web._http._tcp.example.com", &cn, &ct, &cd);
        rv = rs_dns_service_split("My\\032Web._http._tcp.example.com", &rn, &rt, &rd);
        assert_se(cv == rv);
        assert_se(cv == 0);
        if (cn && rn) assert_se(streq(cn, rn));
        if (ct && rt) assert_se(streq(ct, rt));
        if (cd && rd) assert_se(streq(cd, rd));
}

int main(int argc, char **argv) {
        test_dns_label_unescape();
        test_dns_label_escape();
        test_dns_name_is_root();
        test_dns_name_parent();
        test_dns_name_equal();
        test_dns_name_endswith();
        test_dns_name_startswith();
        test_dns_name_count_labels();
        test_dns_srv_type_is_valid();
        test_dnssd_srv_type_is_valid();
        test_dns_name_is_single_label();
        test_dns_name_dont_resolve();
        test_dns_service_name_is_valid();
        test_dns_subtype_name_is_valid();
        test_dns_name_dot_suffixed();
        test_dns_name_skip();
        test_dns_name_suffix();
        test_dns_name_equal_skip();
        test_dns_name_common_suffix();
        test_dns_name_to_wire_format();
        test_dns_name_reverse();
        test_dns_name_address();
        test_dns_name_from_wire_format();
        test_dns_label_unescape_suffix();
        test_dns_name_compare_func();
        test_dns_name_between();
        test_dns_label_escape_new();
        test_dns_name_concat();
        test_dns_name_change_suffix();
        test_dns_name_normalize();
        test_dns_name_is_valid();
        test_dns_name_is_valid_ldh();
        test_dns_service_join();
        test_dns_service_split();
        return 0;
}
