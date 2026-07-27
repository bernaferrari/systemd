/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "dns-domain.h"
#include "tests.h"

/* ── dns_name_count_labels ─────────────────────────────────────────── */

TEST(dns_name_count_labels_basic) {
        int r;

        r = dns_name_count_labels("");
        ASSERT_EQ(r, 0);

        r = dns_name_count_labels(".");
        ASSERT_EQ(r, 0);

        r = dns_name_count_labels("www");
        ASSERT_EQ(r, 1);

        r = dns_name_count_labels("www.example.com");
        ASSERT_EQ(r, 3);

        r = dns_name_count_labels("www.example.com.");
        ASSERT_EQ(r, 3);

        r = dns_name_count_labels("a.b.c.d.e.f");
        ASSERT_EQ(r, 6);
}

/* ── dns_name_is_root ──────────────────────────────────────────────── */

TEST(dns_name_is_root_basic) {
        assert_se(dns_name_is_root(""));
        assert_se(dns_name_is_root("."));
        assert_se(!dns_name_is_root("www"));
        assert_se(!dns_name_is_root("example.com."));
}

/* ── dns_name_is_single_label ──────────────────────────────────────── */

TEST(dns_name_is_single_label_basic) {
        assert_se(dns_name_is_single_label("www"));
        assert_se(dns_name_is_single_label("_tcp"));
        assert_se(!dns_name_is_single_label("www.example"));
        assert_se(!dns_name_is_single_label(""));
        assert_se(!dns_name_is_single_label("."));
        assert_se(!dns_name_is_single_label("example.com."));
}

/* ── dns_name_startswith ───────────────────────────────────────────── */

TEST(dns_name_startswith_basic) {
        int r;

        r = dns_name_startswith("www.example.com", "www");
        ASSERT_GT(r, 0);

        r = dns_name_startswith("www.example.com", "www.example");
        ASSERT_GT(r, 0);

        r = dns_name_startswith("www.example.com", "www.example.com");
        ASSERT_GT(r, 0);

        r = dns_name_startswith("www.example.com", "example");
        ASSERT_EQ(r, 0);

        r = dns_name_startswith("www.example.com", "wwwx");
        ASSERT_EQ(r, 0);

        /* Empty prefix matches everything */
        r = dns_name_startswith("www.example.com", "");
        ASSERT_GT(r, 0);
}

/* ── dns_name_equal (case-insensitive) ─────────────────────────────── */

TEST(dns_name_equal_case) {
        int r;

        r = dns_name_equal("www.Example.COM", "www.example.com");
        ASSERT_GT(r, 0);

        r = dns_name_equal("WWW.EXAMPLE.COM", "www.example.com");
        ASSERT_GT(r, 0);

        r = dns_name_equal("www.example.com", "www.example.org");
        ASSERT_EQ(r, 0);
}

/* ── dns_srv_type_is_valid / dnssd_srv_type_is_valid ───────────────── */

TEST(dns_srv_type_valid_basic) {
        assert_se(dns_srv_type_is_valid("_http._tcp"));
        assert_se(dns_srv_type_is_valid("_ftp._tcp"));
        assert_se(dns_srv_type_is_valid("_sip._udp"));
        assert_se(!dns_srv_type_is_valid("_http"));
        assert_se(!dns_srv_type_is_valid("http._tcp"));
        assert_se(!dns_srv_type_is_valid(""));
        assert_se(!dns_srv_type_is_valid(NULL));
        assert_se(!dns_srv_type_is_valid("_http._tcp._udp")); /* three labels */

        assert_se(dnssd_srv_type_is_valid("_http._tcp"));
        assert_se(dnssd_srv_type_is_valid("_sip._udp"));
        assert_se(!dnssd_srv_type_is_valid("_http._sctp")); /* not tcp or udp */
        assert_se(!dnssd_srv_type_is_valid("_http"));
}

/* ── dns_service_name_is_valid / dns_subtype_name_is_valid ─────────── */

TEST(dns_service_name_valid_basic) {
        assert_se(dns_service_name_is_valid("My Printer"));
        assert_se(dns_service_name_is_valid("_http._tcp"));
        assert_se(!dns_service_name_is_valid(NULL));
        assert_se(!dns_service_name_is_valid(""));
        assert_se(!dns_service_name_is_valid("test\x01")); /* control char */

        assert_se(dns_subtype_name_is_valid("printer"));
        assert_se(dns_subtype_name_is_valid("_ipps"));
        assert_se(!dns_subtype_name_is_valid(NULL));
        assert_se(!dns_subtype_name_is_valid(""));
}

DEFINE_TEST_MAIN(LOG_INFO);
