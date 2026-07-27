/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Shadow test: C dns-type.c + dns-domain.c validators vs Rust */

#include <assert.h>
#include <string.h>
#include "tests.h"
#include "string-util.h"

/* C headers */
#include "dns-type.h"
#include "dns-domain.h"

/* Rust FFI */
#include "rust/dns_type_predicates.h"
#include "rust/dns_domain_validators.h"

/* ── TLSA string lookups ──────────────────────────────────────────────── */

static void test_tlsa_cert_usage_to_string(void) {
        const char *cs, *rs;

        cs = tlsa_cert_usage_to_string(0);
        rs = rs_tlsa_cert_usage_to_string(0);
        assert_se(streq(cs, rs));
        assert_se(streq(cs, "CA constraint"));

        cs = tlsa_cert_usage_to_string(1);
        rs = rs_tlsa_cert_usage_to_string(1);
        assert_se(streq(cs, rs));
        assert_se(streq(cs, "Service certificate constraint"));

        cs = tlsa_cert_usage_to_string(2);
        rs = rs_tlsa_cert_usage_to_string(2);
        assert_se(streq(cs, rs));

        cs = tlsa_cert_usage_to_string(3);
        rs = rs_tlsa_cert_usage_to_string(3);
        assert_se(streq(cs, rs));
        assert_se(streq(cs, "Domain-issued certificate"));

        /* Unassigned range */
        cs = tlsa_cert_usage_to_string(100);
        rs = rs_tlsa_cert_usage_to_string(100);
        assert_se(streq(cs, rs));
        assert_se(streq(cs, "Unassigned"));

        cs = tlsa_cert_usage_to_string(4);
        rs = rs_tlsa_cert_usage_to_string(4);
        assert_se(streq(cs, rs));

        cs = tlsa_cert_usage_to_string(254);
        rs = rs_tlsa_cert_usage_to_string(254);
        assert_se(streq(cs, rs));

        /* Private use */
        cs = tlsa_cert_usage_to_string(255);
        rs = rs_tlsa_cert_usage_to_string(255);
        assert_se(streq(cs, rs));
        assert_se(streq(cs, "Private use"));
}

static void test_tlsa_selector_to_string(void) {
        const char *cs, *rs;

        cs = tlsa_selector_to_string(0);
        rs = rs_tlsa_selector_to_string(0);
        assert_se(streq(cs, rs));
        assert_se(streq(cs, "Full Certificate"));

        cs = tlsa_selector_to_string(1);
        rs = rs_tlsa_selector_to_string(1);
        assert_se(streq(cs, rs));
        assert_se(streq(cs, "SubjectPublicKeyInfo"));

        cs = tlsa_selector_to_string(100);
        rs = rs_tlsa_selector_to_string(100);
        assert_se(streq(cs, rs));
        assert_se(streq(cs, "Unassigned"));

        cs = tlsa_selector_to_string(255);
        rs = rs_tlsa_selector_to_string(255);
        assert_se(streq(cs, rs));
        assert_se(streq(cs, "Private use"));
}

static void test_tlsa_matching_type_to_string(void) {
        const char *cs, *rs;

        cs = tlsa_matching_type_to_string(0);
        rs = rs_tlsa_matching_type_to_string(0);
        assert_se(streq(cs, rs));
        assert_se(streq(cs, "No hash used"));

        cs = tlsa_matching_type_to_string(1);
        rs = rs_tlsa_matching_type_to_string(1);
        assert_se(streq(cs, rs));
        assert_se(streq(cs, "SHA-256"));

        cs = tlsa_matching_type_to_string(2);
        rs = rs_tlsa_matching_type_to_string(2);
        assert_se(streq(cs, rs));
        assert_se(streq(cs, "SHA-512"));

        cs = tlsa_matching_type_to_string(100);
        rs = rs_tlsa_matching_type_to_string(100);
        assert_se(streq(cs, rs));
        assert_se(streq(cs, "Unassigned"));

        cs = tlsa_matching_type_to_string(255);
        rs = rs_tlsa_matching_type_to_string(255);
        assert_se(streq(cs, rs));
        assert_se(streq(cs, "Private use"));
}

/* ── DNS domain validators ────────────────────────────────────────────── */

static void test_dns_service_name_is_valid(void) {
        bool cv, rv;

        /* NULL */
        cv = dns_service_name_is_valid(NULL);
        rv = rs_dns_service_name_is_valid(NULL);
        assert_se(cv == rv);
        assert_se(cv == false);

        /* Empty */
        cv = dns_service_name_is_valid("");
        rv = rs_dns_service_name_is_valid("");
        assert_se(cv == rv);
        assert_se(cv == false);

        /* Valid simple name */
        cv = dns_service_name_is_valid("my service");
        rv = rs_dns_service_name_is_valid("my service");
        assert_se(cv == rv);
        assert_se(cv == true);

        /* Valid single char */
        cv = dns_service_name_is_valid("a");
        rv = rs_dns_service_name_is_valid("a");
        assert_se(cv == rv);
        assert_se(cv == true);

        /* Control character */
        cv = dns_service_name_is_valid("bad\001name");
        rv = rs_dns_service_name_is_valid("bad\001name");
        assert_se(cv == rv);
        assert_se(cv == false);

        /* Tab character */
        cv = dns_service_name_is_valid("bad\tname");
        rv = rs_dns_service_name_is_valid("bad\tname");
        assert_se(cv == rv);
        assert_se(cv == false);

        /* DEL character */
        cv = dns_service_name_is_valid("bad\177name");
        rv = rs_dns_service_name_is_valid("bad\177name");
        assert_se(cv == rv);
        assert_se(cv == false);

        /* Invalid UTF-8 */
        cv = dns_service_name_is_valid("bad\xff\xfe");
        rv = rs_dns_service_name_is_valid("bad\xff\xfe");
        assert_se(cv == rv);
        assert_se(cv == false);

        /* Max length (63 chars) */
        cv = dns_service_name_is_valid("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"); /* 70 chars - too long */
        rv = rs_dns_service_name_is_valid("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        assert_se(cv == rv);
        assert_se(cv == false);

        cv = dns_service_name_is_valid("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"); /* 63 chars - ok */
        rv = rs_dns_service_name_is_valid("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        assert_se(cv == rv);
        assert_se(cv == true);
}

static void test_dns_subtype_name_is_valid(void) {
        bool cv, rv;

        /* NULL */
        cv = dns_subtype_name_is_valid(NULL);
        rv = rs_dns_subtype_name_is_valid(NULL);
        assert_se(cv == rv);
        assert_se(cv == false);

        /* Empty */
        cv = dns_subtype_name_is_valid("");
        rv = rs_dns_subtype_name_is_valid("");
        assert_se(cv == rv);
        assert_se(cv == false);

        /* Valid */
        cv = dns_subtype_name_is_valid("_printer");
        rv = rs_dns_subtype_name_is_valid("_printer");
        assert_se(cv == rv);
        assert_se(cv == true);

        /* Control char */
        cv = dns_subtype_name_is_valid("bad\002");
        rv = rs_dns_subtype_name_is_valid("bad\002");
        assert_se(cv == rv);
        assert_se(cv == false);

        /* Invalid UTF-8 */
        cv = dns_subtype_name_is_valid("bad\xc0\x80");
        rv = rs_dns_subtype_name_is_valid("bad\xc0\x80");
        assert_se(cv == rv);
        assert_se(cv == false);
}

int main(int argc, char **argv) {
        test_tlsa_cert_usage_to_string();
        test_tlsa_selector_to_string();
        test_tlsa_matching_type_to_string();
        test_dns_service_name_is_valid();
        test_dns_subtype_name_is_valid();
        return 0;
}
