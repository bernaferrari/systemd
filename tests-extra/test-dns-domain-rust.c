/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Shadow test: C dns-domain validators vs Rust */

#include <string.h>

#include "tests.h"
#include "dns-domain.h"
#include "rust/dns_domain_validators.h"

/* ── dns_service_name_is_valid ──────────────────────────────────────── */

static void test_dns_service_name_is_valid_null(void) {
        assert_se(!dns_service_name_is_valid(NULL));
        assert_se(!rs_dns_service_name_is_valid(NULL));
}

static void test_dns_service_name_is_valid_simple(void) {
        assert_se(dns_service_name_is_valid("MyPrinter") == rs_dns_service_name_is_valid("MyPrinter"));
        assert_se(dns_service_name_is_valid("MyPrinter") == true);

        assert_se(dns_service_name_is_valid("My Printer") == rs_dns_service_name_is_valid("My Printer"));
        assert_se(dns_service_name_is_valid("My Printer") == true);

        assert_se(dns_service_name_is_valid("My_Printer") == rs_dns_service_name_is_valid("My_Printer"));
        assert_se(dns_service_name_is_valid("My_Printer") == true);
}

static void test_dns_service_name_is_valid_single_char(void) {
        assert_se(dns_service_name_is_valid("a") == rs_dns_service_name_is_valid("a"));
        assert_se(dns_service_name_is_valid("a") == true);

        assert_se(dns_service_name_is_valid("0") == rs_dns_service_name_is_valid("0"));
        assert_se(dns_service_name_is_valid("0") == true);
}

static void test_dns_service_name_is_valid_with_special(void) {
        assert_se(dns_service_name_is_valid("hello-world") == rs_dns_service_name_is_valid("hello-world"));
        assert_se(dns_service_name_is_valid("hello-world") == true);

        assert_se(dns_service_name_is_valid("Service.Name") == rs_dns_service_name_is_valid("Service.Name"));
        assert_se(dns_service_name_is_valid("Service.Name") == true);
}

static void test_dns_service_name_is_valid_empty(void) {
        assert_se(!dns_service_name_is_valid(""));
        assert_se(!rs_dns_service_name_is_valid(""));
}

static void test_dns_service_name_is_valid_max_length(void) {
        /* 63 chars = DNS_LABEL_MAX, should be valid */
        char name[64];
        memset(name, 'a', 63);
        name[63] = '\0';
        assert_se(dns_service_name_is_valid(name) == rs_dns_service_name_is_valid(name));
        assert_se(dns_service_name_is_valid(name) == true);
}

static void test_dns_service_name_is_valid_too_long(void) {
        /* 64 chars = DNS_LABEL_MAX + 1, should be invalid */
        char name[65];
        memset(name, 'a', 64);
        name[64] = '\0';
        assert_se(!dns_service_name_is_valid(name));
        assert_se(!rs_dns_service_name_is_valid(name));
}

static void test_dns_service_name_is_valid_control_chars(void) {
        /* Control characters should be rejected */
        char buf[8];
        buf[0] = 0x01;
        memcpy(buf + 1, "test", 5);
        buf[6] = '\0';
        assert_se(!dns_service_name_is_valid(buf));
        assert_se(!rs_dns_service_name_is_valid(buf));

        buf[0] = 0x7f;
        memcpy(buf + 1, "test", 5);
        buf[6] = '\0';
        assert_se(!dns_service_name_is_valid(buf));
        assert_se(!rs_dns_service_name_is_valid(buf));
}

static void test_dns_service_name_is_valid_utf8(void) {
        /* Valid UTF-8 multi-byte should be accepted */
        assert_se(dns_service_name_is_valid("caf\xc3\xa9") == rs_dns_service_name_is_valid("caf\xc3\xa9"));
        assert_se(dns_service_name_is_valid("caf\xc3\xa9") == true);
}

/* ── dns_subtype_name_is_valid ──────────────────────────────────────── */

static void test_dns_subtype_name_is_valid_null(void) {
        assert_se(!dns_subtype_name_is_valid(NULL));
        assert_se(!rs_dns_subtype_name_is_valid(NULL));
}

static void test_dns_subtype_name_is_valid_simple(void) {
        assert_se(dns_subtype_name_is_valid("_sub") == rs_dns_subtype_name_is_valid("_sub"));
        assert_se(dns_subtype_name_is_valid("_sub") == true);

        assert_se(dns_subtype_name_is_valid("subtype") == rs_dns_subtype_name_is_valid("subtype"));
        assert_se(dns_subtype_name_is_valid("subtype") == true);

        assert_se(dns_subtype_name_is_valid("my-subtype") == rs_dns_subtype_name_is_valid("my-subtype"));
        assert_se(dns_subtype_name_is_valid("my-subtype") == true);
}

static void test_dns_subtype_name_is_valid_empty(void) {
        assert_se(!dns_subtype_name_is_valid(""));
        assert_se(!rs_dns_subtype_name_is_valid(""));
}

static void test_dns_subtype_name_is_valid_max_length(void) {
        char name[64];
        memset(name, 'b', 63);
        name[63] = '\0';
        assert_se(dns_subtype_name_is_valid(name) == rs_dns_subtype_name_is_valid(name));
        assert_se(dns_subtype_name_is_valid(name) == true);
}

static void test_dns_subtype_name_is_valid_too_long(void) {
        char name[65];
        memset(name, 'b', 64);
        name[64] = '\0';
        assert_se(!dns_subtype_name_is_valid(name));
        assert_se(!rs_dns_subtype_name_is_valid(name));
}

static void test_dns_subtype_name_is_valid_control_chars(void) {
        char buf[8];
        buf[0] = 0x1f;
        memcpy(buf + 1, "sub", 4);
        buf[5] = '\0';
        assert_se(!dns_subtype_name_is_valid(buf));
        assert_se(!rs_dns_subtype_name_is_valid(buf));
}

/* ── validators agree on same inputs ────────────────────────────────── */

static void test_dns_validators_agree(void) {
        const char *names[] = {
                "valid",
                "with space",
                "caf\xc3\xa9",
                "a",
                "test-name",
                "My Service Name",
                "12345",
                "foo.bar",
        };
        for (int i = 0; i < (int)ELEMENTSOF(names); i++) {
                bool svc_c = dns_service_name_is_valid(names[i]);
                bool svc_r = rs_dns_service_name_is_valid(names[i]);
                assert_se(svc_c == svc_r);

                bool sub_c = dns_subtype_name_is_valid(names[i]);
                bool sub_r = rs_dns_subtype_name_is_valid(names[i]);
                assert_se(sub_c == sub_r);
        }
}

/* ── dns_srv_type_is_valid ─────────────────────────────────────────── */

static void test_dns_srv_type_is_valid_null(void) {
        assert_se(!dns_srv_type_is_valid(NULL));
        assert_se(!rs_dns_srv_type_is_valid(NULL));
}

static void test_dns_srv_type_is_valid_valid(void) {
        /* RFC 6335: exactly two labels, each starting with '_', second char a letter */
        const char *valid[] = {
                "_http._tcp",
                "_https._tcp",
                "_ftp._tcp",
                "_sip._udp",
                "_xmpp-server._tcp",
                "_test._tcp",
                "_a1._tcp",
                "_ab._udp",
        };
        for (int i = 0; i < (int)ELEMENTSOF(valid); i++) {
                bool c = dns_srv_type_is_valid(valid[i]);
                bool r = rs_dns_srv_type_is_valid(valid[i]);
                assert_se(c == r);
                assert_se(c == true);
        }
}

static void test_dns_srv_type_is_valid_single_label(void) {
        /* Only one label — invalid */
        assert_se(!dns_srv_type_is_valid("_http"));
        assert_se(!rs_dns_srv_type_is_valid("_http"));
}

static void test_dns_srv_type_is_valid_three_labels(void) {
        /* Three labels — invalid */
        assert_se(!dns_srv_type_is_valid("_http._tcp._extra"));
        assert_se(!rs_dns_srv_type_is_valid("_http._tcp._extra"));
}

static void test_dns_srv_type_is_valid_no_underscore(void) {
        /* Labels must start with '_' */
        assert_se(!dns_srv_type_is_valid("http._tcp"));
        assert_se(!rs_dns_srv_type_is_valid("http._tcp"));

        assert_se(!dns_srv_type_is_valid("_http.tcp"));
        assert_se(!rs_dns_srv_type_is_valid("_http.tcp"));
}

static void test_dns_srv_type_is_valid_bad_second_char(void) {
        /* Second char must be a letter */
        assert_se(!dns_srv_type_is_valid("_1http._tcp"));
        assert_se(!rs_dns_srv_type_is_valid("_1http._tcp"));

        assert_se(!dns_srv_type_is_valid("_-http._tcp"));
        assert_se(!rs_dns_srv_type_is_valid("_-http._tcp"));
}

static void test_dns_srv_type_is_valid_empty(void) {
        assert_se(!dns_srv_type_is_valid(""));
        assert_se(!rs_dns_srv_type_is_valid(""));
}

static void test_dns_srv_type_is_valid_empty_labels(void) {
        /* Empty labels */
        assert_se(!dns_srv_type_is_valid("._tcp"));
        assert_se(!rs_dns_srv_type_is_valid("._tcp"));

        assert_se(!dns_srv_type_is_valid("_http."));
        assert_se(!rs_dns_srv_type_is_valid("_http."));
}

/* ── dnssd_srv_type_is_valid ───────────────────────────────────────── */

static void test_dnssd_srv_type_is_valid_null(void) {
        assert_se(!dnssd_srv_type_is_valid(NULL));
        assert_se(!rs_dnssd_srv_type_is_valid(NULL));
}

static void test_dnssd_srv_type_is_valid_tcp(void) {
        assert_se(dnssd_srv_type_is_valid("_http._tcp") == rs_dnssd_srv_type_is_valid("_http._tcp"));
        assert_se(dnssd_srv_type_is_valid("_http._tcp") == true);
}

static void test_dnssd_srv_type_is_valid_udp(void) {
        assert_se(dnssd_srv_type_is_valid("_sip._udp") == rs_dnssd_srv_type_is_valid("_sip._udp"));
        assert_se(dnssd_srv_type_is_valid("_sip._udp") == true);
}

static void test_dnssd_srv_type_is_valid_not_tcp_udp(void) {
        /* Valid SRV type but not DNS-SD (not _tcp or _udp) */
        assert_se(!dnssd_srv_type_is_valid("_http._sctp"));
        assert_se(!rs_dnssd_srv_type_is_valid("_http._sctp"));
}

static void test_dnssd_srv_type_is_valid_invalid_srv(void) {
        /* Invalid SRV type is also invalid DNS-SD */
        assert_se(!dnssd_srv_type_is_valid("http._tcp"));
        assert_se(!rs_dnssd_srv_type_is_valid("http._tcp"));

        assert_se(!dnssd_srv_type_is_valid("_http"));
        assert_se(!rs_dnssd_srv_type_is_valid("_http"));

        assert_se(!dnssd_srv_type_is_valid(""));
        assert_se(!rs_dnssd_srv_type_is_valid(""));
}

int main(int argc, char *argv[]) {
        test_dns_service_name_is_valid_null();
        test_dns_service_name_is_valid_simple();
        test_dns_service_name_is_valid_single_char();
        test_dns_service_name_is_valid_with_special();
        test_dns_service_name_is_valid_empty();
        test_dns_service_name_is_valid_max_length();
        test_dns_service_name_is_valid_too_long();
        test_dns_service_name_is_valid_control_chars();
        test_dns_service_name_is_valid_utf8();
        test_dns_subtype_name_is_valid_null();
        test_dns_subtype_name_is_valid_simple();
        test_dns_subtype_name_is_valid_empty();
        test_dns_subtype_name_is_valid_max_length();
        test_dns_subtype_name_is_valid_too_long();
        test_dns_subtype_name_is_valid_control_chars();
        test_dns_validators_agree();
        test_dns_srv_type_is_valid_null();
        test_dns_srv_type_is_valid_valid();
        test_dns_srv_type_is_valid_single_label();
        test_dns_srv_type_is_valid_three_labels();
        test_dns_srv_type_is_valid_no_underscore();
        test_dns_srv_type_is_valid_bad_second_char();
        test_dns_srv_type_is_valid_empty();
        test_dns_srv_type_is_valid_empty_labels();
        test_dnssd_srv_type_is_valid_null();
        test_dnssd_srv_type_is_valid_tcp();
        test_dnssd_srv_type_is_valid_udp();
        test_dnssd_srv_type_is_valid_not_tcp_udp();
        test_dnssd_srv_type_is_valid_invalid_srv();

        return 0;
}
