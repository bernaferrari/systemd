/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Shadow test: C resolve-util string tables and dns_server_address_valid vs Rust */

#include <assert.h>
#include <string.h>
#include "tests.h"
#include "string-util.h"
#include "resolve-util.h"
#include "in-addr-util.h"

/* Rust FFI forward declarations */
const char *rs_resolve_support_to_string(int support);
int rs_resolve_support_from_string(const char *s);
const char *rs_dnssec_mode_to_string(int mode);
int rs_dnssec_mode_from_string(const char *s);
const char *rs_dns_over_tls_mode_to_string(int mode);
int rs_dns_over_tls_mode_from_string(const char *s);
const char *rs_dns_cache_mode_to_string(int mode);
int rs_dns_cache_mode_from_string(const char *s);
bool rs_dns_server_address_valid(int family, const void *sa);

/* -- resolve_support -------------------------------------------------------- */

static void test_resolve_support(void) {
        /* to_string */
        assert_se(streq_ptr(resolve_support_to_string(RESOLVE_SUPPORT_NO), rs_resolve_support_to_string(RESOLVE_SUPPORT_NO)));
        assert_se(streq(resolve_support_to_string(RESOLVE_SUPPORT_NO), "no"));
        assert_se(streq_ptr(resolve_support_to_string(RESOLVE_SUPPORT_YES), rs_resolve_support_to_string(RESOLVE_SUPPORT_YES)));
        assert_se(streq(resolve_support_to_string(RESOLVE_SUPPORT_YES), "yes"));
        assert_se(streq_ptr(resolve_support_to_string(RESOLVE_SUPPORT_RESOLVE), rs_resolve_support_to_string(RESOLVE_SUPPORT_RESOLVE)));
        assert_se(streq(resolve_support_to_string(RESOLVE_SUPPORT_RESOLVE), "resolve"));

        /* from_string */
        assert_se(resolve_support_from_string("no") == rs_resolve_support_from_string("no"));
        assert_se(resolve_support_from_string("no") == RESOLVE_SUPPORT_NO);
        assert_se(resolve_support_from_string("yes") == rs_resolve_support_from_string("yes"));
        assert_se(resolve_support_from_string("yes") == RESOLVE_SUPPORT_YES);
        assert_se(resolve_support_from_string("resolve") == rs_resolve_support_from_string("resolve"));
        assert_se(resolve_support_from_string("resolve") == RESOLVE_SUPPORT_RESOLVE);
}

/* -- dnssec_mode ---------------------------------------------------------- */

static void test_dnssec_mode(void) {
        assert_se(streq_ptr(dnssec_mode_to_string(DNSSEC_NO), rs_dnssec_mode_to_string(DNSSEC_NO)));
        assert_se(streq(dnssec_mode_to_string(DNSSEC_NO), "no"));
        assert_se(streq_ptr(dnssec_mode_to_string(DNSSEC_ALLOW_DOWNGRADE), rs_dnssec_mode_to_string(DNSSEC_ALLOW_DOWNGRADE)));
        assert_se(streq(dnssec_mode_to_string(DNSSEC_ALLOW_DOWNGRADE), "allow-downgrade"));
        assert_se(streq_ptr(dnssec_mode_to_string(DNSSEC_YES), rs_dnssec_mode_to_string(DNSSEC_YES)));
        assert_se(streq(dnssec_mode_to_string(DNSSEC_YES), "yes"));

        assert_se(dnssec_mode_from_string("no") == rs_dnssec_mode_from_string("no"));
        assert_se(dnssec_mode_from_string("no") == DNSSEC_NO);
        assert_se(dnssec_mode_from_string("yes") == rs_dnssec_mode_from_string("yes"));
        assert_se(dnssec_mode_from_string("yes") == DNSSEC_YES);
}

/* -- dns_over_tls_mode ----------------------------------------------------- */

static void test_dns_over_tls_mode(void) {
        assert_se(streq_ptr(dns_over_tls_mode_to_string(DNS_OVER_TLS_NO), rs_dns_over_tls_mode_to_string(DNS_OVER_TLS_NO)));
        assert_se(streq(dns_over_tls_mode_to_string(DNS_OVER_TLS_NO), "no"));
        assert_se(streq_ptr(dns_over_tls_mode_to_string(DNS_OVER_TLS_OPPORTUNISTIC), rs_dns_over_tls_mode_to_string(DNS_OVER_TLS_OPPORTUNISTIC)));
        assert_se(streq(dns_over_tls_mode_to_string(DNS_OVER_TLS_OPPORTUNISTIC), "opportunistic"));
        assert_se(streq_ptr(dns_over_tls_mode_to_string(DNS_OVER_TLS_YES), rs_dns_over_tls_mode_to_string(DNS_OVER_TLS_YES)));
        assert_se(streq(dns_over_tls_mode_to_string(DNS_OVER_TLS_YES), "yes"));

        assert_se(dns_over_tls_mode_from_string("no") == rs_dns_over_tls_mode_from_string("no"));
        assert_se(dns_over_tls_mode_from_string("no") == DNS_OVER_TLS_NO);
        assert_se(dns_over_tls_mode_from_string("yes") == rs_dns_over_tls_mode_from_string("yes"));
        assert_se(dns_over_tls_mode_from_string("yes") == DNS_OVER_TLS_YES);
}

/* -- dns_cache_mode ------------------------------------------------------ */

static void test_dns_cache_mode(void) {
        assert_se(streq_ptr(dns_cache_mode_to_string(DNS_CACHE_MODE_YES), rs_dns_cache_mode_to_string(DNS_CACHE_MODE_YES)));
        assert_se(streq(dns_cache_mode_to_string(DNS_CACHE_MODE_YES), "yes"));
        assert_se(streq_ptr(dns_cache_mode_to_string(DNS_CACHE_MODE_NO), rs_dns_cache_mode_to_string(DNS_CACHE_MODE_NO)));
        assert_se(streq(dns_cache_mode_to_string(DNS_CACHE_MODE_NO), "no"));
        assert_se(streq_ptr(dns_cache_mode_to_string(DNS_CACHE_MODE_NO_NEGATIVE), rs_dns_cache_mode_to_string(DNS_CACHE_MODE_NO_NEGATIVE)));
        assert_se(streq(dns_cache_mode_to_string(DNS_CACHE_MODE_NO_NEGATIVE), "no-negative"));

        assert_se(dns_cache_mode_from_string("yes") == rs_dns_cache_mode_from_string("yes"));
        assert_se(dns_cache_mode_from_string("yes") == DNS_CACHE_MODE_YES);
        assert_se(dns_cache_mode_from_string("no") == rs_dns_cache_mode_from_string("no"));
        assert_se(dns_cache_mode_from_string("no") == DNS_CACHE_MODE_NO);
}

/* -- dns_server_address_valid --------------------------------------------- */

static void test_dns_server_address_valid(void) {
        union in_addr_union sa4;
        union in_addr_union sa6;

        /* All-zero address → invalid */
        memset(&sa4, 0, sizeof(sa4));
        assert_se(dns_server_address_valid(AF_INET, &sa4) == rs_dns_server_address_valid(AF_INET, &sa4));
        assert_se(dns_server_address_valid(AF_INET, &sa4) == false);

        memset(&sa6, 0, sizeof(sa6));
        assert_se(dns_server_address_valid(AF_INET6, &sa6) == rs_dns_server_address_valid(AF_INET6, &sa6));
        assert_se(dns_server_address_valid(AF_INET6, &sa6) == false);

        /* 127.0.0.53 (DNS stub) → invalid */
        assert_se(in_addr_from_string(AF_INET, "127.0.0.53", &sa4) >= 0);
        assert_se(dns_server_address_valid(AF_INET, &sa4) == rs_dns_server_address_valid(AF_INET, &sa4));
        assert_se(dns_server_address_valid(AF_INET, &sa4) == false);

        /* 127.0.0.54 (DNS proxy stub) → invalid */
        assert_se(in_addr_from_string(AF_INET, "127.0.0.54", &sa4) >= 0);
        assert_se(dns_server_address_valid(AF_INET, &sa4) == rs_dns_server_address_valid(AF_INET, &sa4));
        assert_se(dns_server_address_valid(AF_INET, &sa4) == false);

        /* 8.8.8.8 → valid */
        assert_se(in_addr_from_string(AF_INET, "8.8.8.8", &sa4) >= 0);
        assert_se(dns_server_address_valid(AF_INET, &sa4) == rs_dns_server_address_valid(AF_INET, &sa4));
        assert_se(dns_server_address_valid(AF_INET, &sa4) == true);

        /* 1.1.1.1 → valid */
        assert_se(in_addr_from_string(AF_INET, "1.1.1.1", &sa4) >= 0);
        assert_se(dns_server_address_valid(AF_INET, &sa4) == rs_dns_server_address_valid(AF_INET, &sa4));
        assert_se(dns_server_address_valid(AF_INET, &sa4) == true);

        /* ::1 → valid */
        assert_se(in_addr_from_string(AF_INET6, "::1", &sa6) >= 0);
        assert_se(dns_server_address_valid(AF_INET6, &sa6) == rs_dns_server_address_valid(AF_INET6, &sa6));
        assert_se(dns_server_address_valid(AF_INET6, &sa6) == true);
}

int main(int argc, char **argv) {
        test_resolve_support();
        test_dnssec_mode();
        test_dns_over_tls_mode();
        test_dns_cache_mode();
        test_dns_server_address_valid();
        return 0;
}
