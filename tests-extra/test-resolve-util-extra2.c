/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "string-util.h"
#include "tests.h"
#include "resolve-util.h"

TEST(resolve_support_to_from_string) {
        assert_se(streq(resolve_support_to_string(RESOLVE_SUPPORT_NO), "no"));
        assert_se(streq(resolve_support_to_string(RESOLVE_SUPPORT_RESOLVE), "resolve"));
        assert_se(streq(resolve_support_to_string(RESOLVE_SUPPORT_YES), "yes"));

        assert_se(resolve_support_from_string("no") == RESOLVE_SUPPORT_NO);
        assert_se(resolve_support_from_string("resolve") == RESOLVE_SUPPORT_RESOLVE);
        assert_se(resolve_support_from_string("yes") == RESOLVE_SUPPORT_YES);

        /* Boolean aliases */
        assert_se(resolve_support_from_string("true") == RESOLVE_SUPPORT_YES);
        assert_se(resolve_support_from_string("false") == RESOLVE_SUPPORT_NO);
        assert_se(resolve_support_from_string("invalid") < 0);
}

TEST(dnssec_mode_to_from_string) {
        assert_se(streq(dnssec_mode_to_string(DNSSEC_NO), "no"));
        assert_se(streq(dnssec_mode_to_string(DNSSEC_ALLOW_DOWNGRADE), "allow-downgrade"));
        assert_se(streq(dnssec_mode_to_string(DNSSEC_YES), "yes"));

        assert_se(dnssec_mode_from_string("no") == DNSSEC_NO);
        assert_se(dnssec_mode_from_string("allow-downgrade") == DNSSEC_ALLOW_DOWNGRADE);
        assert_se(dnssec_mode_from_string("yes") == DNSSEC_YES);
        assert_se(dnssec_mode_from_string("true") == DNSSEC_YES);
        assert_se(dnssec_mode_from_string("false") == DNSSEC_NO);
        assert_se(dnssec_mode_from_string("invalid") < 0);
}

TEST(dns_over_tls_mode_to_from_string) {
        assert_se(streq(dns_over_tls_mode_to_string(DNS_OVER_TLS_NO), "no"));
        assert_se(streq(dns_over_tls_mode_to_string(DNS_OVER_TLS_OPPORTUNISTIC), "opportunistic"));
        assert_se(streq(dns_over_tls_mode_to_string(DNS_OVER_TLS_YES), "yes"));

        assert_se(dns_over_tls_mode_from_string("no") == DNS_OVER_TLS_NO);
        assert_se(dns_over_tls_mode_from_string("opportunistic") == DNS_OVER_TLS_OPPORTUNISTIC);
        assert_se(dns_over_tls_mode_from_string("yes") == DNS_OVER_TLS_YES);
        assert_se(dns_over_tls_mode_from_string("true") == DNS_OVER_TLS_YES);
        assert_se(dns_over_tls_mode_from_string("invalid") < 0);
}

TEST(dns_cache_mode_to_from_string) {
        assert_se(streq(dns_cache_mode_to_string(DNS_CACHE_MODE_NO), "no"));
        assert_se(streq(dns_cache_mode_to_string(DNS_CACHE_MODE_YES), "yes"));
        assert_se(streq(dns_cache_mode_to_string(DNS_CACHE_MODE_NO_NEGATIVE), "no-negative"));

        assert_se(dns_cache_mode_from_string("no") == DNS_CACHE_MODE_NO);
        assert_se(dns_cache_mode_from_string("yes") == DNS_CACHE_MODE_YES);
        assert_se(dns_cache_mode_from_string("no-negative") == DNS_CACHE_MODE_NO_NEGATIVE);
        assert_se(dns_cache_mode_from_string("true") == DNS_CACHE_MODE_YES);
        assert_se(dns_cache_mode_from_string("invalid") < 0);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
