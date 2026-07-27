/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "resolve-util.h"
#include "string-util.h"
#include "tests.h"

TEST(resolve_support_roundtrip) {
        assert_se(streq(resolve_support_to_string(RESOLVE_SUPPORT_NO), "no"));
        assert_se(streq(resolve_support_to_string(RESOLVE_SUPPORT_YES), "yes"));
        assert_se(streq(resolve_support_to_string(RESOLVE_SUPPORT_RESOLVE), "resolve"));

        assert_se(resolve_support_from_string("no") == RESOLVE_SUPPORT_NO);
        assert_se(resolve_support_from_string("yes") == RESOLVE_SUPPORT_YES);
        assert_se(resolve_support_from_string("resolve") == RESOLVE_SUPPORT_RESOLVE);

        /* WITH_BOOLEAN also accepts "true"/"false" */
        assert_se(resolve_support_from_string("true") == RESOLVE_SUPPORT_YES);
        assert_se(resolve_support_from_string("false") == RESOLVE_SUPPORT_NO);

        /* Invalid */
        assert_se(resolve_support_from_string("invalid") == _RESOLVE_SUPPORT_INVALID);
        assert_se(resolve_support_from_string("") == _RESOLVE_SUPPORT_INVALID);
}

TEST(dnssec_mode_roundtrip) {
        assert_se(streq(dnssec_mode_to_string(DNSSEC_NO), "no"));
        assert_se(streq(dnssec_mode_to_string(DNSSEC_ALLOW_DOWNGRADE), "allow-downgrade"));
        assert_se(streq(dnssec_mode_to_string(DNSSEC_YES), "yes"));

        assert_se(dnssec_mode_from_string("no") == DNSSEC_NO);
        assert_se(dnssec_mode_from_string("allow-downgrade") == DNSSEC_ALLOW_DOWNGRADE);
        assert_se(dnssec_mode_from_string("yes") == DNSSEC_YES);

        /* WITH_BOOLEAN */
        assert_se(dnssec_mode_from_string("true") == DNSSEC_YES);
        assert_se(dnssec_mode_from_string("false") == DNSSEC_NO);

        /* Invalid */
        assert_se(dnssec_mode_from_string("invalid") == _DNSSEC_MODE_INVALID);
}

TEST(dns_over_tls_mode_roundtrip) {
        assert_se(streq(dns_over_tls_mode_to_string(DNS_OVER_TLS_NO), "no"));
        assert_se(streq(dns_over_tls_mode_to_string(DNS_OVER_TLS_OPPORTUNISTIC), "opportunistic"));
        assert_se(streq(dns_over_tls_mode_to_string(DNS_OVER_TLS_YES), "yes"));

        assert_se(dns_over_tls_mode_from_string("no") == DNS_OVER_TLS_NO);
        assert_se(dns_over_tls_mode_from_string("opportunistic") == DNS_OVER_TLS_OPPORTUNISTIC);
        assert_se(dns_over_tls_mode_from_string("yes") == DNS_OVER_TLS_YES);

        /* WITH_BOOLEAN */
        assert_se(dns_over_tls_mode_from_string("true") == DNS_OVER_TLS_YES);
        assert_se(dns_over_tls_mode_from_string("false") == DNS_OVER_TLS_NO);

        /* Invalid */
        assert_se(dns_over_tls_mode_from_string("invalid") == _DNS_OVER_TLS_MODE_INVALID);
}

TEST(dns_cache_mode_roundtrip) {
        assert_se(streq(dns_cache_mode_to_string(DNS_CACHE_MODE_YES), "yes"));
        assert_se(streq(dns_cache_mode_to_string(DNS_CACHE_MODE_NO), "no"));
        assert_se(streq(dns_cache_mode_to_string(DNS_CACHE_MODE_NO_NEGATIVE), "no-negative"));

        assert_se(dns_cache_mode_from_string("yes") == DNS_CACHE_MODE_YES);
        assert_se(dns_cache_mode_from_string("no") == DNS_CACHE_MODE_NO);
        assert_se(dns_cache_mode_from_string("no-negative") == DNS_CACHE_MODE_NO_NEGATIVE);

        /* WITH_BOOLEAN */
        assert_se(dns_cache_mode_from_string("true") == DNS_CACHE_MODE_YES);
        assert_se(dns_cache_mode_from_string("false") == DNS_CACHE_MODE_NO);

        /* Invalid */
        assert_se(dns_cache_mode_from_string("invalid") == _DNS_CACHE_MODE_INVALID);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
