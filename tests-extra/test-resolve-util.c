/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "resolve-util.h"
#include "tests.h"

TEST(resolve_support_to_string) {
        ASSERT_STREQ(resolve_support_to_string(RESOLVE_SUPPORT_NO), "no");
        ASSERT_STREQ(resolve_support_to_string(RESOLVE_SUPPORT_RESOLVE), "resolve");
        ASSERT_STREQ(resolve_support_to_string(RESOLVE_SUPPORT_YES), "yes");
}

TEST(resolve_support_from_string) {
        ASSERT_EQ(resolve_support_from_string("no"), RESOLVE_SUPPORT_NO);
        ASSERT_EQ(resolve_support_from_string("yes"), RESOLVE_SUPPORT_YES);
        ASSERT_EQ(resolve_support_from_string("resolve"), RESOLVE_SUPPORT_RESOLVE);
        ASSERT_EQ(resolve_support_from_string("invalid"), _RESOLVE_SUPPORT_INVALID);
}

TEST(dnssec_mode_to_string) {
        ASSERT_STREQ(dnssec_mode_to_string(DNSSEC_NO), "no");
        ASSERT_STREQ(dnssec_mode_to_string(DNSSEC_ALLOW_DOWNGRADE), "allow-downgrade");
        ASSERT_STREQ(dnssec_mode_to_string(DNSSEC_YES), "yes");
}

TEST(dnssec_mode_from_string) {
        ASSERT_EQ(dnssec_mode_from_string("no"), DNSSEC_NO);
        ASSERT_EQ(dnssec_mode_from_string("allow-downgrade"), DNSSEC_ALLOW_DOWNGRADE);
        ASSERT_EQ(dnssec_mode_from_string("yes"), DNSSEC_YES);
        ASSERT_EQ(dnssec_mode_from_string("invalid"), _DNSSEC_MODE_INVALID);
}

TEST(dns_over_tls_mode_to_string) {
        ASSERT_STREQ(dns_over_tls_mode_to_string(DNS_OVER_TLS_NO), "no");
        ASSERT_STREQ(dns_over_tls_mode_to_string(DNS_OVER_TLS_OPPORTUNISTIC), "opportunistic");
        ASSERT_STREQ(dns_over_tls_mode_to_string(DNS_OVER_TLS_YES), "yes");
}

TEST(dns_over_tls_mode_from_string) {
        ASSERT_EQ(dns_over_tls_mode_from_string("no"), DNS_OVER_TLS_NO);
        ASSERT_EQ(dns_over_tls_mode_from_string("opportunistic"), DNS_OVER_TLS_OPPORTUNISTIC);
        ASSERT_EQ(dns_over_tls_mode_from_string("yes"), DNS_OVER_TLS_YES);
        ASSERT_EQ(dns_over_tls_mode_from_string("invalid"), _DNS_OVER_TLS_MODE_INVALID);
}

TEST(dns_cache_mode_to_string) {
        ASSERT_STREQ(dns_cache_mode_to_string(DNS_CACHE_MODE_YES), "yes");
        ASSERT_STREQ(dns_cache_mode_to_string(DNS_CACHE_MODE_NO), "no");
        ASSERT_STREQ(dns_cache_mode_to_string(DNS_CACHE_MODE_NO_NEGATIVE), "no-negative");
}

TEST(dns_cache_mode_from_string) {
        ASSERT_EQ(dns_cache_mode_from_string("yes"), DNS_CACHE_MODE_YES);
        ASSERT_EQ(dns_cache_mode_from_string("no"), DNS_CACHE_MODE_NO);
        ASSERT_EQ(dns_cache_mode_from_string("no-negative"), DNS_CACHE_MODE_NO_NEGATIVE);
        ASSERT_EQ(dns_cache_mode_from_string("invalid"), _DNS_CACHE_MODE_INVALID);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
