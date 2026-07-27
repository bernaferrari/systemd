/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "dns-type.h"
#include "tests.h"

TEST(dns_type_may_redirect) {
        /* CNAME/DNAME themselves cannot be redirected */
        ASSERT_FALSE(dns_type_may_redirect(DNS_TYPE_CNAME));
        ASSERT_FALSE(dns_type_may_redirect(DNS_TYPE_DNAME));

        /* Regular records may be redirected */
        ASSERT_TRUE(dns_type_may_redirect(DNS_TYPE_A));
        ASSERT_TRUE(dns_type_may_redirect(DNS_TYPE_AAAA));
        ASSERT_TRUE(dns_type_may_redirect(DNS_TYPE_MX));

        /* DNSSEC types cannot */
        ASSERT_FALSE(dns_type_may_redirect(DNS_TYPE_RRSIG));
        ASSERT_FALSE(dns_type_may_redirect(DNS_TYPE_NSEC));
}

TEST(dns_type_is_zone_transfer) {
        ASSERT_TRUE(dns_type_is_zone_transfer(DNS_TYPE_AXFR));
        ASSERT_TRUE(dns_type_is_zone_transfer(DNS_TYPE_IXFR));
        ASSERT_FALSE(dns_type_is_zone_transfer(DNS_TYPE_A));
}

TEST(dns_type_is_valid_query) {
        ASSERT_TRUE(dns_type_is_valid_query(DNS_TYPE_A));
        ASSERT_TRUE(dns_type_is_valid_query(DNS_TYPE_AAAA));
        ASSERT_TRUE(dns_type_is_valid_query(DNS_TYPE_ANY)); /* ANY is a valid query type */
        ASSERT_FALSE(dns_type_is_valid_query(0));
        ASSERT_FALSE(dns_type_is_valid_query(DNS_TYPE_OPT));
        ASSERT_FALSE(dns_type_is_valid_query(DNS_TYPE_RRSIG));
}

TEST(dns_type_is_valid_rr) {
        ASSERT_TRUE(dns_type_is_valid_rr(DNS_TYPE_A));
        ASSERT_FALSE(dns_type_is_valid_rr(DNS_TYPE_ANY));
        ASSERT_FALSE(dns_type_is_valid_rr(DNS_TYPE_AXFR));
}

TEST(dns_type_apex_only) {
        ASSERT_TRUE(dns_type_apex_only(DNS_TYPE_SOA));
        ASSERT_TRUE(dns_type_apex_only(DNS_TYPE_DNSKEY));
        ASSERT_FALSE(dns_type_apex_only(DNS_TYPE_A));
}

TEST(dns_type_needs_authentication) {
        ASSERT_TRUE(dns_type_needs_authentication(DNS_TYPE_DNSKEY));
        ASSERT_TRUE(dns_type_needs_authentication(DNS_TYPE_DS));
        ASSERT_TRUE(dns_type_needs_authentication(DNS_TYPE_SSHFP));
        ASSERT_FALSE(dns_type_needs_authentication(DNS_TYPE_A));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
