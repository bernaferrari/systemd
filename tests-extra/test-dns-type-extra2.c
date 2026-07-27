/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "dns-type.h"
#include "tests.h"
#include <sys/socket.h>

TEST(dns_type_is_pseudo) {
        ASSERT_TRUE(dns_type_is_pseudo(DNS_TYPE_ANY));
        ASSERT_FALSE(dns_type_is_pseudo(DNS_TYPE_A));
        ASSERT_FALSE(dns_type_is_pseudo(DNS_TYPE_AAAA));
}

TEST(dns_type_is_dnssec) {
        ASSERT_TRUE(dns_type_is_dnssec(DNS_TYPE_DNSKEY));
        ASSERT_TRUE(dns_type_is_dnssec(DNS_TYPE_RRSIG));
        ASSERT_TRUE(dns_type_is_dnssec(DNS_TYPE_DS));
        ASSERT_FALSE(dns_type_is_dnssec(DNS_TYPE_A));
}

TEST(dns_type_is_obsolete) {
        ASSERT_TRUE(dns_type_is_obsolete(DNS_TYPE_MD));
        ASSERT_TRUE(dns_type_is_obsolete(DNS_TYPE_MAILA));
        ASSERT_TRUE(dns_type_is_obsolete(DNS_TYPE_MB));
        ASSERT_FALSE(dns_type_is_obsolete(DNS_TYPE_A));
}

TEST(dns_type_may_wildcard) {
        ASSERT_TRUE(dns_type_may_wildcard(DNS_TYPE_A));
        ASSERT_TRUE(dns_type_may_wildcard(DNS_TYPE_AAAA));
        ASSERT_FALSE(dns_type_may_wildcard(DNS_TYPE_SOA));
}

TEST(dns_type_to_af) {
        ASSERT_EQ(dns_type_to_af(DNS_TYPE_A), AF_INET);
        ASSERT_EQ(dns_type_to_af(DNS_TYPE_AAAA), AF_INET6);
        ASSERT_LT(dns_type_to_af(DNS_TYPE_SOA), 0);
}

TEST(dns_class) {
        ASSERT_TRUE(dns_class_is_valid_rr(DNS_CLASS_IN));
        ASSERT_TRUE(dns_class_is_valid_rr(0)); /* any class != ANY is valid */
        ASSERT_FALSE(dns_class_is_valid_rr(DNS_CLASS_ANY));
        ASSERT_TRUE(dns_class_is_pseudo(DNS_CLASS_ANY));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
