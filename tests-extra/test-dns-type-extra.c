/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "dns-type.h"
#include "tests.h"

TEST(dns_type_is_valid) {
        /* Common DNS types */
        ASSERT_TRUE(dns_type_is_valid_query(DNS_TYPE_A));
        ASSERT_TRUE(dns_type_is_valid_query(DNS_TYPE_AAAA));
        ASSERT_TRUE(dns_type_is_valid_query(DNS_TYPE_CNAME));
        ASSERT_TRUE(dns_type_is_valid_query(DNS_TYPE_MX));
        ASSERT_TRUE(dns_type_is_valid_query(DNS_TYPE_TXT));
        ASSERT_TRUE(dns_type_is_valid_query(DNS_TYPE_SOA));
        ASSERT_TRUE(dns_type_is_valid_query(DNS_TYPE_NS));
        ASSERT_TRUE(dns_type_is_valid_query(DNS_TYPE_SRV));
        ASSERT_TRUE(dns_type_is_valid_query(DNS_TYPE_PTR));

        /* Invalid */
        ASSERT_FALSE(dns_type_is_valid_query(0));
        /* UINT16_MAX is actually valid (any private-use QTYPE) */
        ASSERT_TRUE(dns_type_is_valid_query(UINT16_MAX));
}

TEST(dns_type_is_valid_rr) {
        ASSERT_TRUE(dns_type_is_valid_rr(DNS_TYPE_A));
        ASSERT_TRUE(dns_type_is_valid_rr(DNS_TYPE_AAAA));

        /* 0 is actually valid as an RR type */
        ASSERT_TRUE(dns_type_is_valid_rr(0));
}

TEST(dns_type_to_from_string) {
        const char *s;

        s = dns_type_to_string(DNS_TYPE_A);
        ASSERT_NOT_NULL(s);
        ASSERT_STREQ(s, "A");

        s = dns_type_to_string(DNS_TYPE_AAAA);
        ASSERT_NOT_NULL(s);
        ASSERT_STREQ(s, "AAAA");

        s = dns_type_to_string(DNS_TYPE_CNAME);
        ASSERT_NOT_NULL(s);
        ASSERT_STREQ(s, "CNAME");

        /* Unknown type returns NULL */
        s = dns_type_to_string(65535);
        ASSERT_NULL(s);

        /* from_string returns value directly */
        int t = dns_type_from_string("A");
        ASSERT_GE(t, 0);
        ASSERT_EQ(t, DNS_TYPE_A);

        t = dns_type_from_string("MX");
        ASSERT_GE(t, 0);
        ASSERT_EQ(t, DNS_TYPE_MX);

        t = dns_type_from_string("INVALID_TYPE");
        ASSERT_LT(t, 0);
}

TEST(dns_class) {
        const char *s;

        s = dns_class_to_string(DNS_CLASS_IN);
        ASSERT_NOT_NULL(s);
        ASSERT_STREQ(s, "IN");

        /* from_string returns value directly */
        int c = dns_class_from_string("IN");
        ASSERT_GE(c, 0);
        ASSERT_EQ(c, (int)DNS_CLASS_IN);

        /* Invalid class */
        c = dns_class_from_string("INVALID");
        ASSERT_LT(c, 0);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
