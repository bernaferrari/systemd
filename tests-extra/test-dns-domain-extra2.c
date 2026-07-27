/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "dns-domain.h"
#include "tests.h"

TEST(dns_name_is_root) {
        ASSERT_TRUE(dns_name_is_root(""));
        ASSERT_TRUE(dns_name_is_root("."));
        ASSERT_FALSE(dns_name_is_root("example.com"));
        ASSERT_FALSE(dns_name_is_root("localhost"));
}

TEST(dns_name_is_single_label) {
        ASSERT_TRUE(dns_name_is_single_label("localhost"));
        ASSERT_TRUE(dns_name_is_single_label("foo"));
        ASSERT_FALSE(dns_name_is_single_label("example.com"));
        ASSERT_FALSE(dns_name_is_single_label(""));
        ASSERT_FALSE(dns_name_is_single_label("."));
}

TEST(dns_name_equal) {
        ASSERT_TRUE(dns_name_equal("example.com", "example.com"));
        ASSERT_TRUE(dns_name_equal("Example.Com", "example.com")); /* case-insensitive */
        ASSERT_FALSE(dns_name_equal("example.com", "example.org"));
        ASSERT_TRUE(dns_name_equal("", "")); /* root equals root */
}

TEST(dns_name_endswith) {
        ASSERT_TRUE(dns_name_endswith("www.example.com", "example.com"));
        ASSERT_TRUE(dns_name_endswith("example.com", "example.com"));
        ASSERT_FALSE(dns_name_endswith("example.com", "www.example.com"));
        ASSERT_TRUE(dns_name_endswith("example.com", ""));
        ASSERT_TRUE(dns_name_endswith("", ""));
        ASSERT_FALSE(dns_name_endswith("example.com", "notexample.com"));
}

TEST(dns_name_startswith) {
        ASSERT_TRUE(dns_name_startswith("www.example.com", "www"));
        ASSERT_TRUE(dns_name_startswith("www.example.com", "www.example"));
        ASSERT_FALSE(dns_name_startswith("example.com", "www"));
}

TEST(dns_name_count_labels) {
        ASSERT_EQ(dns_name_count_labels(""), 0);
        ASSERT_EQ(dns_name_count_labels("localhost"), 1);
        ASSERT_EQ(dns_name_count_labels("example.com"), 2);
        ASSERT_EQ(dns_name_count_labels("www.example.com"), 3);
}

TEST(dns_srv_type_is_valid) {
        ASSERT_TRUE(dns_srv_type_is_valid("_http._tcp"));
        ASSERT_TRUE(dns_srv_type_is_valid("_ldap._tcp"));
        ASSERT_FALSE(dns_srv_type_is_valid("http._tcp"));  /* missing leading _ */
        ASSERT_FALSE(dns_srv_type_is_valid(""));
        ASSERT_FALSE(dns_srv_type_is_valid("_http"));       /* only one label */
}

TEST(dnssd_srv_type_is_valid) {
        ASSERT_TRUE(dnssd_srv_type_is_valid("_http._tcp"));
        ASSERT_TRUE(dnssd_srv_type_is_valid("_ldap._tcp"));
        ASSERT_FALSE(dnssd_srv_type_is_valid("http._tcp"));
        ASSERT_FALSE(dnssd_srv_type_is_valid(""));
}

TEST(dns_service_name_is_valid) {
        ASSERT_TRUE(dns_service_name_is_valid("My Service"));
        ASSERT_FALSE(dns_service_name_is_valid(""));
}

TEST(dns_name_compare_func) {
        /* DNS names are case-insensitive */
        ASSERT_EQ(dns_name_compare_func("EXAMPLE.COM", "example.com"), 0);
        ASSERT_LT(dns_name_compare_func("a.example.com", "b.example.com"), 0);
        ASSERT_GT(dns_name_compare_func("b.example.com", "a.example.com"), 0);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
