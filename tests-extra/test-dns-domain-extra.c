/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "dns-domain.h"
#include "tests.h"

TEST(dns_name_is_root) {
        ASSERT_TRUE(dns_name_is_root("."));
        ASSERT_TRUE(dns_name_is_root(""));
        ASSERT_FALSE(dns_name_is_root("example.com"));
        ASSERT_FALSE(dns_name_is_root("example.com."));
}

TEST(dns_name_equal) {
        /* Simple comparison */
        ASSERT_TRUE(dns_name_equal("example.com", "example.com"));
        ASSERT_TRUE(dns_name_equal("Example.Com.", "example.com."));
        ASSERT_FALSE(dns_name_equal("example.com", "example.org"));
}

TEST(dns_name_endswith) {
        /* dns_name_endswith checks if name ends with suffix */
        ASSERT_TRUE(dns_name_endswith("www.example.com", "example.com"));
        ASSERT_TRUE(dns_name_endswith("www.example.com.", "example.com."));
        ASSERT_FALSE(dns_name_endswith("example.com", "example.org"));
        ASSERT_FALSE(dns_name_endswith("example.com.", "notexample.com."));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
