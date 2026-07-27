/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "dns-domain.h"
#include "string-util.h"
#include "tests.h"

TEST(dns_name_dot_suffixed) {
        /* Trailing dot → true */
        assert_se(dns_name_dot_suffixed("example.com.") > 0);
        assert_se(dns_name_dot_suffixed("com.") > 0);
        assert_se(dns_name_dot_suffixed(".") > 0);

        /* No trailing dot → false */
        assert_se(dns_name_dot_suffixed("example.com") == 0);
        assert_se(dns_name_dot_suffixed("com") == 0);
        assert_se(dns_name_dot_suffixed("") == 0);
}

TEST(dns_name_is_root) {
        assert_se(dns_name_is_root(""));
        assert_se(dns_name_is_root("."));
        assert_se(!dns_name_is_root("example.com"));
        assert_se(!dns_name_is_root("com"));
}

TEST(dns_name_is_single_label) {
        assert_se(dns_name_is_single_label("localhost") == true);
        assert_se(dns_name_is_single_label("com") == true);
        assert_se(dns_name_is_single_label("a") == true);
        assert_se(dns_name_is_single_label("www.example.com") == false);
        assert_se(dns_name_is_single_label("") == false);
        assert_se(dns_name_is_single_label(".") == false);
}

TEST(dns_name_is_valid_or_address) {
        /* Valid DNS names */
        assert_se(dns_name_is_valid_or_address("example.com") > 0);
        assert_se(dns_name_is_valid_or_address("www.example.com") > 0);
        assert_se(dns_name_is_valid_or_address("localhost") > 0);

        /* Valid IP addresses */
        assert_se(dns_name_is_valid_or_address("127.0.0.1") > 0);
        assert_se(dns_name_is_valid_or_address("::1") > 0);
        assert_se(dns_name_is_valid_or_address("192.168.1.1") > 0);

        /* Empty string → invalid */
        assert_se(dns_name_is_valid_or_address("") == 0);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
