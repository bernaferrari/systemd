/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "dns-domain.h"
#include "tests.h"

TEST(dns_subtype_name_is_valid_basic) {
        assert_se(dns_subtype_name_is_valid("My Subtype"));
        assert_se(dns_subtype_name_is_valid("_sub"));
        assert_se(!dns_subtype_name_is_valid(NULL));
        assert_se(!dns_subtype_name_is_valid(""));
}

TEST(dns_name_is_valid_ldh_basic) {
        /* LDH = letters, digits, hyphens */
        assert_se(dns_name_is_valid_ldh("example"));
        assert_se(dns_name_is_valid_ldh("example.com"));
        assert_se(dns_name_is_valid_ldh("my-host"));
        assert_se(!dns_name_is_valid_ldh("_underscore"));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
