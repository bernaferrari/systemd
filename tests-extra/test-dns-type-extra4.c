/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "dns-type.h"
#include "string-util.h"
#include "tests.h"

TEST(tlsa_cert_usage_to_string) {
        assert_se(streq(tlsa_cert_usage_to_string(0), "CA constraint"));
        assert_se(streq(tlsa_cert_usage_to_string(1), "Service certificate constraint"));
        assert_se(streq(tlsa_cert_usage_to_string(2), "Trust anchor assertion"));
        assert_se(streq(tlsa_cert_usage_to_string(3), "Domain-issued certificate"));
        assert_se(streq(tlsa_cert_usage_to_string(100), "Unassigned"));
        assert_se(streq(tlsa_cert_usage_to_string(254), "Unassigned"));
        assert_se(streq(tlsa_cert_usage_to_string(255), "Private use"));
}

TEST(tlsa_selector_to_string) {
        assert_se(streq(tlsa_selector_to_string(0), "Full Certificate"));
        assert_se(streq(tlsa_selector_to_string(1), "SubjectPublicKeyInfo"));
        assert_se(streq(tlsa_selector_to_string(50), "Unassigned"));
        assert_se(streq(tlsa_selector_to_string(255), "Private use"));
}

TEST(tlsa_matching_type_to_string) {
        assert_se(streq(tlsa_matching_type_to_string(0), "No hash used"));
        assert_se(streq(tlsa_matching_type_to_string(1), "SHA-256"));
        assert_se(streq(tlsa_matching_type_to_string(2), "SHA-512"));
        assert_se(streq(tlsa_matching_type_to_string(100), "Unassigned"));
        assert_se(streq(tlsa_matching_type_to_string(255), "Private use"));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
