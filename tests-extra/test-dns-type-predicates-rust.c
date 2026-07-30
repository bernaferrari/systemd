/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* RUST-CONTRACT: dns-type-predicates */
/* RUST-CONTRACT: dns-type-address-family */
/* RUST-CONTRACT: tlsa-name-rendering */

#include <stdint.h>

#include "dns-type.h"
#include "string-util.h"
#include "tests.h"

#include "rust/dns_type_predicates.h"

TEST(dns_type_predicates_exhaustive) {
        for (uint32_t value = 0; value <= UINT16_MAX; value++) {
                uint16_t type = (uint16_t) value;

                assert_se(dns_type_is_pseudo(type) == rs_dns_type_is_pseudo(type));
                assert_se(dns_class_is_pseudo(type) == rs_dns_class_is_pseudo(type));
                assert_se(dns_type_is_valid_query(type) == rs_dns_type_is_valid_query(type));
                assert_se(dns_type_is_zone_transfer(type) == rs_dns_type_is_zone_transfer(type));
                assert_se(dns_type_is_valid_rr(type) == rs_dns_type_is_valid_rr(type));
                assert_se(dns_class_is_valid_rr(type) == rs_dns_class_is_valid_rr(type));
                assert_se(dns_type_may_redirect(type) == rs_dns_type_may_redirect(type));
                assert_se(dns_type_may_wildcard(type) == rs_dns_type_may_wildcard(type));
                assert_se(dns_type_apex_only(type) == rs_dns_type_apex_only(type));
                assert_se(dns_type_is_dnssec(type) == rs_dns_type_is_dnssec(type));
                assert_se(dns_type_is_obsolete(type) == rs_dns_type_is_obsolete(type));
                assert_se(dns_type_needs_authentication(type) == rs_dns_type_needs_authentication(type));
                assert_se(dns_type_to_af(type) == rs_dns_type_to_af(type));
        }
}

TEST(tlsa_strings_exhaustive) {
        for (uint16_t value = 0; value <= UINT8_MAX; value++) {
                uint8_t selector = (uint8_t) value;
                const char *cert_usage, *matching_type, *selector_name;

                cert_usage = rs_tlsa_cert_usage_to_string(selector);
                selector_name = rs_tlsa_selector_to_string(selector);
                matching_type = rs_tlsa_matching_type_to_string(selector);

                assert_se(streq_ptr(tlsa_cert_usage_to_string(selector), cert_usage));
                assert_se(streq_ptr(tlsa_selector_to_string(selector), selector_name));
                assert_se(streq_ptr(tlsa_matching_type_to_string(selector), matching_type));

                /* The Rust facade returns borrowed static storage, not an allocation. */
                assert_se(cert_usage == rs_tlsa_cert_usage_to_string(selector));
                assert_se(selector_name == rs_tlsa_selector_to_string(selector));
                assert_se(matching_type == rs_tlsa_matching_type_to_string(selector));
        }
}

DEFINE_TEST_MAIN(LOG_INFO);
