/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "dns-packet.h"
#include "string-util.h"
#include "tests.h"

TEST(dns_ede_rcode_to_string_values) {
        assert_se(streq(dns_ede_rcode_to_string(DNS_EDE_RCODE_OTHER), "Other"));
        assert_se(streq(dns_ede_rcode_to_string(DNS_EDE_RCODE_UNSUPPORTED_DNSKEY_ALG), "Unsupported DNSKEY Algorithm"));
        assert_se(streq(dns_ede_rcode_to_string(DNS_EDE_RCODE_UNSUPPORTED_DS_DIGEST), "Unsupported DS Digest Type"));
        assert_se(streq(dns_ede_rcode_to_string(DNS_EDE_RCODE_STALE_ANSWER), "Stale Answer"));
        assert_se(streq(dns_ede_rcode_to_string(DNS_EDE_RCODE_FORGED_ANSWER), "Forged Answer"));
        assert_se(streq(dns_ede_rcode_to_string(DNS_EDE_RCODE_BLOCKED), "Blocked"));
        assert_se(streq(dns_ede_rcode_to_string(DNS_EDE_RCODE_SYNTHESIZED), "Synthesized"));
        assert_se(dns_ede_rcode_to_string(9999) == NULL);
}

TEST(format_dns_ede_rcode) {
        char buf[DECIMAL_STR_MAX(int)];
        /* Known → name */
        assert_se(streq(format_dns_ede_rcode(DNS_EDE_RCODE_OTHER, buf), "Other"));
        /* Unknown → numeric string */
        assert_se(streq(format_dns_ede_rcode(9999, buf), "9999"));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
