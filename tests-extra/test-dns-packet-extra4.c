/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "dns-packet.h"
#include "string-util.h"
#include "tests.h"

TEST(dns_rcode_to_from_string) {
        /* to_string */
        assert_se(streq(dns_rcode_to_string(DNS_RCODE_SUCCESS), "SUCCESS"));
        assert_se(streq(dns_rcode_to_string(DNS_RCODE_FORMERR), "FORMERR"));
        assert_se(streq(dns_rcode_to_string(DNS_RCODE_SERVFAIL), "SERVFAIL"));
        assert_se(streq(dns_rcode_to_string(DNS_RCODE_NXDOMAIN), "NXDOMAIN"));
        assert_se(streq(dns_rcode_to_string(DNS_RCODE_REFUSED), "REFUSED"));

        /* from_string */
        assert_se(dns_rcode_from_string("SUCCESS") == DNS_RCODE_SUCCESS);
        assert_se(dns_rcode_from_string("SERVFAIL") == DNS_RCODE_SERVFAIL);
        assert_se(dns_rcode_from_string("NXDOMAIN") == DNS_RCODE_NXDOMAIN);

        /* Invalid */
        assert_se(dns_rcode_from_string("invalid") < 0);
}

TEST(dns_protocol_to_from_string) {
        /* to_string */
        assert_se(streq(dns_protocol_to_string(DNS_PROTOCOL_DNS), "dns"));
        assert_se(streq(dns_protocol_to_string(DNS_PROTOCOL_MDNS), "mdns"));
        assert_se(streq(dns_protocol_to_string(DNS_PROTOCOL_LLMNR), "llmnr"));

        /* from_string */
        assert_se(dns_protocol_from_string("dns") == DNS_PROTOCOL_DNS);
        assert_se(dns_protocol_from_string("mdns") == DNS_PROTOCOL_MDNS);
        assert_se(dns_protocol_from_string("llmnr") == DNS_PROTOCOL_LLMNR);

        /* Invalid */
        assert_se(dns_protocol_from_string("invalid") < 0);
}

TEST(dns_svc_param_key_to_string) {
        /* TO_STRING only — no from_string */
        assert_se(streq(dns_svc_param_key_to_string(DNS_SVC_PARAM_KEY_MANDATORY), "mandatory"));
        assert_se(streq(dns_svc_param_key_to_string(DNS_SVC_PARAM_KEY_ALPN), "alpn"));
        assert_se(streq(dns_svc_param_key_to_string(DNS_SVC_PARAM_KEY_PORT), "port"));
        assert_se(streq(dns_svc_param_key_to_string(DNS_SVC_PARAM_KEY_IPV4HINT), "ipv4hint"));
        assert_se(streq(dns_svc_param_key_to_string(DNS_SVC_PARAM_KEY_IPV6HINT), "ipv6hint"));
}

TEST(dns_ede_rcode_to_string) {
        /* TO_STRING only */
        assert_se(dns_ede_rcode_to_string(DNS_EDE_RCODE_OTHER) != NULL);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
