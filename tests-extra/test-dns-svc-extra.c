/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "dns-packet.h"
#include "tests.h"

TEST(dns_svc_param_key_to_string) {
        ASSERT_STREQ(dns_svc_param_key_to_string(DNS_SVC_PARAM_KEY_MANDATORY), "mandatory");
        ASSERT_STREQ(dns_svc_param_key_to_string(DNS_SVC_PARAM_KEY_ALPN), "alpn");
        ASSERT_STREQ(dns_svc_param_key_to_string(DNS_SVC_PARAM_KEY_PORT), "port");
        ASSERT_STREQ(dns_svc_param_key_to_string(DNS_SVC_PARAM_KEY_IPV4HINT), "ipv4hint");
        ASSERT_STREQ(dns_svc_param_key_to_string(DNS_SVC_PARAM_KEY_IPV6HINT), "ipv6hint");
        ASSERT_STREQ(dns_svc_param_key_to_string(DNS_SVC_PARAM_KEY_ECH), "ech");
}

TEST(dns_ede_rcode_to_string) {
        ASSERT_STREQ(dns_ede_rcode_to_string(DNS_EDE_RCODE_OTHER), "Other");
        ASSERT_STREQ(dns_ede_rcode_to_string(DNS_EDE_RCODE_STALE_ANSWER), "Stale Answer");
        ASSERT_STREQ(dns_ede_rcode_to_string(DNS_EDE_RCODE_FORGED_ANSWER), "Forged Answer");
        ASSERT_STREQ(dns_ede_rcode_to_string(DNS_EDE_RCODE_CACHED_ERROR), "Cached Error");
}

DEFINE_TEST_MAIN(LOG_DEBUG);
