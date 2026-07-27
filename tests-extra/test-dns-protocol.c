/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "dns-packet.h"
#include "tests.h"

TEST(dns_protocol_to_string) {
        ASSERT_STREQ(dns_protocol_to_string(DNS_PROTOCOL_DNS), "dns");
        ASSERT_STREQ(dns_protocol_to_string(DNS_PROTOCOL_MDNS), "mdns");
        ASSERT_STREQ(dns_protocol_to_string(DNS_PROTOCOL_LLMNR), "llmnr");
}

TEST(dns_protocol_from_string) {
        ASSERT_EQ(dns_protocol_from_string("dns"), DNS_PROTOCOL_DNS);
        ASSERT_EQ(dns_protocol_from_string("mdns"), DNS_PROTOCOL_MDNS);
        ASSERT_EQ(dns_protocol_from_string("llmnr"), DNS_PROTOCOL_LLMNR);
        ASSERT_EQ(dns_protocol_from_string("invalid"), _DNS_PROTOCOL_INVALID);
}

TEST(dns_rcode_to_string) {
        ASSERT_STREQ(dns_rcode_to_string(DNS_RCODE_SUCCESS), "SUCCESS");
        ASSERT_STREQ(dns_rcode_to_string(DNS_RCODE_FORMERR), "FORMERR");
        ASSERT_STREQ(dns_rcode_to_string(DNS_RCODE_SERVFAIL), "SERVFAIL");
        ASSERT_STREQ(dns_rcode_to_string(DNS_RCODE_NXDOMAIN), "NXDOMAIN");
        ASSERT_STREQ(dns_rcode_to_string(DNS_RCODE_REFUSED), "REFUSED");
}

TEST(dns_rcode_from_string) {
        ASSERT_EQ(dns_rcode_from_string("SUCCESS"), DNS_RCODE_SUCCESS);
        ASSERT_EQ(dns_rcode_from_string("NXDOMAIN"), DNS_RCODE_NXDOMAIN);
        ASSERT_EQ(dns_rcode_from_string("REFUSED"), DNS_RCODE_REFUSED);
        ASSERT_EQ(dns_rcode_from_string("invalid"), _DNS_RCODE_INVALID);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
