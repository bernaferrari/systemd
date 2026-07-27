/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "dns-packet.h"
#include "tests.h"

TEST(dns_rcode_to_from_string) {
        assert_se(streq(dns_rcode_to_string(DNS_RCODE_SUCCESS), "SUCCESS"));
        assert_se(streq(dns_rcode_to_string(DNS_RCODE_FORMERR), "FORMERR"));
        assert_se(streq(dns_rcode_to_string(DNS_RCODE_SERVFAIL), "SERVFAIL"));
        assert_se(streq(dns_rcode_to_string(DNS_RCODE_NXDOMAIN), "NXDOMAIN"));
        assert_se(streq(dns_rcode_to_string(DNS_RCODE_NOTIMP), "NOTIMP"));
        assert_se(streq(dns_rcode_to_string(DNS_RCODE_REFUSED), "REFUSED"));
        assert_se(streq(dns_rcode_to_string(DNS_RCODE_YXRRSET), "YRRSET"));
        assert_se(streq(dns_rcode_to_string(DNS_RCODE_BADVERS), "BADVERS"));
        assert_se(streq(dns_rcode_to_string(DNS_RCODE_BADCOOKIE), "BADCOOKIE"));

        assert_se(dns_rcode_from_string("SUCCESS") == DNS_RCODE_SUCCESS);
        assert_se(dns_rcode_from_string("SERVFAIL") == DNS_RCODE_SERVFAIL);
        assert_se(dns_rcode_from_string("NXDOMAIN") == DNS_RCODE_NXDOMAIN);
        assert_se(dns_rcode_from_string("REFUSED") == DNS_RCODE_REFUSED);
        assert_se(dns_rcode_from_string("BADCOOKIE") == DNS_RCODE_BADCOOKIE);
        assert_se(dns_rcode_from_string("invalid") < 0);
}

TEST(dns_protocol_to_from_string) {
        assert_se(streq(dns_protocol_to_string(DNS_PROTOCOL_DNS), "dns"));
        assert_se(streq(dns_protocol_to_string(DNS_PROTOCOL_MDNS), "mdns"));
        assert_se(streq(dns_protocol_to_string(DNS_PROTOCOL_LLMNR), "llmnr"));

        assert_se(dns_protocol_from_string("dns") == DNS_PROTOCOL_DNS);
        assert_se(dns_protocol_from_string("mdns") == DNS_PROTOCOL_MDNS);
        assert_se(dns_protocol_from_string("llmnr") == DNS_PROTOCOL_LLMNR);
        assert_se(dns_protocol_from_string("invalid") < 0);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
