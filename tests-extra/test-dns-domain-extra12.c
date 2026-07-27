/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "dns-def.h"
#include "dns-domain.h"
#include "tests.h"

TEST(dns_service_name_is_valid) {
        /* Valid service names */
        assert_se(dns_service_name_is_valid("My Printer"));
        assert_se(dns_service_name_is_valid("webserver"));
        assert_se(dns_service_name_is_valid("a"));

        /* Invalid: NULL */
        assert_se(!dns_service_name_is_valid(NULL));

        /* Invalid: empty */
        assert_se(!dns_service_name_is_valid(""));

        /* Invalid: too long label */
        char long_name[DNS_LABEL_MAX + 2];
        memset(long_name, 'a', DNS_LABEL_MAX + 1);
        long_name[DNS_LABEL_MAX + 1] = '\0';
        assert_se(!dns_service_name_is_valid(long_name));
}

TEST(dnssd_srv_type_is_valid) {
        /* Valid DNS-SD service types: _service._tcp or _service._udp */
        assert_se(dnssd_srv_type_is_valid("_http._tcp"));
        assert_se(dnssd_srv_type_is_valid("_sip._udp"));
        assert_se(dnssd_srv_type_is_valid("_printer._tcp"));

        /* Missing leading underscore */
        assert_se(!dnssd_srv_type_is_valid("http._tcp"));

        /* Wrong protocol suffix */
        assert_se(!dnssd_srv_type_is_valid("_http._sctp"));

        /* NULL */
        assert_se(!dnssd_srv_type_is_valid(NULL));

        /* Empty */
        assert_se(!dnssd_srv_type_is_valid(""));

        /* Only _tcp */
        assert_se(!dnssd_srv_type_is_valid("_tcp"));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
