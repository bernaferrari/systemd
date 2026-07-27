/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "dns-domain.h"
#include "tests.h"

TEST(dns_service_join_split) {
        _cleanup_free_ char *joined = NULL;
        _cleanup_free_ char *ret_name = NULL, *ret_type = NULL, *ret_domain = NULL;

        /* Basic join */
        assert_se(dns_service_join("myname", "_http._tcp", "example.com", &joined) == 0);
        assert_se(joined);

        /* Split it back */
        assert_se(dns_service_split(joined, &ret_name, &ret_type, &ret_domain) == 0);
        assert_se(streq(ret_name, "myname"));
        assert_se(streq(ret_type, "_http._tcp"));
        assert_se(streq(ret_domain, "example.com"));

        /* NULL name */
        free(joined);
        joined = NULL;
        assert_se(dns_service_join(NULL, "_http._tcp", "example.com", &joined) == 0);
        assert_se(joined);
}

TEST(dns_srv_type_is_valid) {
        assert_se(dns_srv_type_is_valid("_http._tcp"));
        assert_se(dns_srv_type_is_valid("_sip._udp"));
        assert_se(!dns_srv_type_is_valid("http._tcp"));   /* missing leading _ */
        assert_se(!dns_srv_type_is_valid("_http.tcp"));    /* protocol must start with _ */
        assert_se(!dns_srv_type_is_valid(NULL));
        assert_se(!dns_srv_type_is_valid(""));
}

TEST(dns_service_name_is_valid) {
        assert_se(dns_service_name_is_valid("My Service"));
        assert_se(dns_service_name_is_valid("test"));
        assert_se(!dns_service_name_is_valid(NULL));
        assert_se(!dns_service_name_is_valid(""));
}

TEST(dnssd_srv_type_is_valid) {
        assert_se(dnssd_srv_type_is_valid("_http._tcp"));
        assert_se(!dnssd_srv_type_is_valid(NULL));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
