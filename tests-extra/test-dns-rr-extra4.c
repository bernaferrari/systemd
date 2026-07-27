/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "dns-type.h"
#include "dns-rr.h"
#include "string-util.h"
#include "tests.h"

TEST(dns_resource_key_is_address) {
        DnsResourceKey key;

        /* A record is address */
        key = (DnsResourceKey) { .n_ref = UINT_MAX, .class = DNS_CLASS_IN, .type = DNS_TYPE_A, ._name = (char*) "example.com" };
        assert_se(dns_resource_key_is_address(&key));

        /* AAAA record is address */
        key.type = DNS_TYPE_AAAA;
        assert_se(dns_resource_key_is_address(&key));

        /* CNAME is NOT address */
        key.type = DNS_TYPE_CNAME;
        assert_se(!dns_resource_key_is_address(&key));

        /* MX is NOT address */
        key.type = DNS_TYPE_MX;
        assert_se(!dns_resource_key_is_address(&key));

        /* Non-IN class is NOT address */
        key.type = DNS_TYPE_A;
        key.class = DNS_CLASS_ANY;
        assert_se(!dns_resource_key_is_address(&key));
}

TEST(dns_resource_key_equal) {
        DnsResourceKey a, b;

        /* Same keys → equal */
        a = (DnsResourceKey) { .n_ref = UINT_MAX, .class = DNS_CLASS_IN, .type = DNS_TYPE_A, ._name = (char*) "example.com" };
        b = (DnsResourceKey) { .n_ref = UINT_MAX, .class = DNS_CLASS_IN, .type = DNS_TYPE_A, ._name = (char*) "example.com" };
        assert_se(dns_resource_key_equal(&a, &b) == 1);

        /* Same pointer → equal */
        assert_se(dns_resource_key_equal(&a, &a) == 1);

        /* Different type → not equal */
        b.type = DNS_TYPE_AAAA;
        assert_se(dns_resource_key_equal(&a, &b) == 0);

        /* Different class → not equal */
        b.type = DNS_TYPE_A;
        b.class = DNS_CLASS_ANY;
        assert_se(dns_resource_key_equal(&a, &b) == 0);

        /* Different name → not equal */
        b.class = DNS_CLASS_IN;
        b._name = (char*) "other.com";
        assert_se(dns_resource_key_equal(&a, &b) == 0);

        /* Case insensitive comparison */
        b._name = (char*) "EXAMPLE.COM";
        assert_se(dns_resource_key_equal(&a, &b) == 1);
}

TEST(dns_resource_key_to_string) {
        DnsResourceKey key;
        char buf[DNS_RESOURCE_KEY_STRING_MAX];

        key = (DnsResourceKey) { .n_ref = UINT_MAX, .class = DNS_CLASS_IN, .type = DNS_TYPE_A, ._name = (char*) "example.com" };
        char *s = dns_resource_key_to_string(&key, buf, sizeof(buf));
        assert_se(s != NULL);
        assert_se(strstr(s, "example.com") != NULL);

        /* AAAA type */
        key.type = DNS_TYPE_AAAA;
        s = dns_resource_key_to_string(&key, buf, sizeof(buf));
        assert_se(s != NULL);
        assert_se(strstr(s, "example.com") != NULL);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
