/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "dns-type.h"
#include "dns-rr.h"
#include "string-util.h"
#include "tests.h"

TEST(dns_resource_key_is_dnssd_ptr) {
        DnsResourceKey key;

        /* PTR under _tcp.local → true */
        key = (DnsResourceKey) { .n_ref = UINT_MAX, .class = DNS_CLASS_IN, .type = DNS_TYPE_PTR, ._name = (char*) "_http._tcp.local" };
        assert_se(dns_resource_key_is_dnssd_ptr(&key));

        /* PTR under _udp.local → true */
        key._name = (char*) "_ntp._udp.local";
        assert_se(dns_resource_key_is_dnssd_ptr(&key));

        /* Non-PTR type → false */
        key.type = DNS_TYPE_A;
        assert_se(!dns_resource_key_is_dnssd_ptr(&key));

        /* PTR but not under _tcp.local or _udp.local → false */
        key.type = DNS_TYPE_PTR;
        key._name = (char*) "example.com";
        assert_se(!dns_resource_key_is_dnssd_ptr(&key));
}

TEST(dns_resource_key_is_dnssd_two_label_ptr) {
        DnsResourceKey key;

        /* Two-label PTR under _tcp.local → true */
        key = (DnsResourceKey) { .n_ref = UINT_MAX, .class = DNS_CLASS_IN, .type = DNS_TYPE_PTR, ._name = (char*) "_http._tcp.local" };
        assert_se(dns_resource_key_is_dnssd_two_label_ptr(&key));

        /* Two-label PTR under _udp.local → true */
        key._name = (char*) "_ntp._udp.local";
        assert_se(dns_resource_key_is_dnssd_two_label_ptr(&key));

        /* Three-label → false (parent of _http._tcp.local is _tcp.local, not just _tcp) */
        key._name = (char*) "_sub._http._tcp.local";
        assert_se(!dns_resource_key_is_dnssd_two_label_ptr(&key));

        /* Non-PTR → false */
        key.type = DNS_TYPE_A;
        key._name = (char*) "_http._tcp.local";
        assert_se(!dns_resource_key_is_dnssd_two_label_ptr(&key));
}

TEST(dns_resource_key_match_soa) {
        DnsResourceKey key, soa;

        /* Exact match */
        key = (DnsResourceKey) { .n_ref = UINT_MAX, .class = DNS_CLASS_IN, .type = DNS_TYPE_SOA, ._name = (char*) "example.com" };
        soa = (DnsResourceKey) { .n_ref = UINT_MAX, .class = DNS_CLASS_IN, .type = DNS_TYPE_SOA, ._name = (char*) "example.com" };
        assert_se(dns_resource_key_match_soa(&key, &soa) > 0);

        /* Subdomain match */
        key._name = (char*) "sub.example.com";
        assert_se(dns_resource_key_match_soa(&key, &soa) > 0);

        /* No match */
        key._name = (char*) "other.com";
        assert_se(dns_resource_key_match_soa(&key, &soa) == 0);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
