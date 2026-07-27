/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "dns-question.h"
#include "dns-type.h"
#include "tests.h"

TEST(dns_question_new_free) {
        _cleanup_(dns_question_unrefp) DnsQuestion *q = NULL;

        q = dns_question_new(5);
        assert_se(q);
        assert_se(dns_question_size(q) == 0);
        assert_se(dns_question_isempty(q));
        assert_se(dns_question_first_key(q) == NULL);
        assert_se(dns_question_first_name(q) == NULL);
}

TEST(dns_question_new_zero) {
        _cleanup_(dns_question_unrefp) DnsQuestion *q = NULL;

        q = dns_question_new(0);
        assert_se(q);
        assert_se(dns_question_size(q) == 0);
        assert_se(dns_question_isempty(q));
}

TEST(dns_question_add_raw) {
        _cleanup_(dns_question_unrefp) DnsQuestion *q = NULL;
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key1 = NULL, *key2 = NULL;
        int r;

        q = dns_question_new(2);
        assert_se(q);

        key1 = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "example.com");
        assert_se(key1);

        r = dns_question_add_raw(q, key1, 0);
        assert_se(r >= 0);
        assert_se(dns_question_size(q) == 1);
        assert_se(!dns_question_isempty(q));

        key2 = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_AAAA, "example.com");
        assert_se(key2);

        r = dns_question_add_raw(q, key2, 0);
        assert_se(r >= 0);
        assert_se(dns_question_size(q) == 2);

        /* Adding to a full question should fail */
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key3 = NULL;
        key3 = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_TXT, "example.com");
        assert_se(key3);

        r = dns_question_add_raw(q, key3, 0);
        assert_se(r == -ENOSPC);
        assert_se(dns_question_size(q) == 2);
}

TEST(dns_question_add_dedup) {
        _cleanup_(dns_question_unrefp) DnsQuestion *q = NULL;
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key1 = NULL, *key1_dup = NULL;
        int r;

        q = dns_question_new(5);
        assert_se(q);

        key1 = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "example.com");
        assert_se(key1);

        r = dns_question_add(q, key1, 0);
        assert_se(r >= 0);
        assert_se(dns_question_size(q) == 1);

        /* Adding the same key with the same flags should be a no-op */
        key1_dup = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "example.com");
        assert_se(key1_dup);

        r = dns_question_add(q, key1_dup, 0);
        assert_se(r >= 0);
        assert_se(dns_question_size(q) == 1); /* still 1, dedup */

        /* Adding same key but different flags should add */
        r = dns_question_add(q, key1_dup, DNS_QUESTION_WANTS_UNICAST_REPLY);
        assert_se(r >= 0);
        assert_se(dns_question_size(q) == 2);
}

TEST(dns_question_first_key_first_name) {
        _cleanup_(dns_question_unrefp) DnsQuestion *q = NULL;
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key1 = NULL;

        q = dns_question_new(2);
        assert_se(q);

        /* Empty question */
        assert_se(dns_question_first_key(q) == NULL);
        assert_se(dns_question_first_name(q) == NULL);

        key1 = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "example.com");
        assert_se(key1);

        assert_se(dns_question_add_raw(q, key1, 0) >= 0);
        assert_se(dns_question_first_key(q) == key1);
        assert_se(streq(dns_question_first_name(q), "example.com"));
}

TEST(dns_question_is_valid_for_query) {
        _cleanup_(dns_question_unrefp) DnsQuestion *q = NULL;
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key1 = NULL, *key2 = NULL;
        int r;

        /* NULL is not valid */
        assert_se(dns_question_is_valid_for_query(NULL) == 0);

        /* Empty is not valid */
        q = dns_question_new(2);
        assert_se(q);
        assert_se(dns_question_is_valid_for_query(q) == 0);

        /* Single key is valid */
        key1 = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "example.com");
        assert_se(key1);
        assert_se(dns_question_add_raw(q, key1, 0) >= 0);
        r = dns_question_is_valid_for_query(q);
        assert_se(r >= 0 || r == 1);

        /* Two keys with same name is valid */
        key2 = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_AAAA, "example.com");
        assert_se(key2);
        assert_se(dns_question_add_raw(q, key2, 0) >= 0);
        r = dns_question_is_valid_for_query(q);
        assert_se(r >= 0 || r == 1);
}

TEST(dns_question_contains_key) {
        _cleanup_(dns_question_unrefp) DnsQuestion *q = NULL;
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key1 = NULL, *key_other = NULL;
        int r;

        q = dns_question_new(2);
        assert_se(q);

        key1 = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "example.com");
        assert_se(key1);
        assert_se(dns_question_add_raw(q, key1, 0) >= 0);

        /* Contains matching key */
        r = dns_question_contains_key(q, key1);
        assert_se(r > 0);

        /* Does not contain different key */
        key_other = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_AAAA, "example.com");
        assert_se(key_other);
        r = dns_question_contains_key(q, key_other);
        assert_se(r == 0);

        /* NULL question returns 0 */
        r = dns_question_contains_key(NULL, key1);
        assert_se(r == 0);
}

TEST(dns_question_is_equal) {
        _cleanup_(dns_question_unrefp) DnsQuestion *q1 = NULL, *q2 = NULL;
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key1 = NULL;

        /* Both NULL */
        assert_se(dns_question_is_equal(NULL, NULL) == 1);

        /* NULL vs empty */
        q1 = dns_question_new(1);
        assert_se(q1);
        assert_se(dns_question_is_equal(NULL, q1) == 1);
        assert_se(dns_question_is_equal(q1, NULL) == 1);

        /* Same object */
        assert_se(dns_question_is_equal(q1, q1) == 1);

        /* Same content */
        q2 = dns_question_new(1);
        assert_se(q2);
        assert_se(dns_question_is_equal(q1, q2) == 1);

        key1 = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "example.com");
        assert_se(key1);
        assert_se(dns_question_add_raw(q1, key1, 0) >= 0);
        assert_se(dns_question_is_equal(q1, q2) == 0);
}

TEST(dns_question_merge) {
        _cleanup_(dns_question_unrefp) DnsQuestion *q1 = NULL, *q2 = NULL, *merged = NULL;
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key1 = NULL, *key2 = NULL;
        int r;

        /* Merge two empty questions */
        q1 = dns_question_new(1);
        q2 = dns_question_new(1);
        assert_se(q1 && q2);

        r = dns_question_merge(q1, q2, &merged);
        assert_se(r >= 0);
        assert_se(dns_question_size(merged) == 0);
        merged = dns_question_unref(merged);

        /* Merge empty with non-empty */
        key1 = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "example.com");
        assert_se(key1);
        assert_se(dns_question_add_raw(q1, key1, 0) >= 0);

        r = dns_question_merge(q1, q2, &merged);
        assert_se(r >= 0);
        assert_se(dns_question_size(merged) == 1);
        merged = dns_question_unref(merged);

        /* Merge two non-empty */
        key2 = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_AAAA, "example.com");
        assert_se(key2);
        assert_se(dns_question_add_raw(q2, key2, 0) >= 0);

        r = dns_question_merge(q1, q2, &merged);
        assert_se(r >= 0);
        assert_se(dns_question_size(merged) == 2);
}

TEST(dns_question_matches_rr) {
        _cleanup_(dns_question_unrefp) DnsQuestion *q = NULL;
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL;
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL;
        int r;

        q = dns_question_new(1);
        assert_se(q);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "example.com");
        assert_se(key);
        assert_se(dns_question_add_raw(q, key, 0) >= 0);

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "example.com");
        assert_se(rr);
        rr->a.in_addr.s_addr = htobe32(INADDR_LOOPBACK);

        /* Matching RR */
        r = dns_question_matches_rr(q, rr, NULL);
        assert_se(r > 0);

        /* NULL question returns 0 */
        r = dns_question_matches_rr(NULL, rr, NULL);
        assert_se(r == 0);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
