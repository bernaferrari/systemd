/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "dns-answer.h"
#include "dns-type.h"
#include "tests.h"

#include "alloc-util.h"

#include "dns-rr.h"

#include "ordered-set.h"

TEST(dns_answer_new_free) {
        _cleanup_(dns_answer_unrefp) DnsAnswer *a = NULL;

        a = dns_answer_new(5);
        assert_se(a);
        assert_se(dns_answer_size(a) == 0);
        assert_se(dns_answer_isempty(a));
        dns_answer_unref(a);
        a = NULL;
        assert_se(dns_answer_size(NULL) == 0);
        assert_se(dns_answer_isempty(NULL));
}

TEST(dns_answer_add) {
        _cleanup_(dns_answer_unrefp) DnsAnswer *a = NULL;
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL;
        int r;

        a = dns_answer_new(3);
        assert_se(a);
        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "example.com");
        assert_se(rr);
        r = dns_answer_add(a, rr, 0, 0, NULL);
        assert_se(r >= 0);
        assert_se(dns_answer_size(a) == 1);
        assert_se(!dns_answer_isempty(a));
}
TEST(dns_answer_add_duplicate) {
        _cleanup_(dns_answer_unrefp) DnsAnswer *a = NULL;
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr1 = NULL, *rr2 = NULL;
        int r;

        a = dns_answer_new(2);
        assert_se(a);
        rr1 = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "example.com");
        assert_se(rr1);
        rr1->ttl = 100;
        r = dns_answer_add(a, rr1, 0, 0, NULL);
        assert_se(r >= 0);
        assert_se(dns_answer_size(a) == 1);
        /* Adding same key again should return 0 (already exists) */
        r = dns_answer_add(a, rr1, 0, 0, NULL);
        assert_se(r >= 0);
        /* Size should not double */
        assert_se(dns_answer_size(a) == 1);
        /* Now add same key but with lower TTL, should keep existing (higher) */
        rr2 = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "example.com");
        assert_se(rr2);
        rr2->ttl = 50;
        r = dns_answer_add(a, rr2, 0, 0, NULL);
        assert_se(r >= 0);
        /* Higher TTL replaces existing */
        assert_se(dns_answer_size(a) == 1);
}
TEST(dns_answer_add_extend_full) {
        _cleanup_(dns_answer_unrefp) DnsAnswer *a = NULL;
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL;
        int r;

        r = dns_answer_add_extend(&a, rr, 0, 0, NULL);
        assert_se(r >= 0);
        assert_se(a);
        assert_se(dns_answer_size(a) == 1);
}
TEST(dns_answer_contains) {
        _cleanup_(dns_answer_unrefp) DnsAnswer *a = NULL;
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr1 = NULL, *rr2 = NULL;
        bool found;
        a = dns_answer_new(1);
        assert_se(a);
        rr1 = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "example.com");
        assert_se(rr1);
        dns_answer_add(a, rr1, 0, 0, NULL);
        rr2 = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "other.com");
        assert_se(rr2);
        dns_answer_add(a, rr2, 0, 0, NULL);
        found = dns_answer_contains(a, rr1);
        assert_se(found);
        found = dns_answer_contains(a, rr2);
        assert_se(found);
        /* Not present */
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr3 = NULL;
        rr3 = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "absent.com");
        assert_se(rr3);
        found = dns_answer_contains(a, rr3);
        assert_se(!found);
}
TEST(dns_answer_match_key) {
        _cleanup_(dns_answer_unrefp) DnsAnswer *a = NULL;
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL;
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL;
        DnsAnswerFlags flags = 0;
        int r;
        a = dns_answer_new(1);
        assert_se(a);
        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "example.com");
        assert_se(rr);
        dns_answer_add(a, rr, 0, DNS_ANSWER_AUTHENTICATED, NULL);
        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "example.com");
        assert_se(key);
        r = dns_answer_match_key(a, key, &flags);
        assert_se(r > 0);
        assert_se(flags & DNS_ANSWER_AUTHENTICATED);
        /* Non-matching key */
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key2 = NULL;
        key2 = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_AAAA, "example.com");
        assert_se(key2);
        r = dns_answer_match_key(a, key2, NULL);
        assert_se(r == 0);
        /* NULL answer */
        r = dns_answer_match_key(NULL, key, NULL);
        assert_se(r == 0);
}
TEST(dns_answer_contains_nsec) {
        _cleanup_(dns_answer_unrefp) DnsAnswer *a = NULL;
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL;
        a = dns_answer_new(1);
        assert_se(a);
        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "example.com");
        assert_se(rr);
        dns_answer_add(a, rr, 0, 0, NULL);
        assert_se(!dns_answer_contains_nsec_or_nsec3(a));
}
TEST(dns_answer_merge) {
        _cleanup_(dns_answer_unrefp) DnsAnswer *a = NULL, *b = NULL, *c = NULL;
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr1 = NULL, *rr2 = NULL;
        int r;
        a = dns_answer_new(1);
        assert_se(a);
        b = dns_answer_new(1);
        assert_se(b);
        rr1 = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "a.com");
        assert_se(rr1);
        rr2 = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "b.com");
        assert_se(rr2);
        dns_answer_add(a, rr1, 0, 0, NULL);
        dns_answer_add(b, rr2, 0, 0, NULL);
        r = dns_answer_merge(a, b, &c);
        assert_se(r >= 0);
        assert_se(c);
        assert_se(dns_answer_size(c) == 2);
}
TEST(dns_answer_merge_null) {
        _cleanup_(dns_answer_unrefp) DnsAnswer *a = NULL, *b = NULL, *c = NULL;
        int r;
        /* Merge NULL+NULL */
        r = dns_answer_merge(NULL, NULL, &c);
        assert_se(r >= 0);
        /* Result should be NULL */
        assert_se(c == NULL);
}
TEST(dns_answer_merge_empty) {
        _cleanup_(dns_answer_unrefp) DnsAnswer *a = NULL, *c = NULL;
        int r;
        a = dns_answer_new(1);
        assert_se(a);
        /* Merge empty with non-empty */
        r = dns_answer_merge(a, NULL, &c);
        assert_se(r >= 0);
        assert_se(c == a);
}
TEST(dns_answer_remove_by_key) {
        _cleanup_(dns_answer_unrefp) DnsAnswer *a = NULL;
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL;
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL;
        int r;
        a = dns_answer_new(2);
        assert_se(a);
        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "example.com");
        assert_se(rr);
        dns_answer_add(a, rr, 0, 0, NULL);
        assert_se(dns_answer_size(a) == 1);
        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "example.com");
        assert_se(key);
        r = dns_answer_remove_by_key(&a, key);
        assert_se(r > 0);
        /* Answer should be freed since it becomes empty */
        assert_se(a == NULL);
        /* Removing from NULL should work */
        r = dns_answer_remove_by_key(&a, key);
        assert_se(r == 0);
}
TEST(dns_answer_min_ttl_empty) {
        assert_se(dns_answer_min_ttl(NULL) == UINT32_MAX);
}
TEST(dns_answer_min_ttl) {
        _cleanup_(dns_answer_unrefp) DnsAnswer *a = NULL;
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr1 = NULL, *rr2 = NULL;
        a = dns_answer_new(2);
        assert_se(a);
        rr1 = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "a.com");
        assert_se(rr1);
        rr1->ttl = 100;
        dns_answer_add(a, rr1, 0, 0, NULL);
        rr2 = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "b.com");
        assert_se(rr2);
        rr2->ttl = 200;
        dns_answer_add(a, rr2, 0, 0, NULL);
        assert_se(dns_answer_min_ttl(a) == 100);
}
TEST(dns_answer_add_soa) {
        _cleanup_(dns_answer_unrefp) DnsAnswer *a = NULL;
        int r;
        a = dns_answer_new(1);
        assert_se(a);
        r = dns_answer_add_soa(a, "example.com", 300, 0);
        assert_se(r >= 0);
        assert_se(dns_answer_size(a) == 1);
}
TEST(dns_answer_reserve) {
        _cleanup_(dns_answer_unrefp) DnsAnswer *a = NULL;
        int r;
        /* Reserve with NULL creates a new answer */
        r = dns_answer_reserve(&a, 5);
        assert_se(r >= 0);
        assert_se(a);
        assert_se(dns_answer_size(a) == 0);
}
TEST(dns_answer_extend) {
        _cleanup_(dns_answer_unrefp) DnsAnswer *a = NULL;
        _cleanup_(dns_answer_unrefp) DnsAnswer *b = NULL;
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL;
        int r;
        a = dns_answer_new(1);
        assert_se(a);
        b = dns_answer_new(1);
        assert_se(b);
        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "example.com");
        assert_se(rr);
        dns_answer_add(b, rr, 0, 0, NULL);
        r = dns_answer_extend(&a, b);
        assert_se(r >= 0);
        assert_se(dns_answer_size(a) == 1);
}
TEST(dns_answer_copy_by_key) {
        _cleanup_(dns_answer_unrefp) DnsAnswer *to = NULL;
        _cleanup_(dns_answer_unrefp) DnsAnswer *from = NULL;
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr1 = NULL, *rr2 = NULL;
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL;
        int r;
        from = dns_answer_new(2);
        assert_se(from);
        to = dns_answer_new(1);
        assert_se(to);
        rr1 = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "example.com");
        assert_se(rr1);
        rr2 = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_AAAA, "example.com");
        assert_se(rr2);
        dns_answer_add(from, rr1, 0, 0, NULL);
        dns_answer_add(from, rr2, 0, 0, NULL);
        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "example.com");
        assert_se(key);
        r = dns_answer_copy_by_key(&to, from, key, 0, NULL);
        assert_se(r >= 0);
        assert_se(dns_answer_size(to) == 1);
}
DEFINE_TEST_MAIN(LOG_DEBUG);
