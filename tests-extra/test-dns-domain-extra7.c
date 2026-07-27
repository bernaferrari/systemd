/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "dns-domain.h"
#include "string-util.h"
#include "tests.h"

TEST(dns_name_between) {
        /* Normal ordering: a < b < c */
        assert_se(dns_name_between("a.com", "b.com", "c.com"));
        assert_se(!dns_name_between("a.com", "a.com", "c.com"));
        assert_se(!dns_name_between("a.com", "c.com", "c.com"));
        assert_se(!dns_name_between("a.com", "d.com", "c.com"));

        /* Circular: a > c, so b is "between" if b > a OR b < c */
        assert_se(dns_name_between("z.com", "a.com", "b.com"));
        assert_se(dns_name_between("z.com", "z1.com", "b.com"));
}

TEST(dns_name_change_suffix) {
        _cleanup_free_ char *ret = NULL;

        assert_se(dns_name_change_suffix("www.example.com", "example.com", "example.org", &ret) >= 0);
        assert_se(streq(ret, "www.example.org"));
        ret = mfree(ret);

        assert_se(dns_name_change_suffix("example.com", "example.com", "example.org", &ret) >= 0);
        assert_se(streq(ret, "example.org"));
        ret = mfree(ret);

        /* Suffix doesn't match → returns 0 with NULL ret */
        assert_se(dns_name_change_suffix("www.example.com", "example.org", "example.net", &ret) == 0);
        assert_se(ret == NULL);
}

TEST(dns_name_to_wire_format) {
        uint8_t buffer[256];
        int r;

        r = dns_name_to_wire_format("www.example.com", buffer, sizeof(buffer), false);
        assert_se(r >= 0);
        /* wire format: 3www7example3com0 */
        assert_se(buffer[0] == 3);
        assert_se(buffer[4] == 7);
        assert_se(buffer[12] == 3);

        /* Root domain */
        r = dns_name_to_wire_format("", buffer, sizeof(buffer), false);
        assert_se(r >= 0);
        assert_se(buffer[0] == 0);

        /* Buffer too small */
        r = dns_name_to_wire_format("www.example.com", buffer, 5, false);
        assert_se(r < 0);
}

TEST(dns_label_escape_new) {
        _cleanup_free_ char *ret = NULL;
        int r;

        r = dns_label_escape_new("hello", 5, &ret);
        assert_se(r >= 0);
        assert_se(streq(ret, "hello"));

        ret = mfree(ret);
        r = dns_label_escape_new("a b", 3, &ret);
        assert_se(r >= 0);
        /* Space should be escaped */
        assert_se(!streq(ret, "a b"));

        /* Zero length */
        r = dns_label_escape_new("x", 0, &ret);
        assert_se(r == -EINVAL);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
