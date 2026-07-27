/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "dns-domain.h"
#include "string-util.h"
#include "tests.h"

TEST(dns_name_count_labels) {
        assert_se(dns_name_count_labels("") == 0);
        assert_se(dns_name_count_labels(".") == 0);
        assert_se(dns_name_count_labels("com") == 1);
        assert_se(dns_name_count_labels("example.com") == 2);
        assert_se(dns_name_count_labels("www.example.com") == 3);
        assert_se(dns_name_count_labels("a.b.c.d") == 4);
}

TEST(dns_name_skip) {
        const char *ret = NULL;
        int r;

        /* Skip 0 labels → same name */
        r = dns_name_skip("www.example.com", 0, &ret);
        assert_se(r > 0);
        assert_se(streq(ret, "www.example.com"));

        /* Skip 1 label → "example.com" */
        r = dns_name_skip("www.example.com", 1, &ret);
        assert_se(r > 0);
        assert_se(streq(ret, "example.com"));

        /* Skip 2 labels → "com" */
        r = dns_name_skip("www.example.com", 2, &ret);
        assert_se(r > 0);
        assert_se(streq(ret, "com"));

        /* Skip all labels (3 for www.example.com) → returns 1 but *ret = "" */
        r = dns_name_skip("www.example.com", 3, &ret);
        assert_se(r > 0);
        assert_se(streq(ret, ""));

        /* Single label, skip 1 → empty string, */
        r = dns_name_skip("com", 1, &ret);
        assert_se(r > 0);
        assert_se(streq(ret, ""));
}

TEST(dns_name_equal_skip) {
        /* Skip first label, compare rest */
        assert_se(dns_name_equal_skip("www.example.com", 1, "example.com") > 0);
        assert_se(dns_name_equal_skip("www.example.com", 1, "example.org") == 0);

        /* Skip 2 labels */
        assert_se(dns_name_equal_skip("www.example.com", 2, "com") > 0);
        assert_se(dns_name_equal_skip("www.example.com", 2, "net") == 0);

        /* Skip 0 labels → compare entire name */
        assert_se(dns_name_equal_skip("example.com", 0, "example.com") > 0);
        assert_se(dns_name_equal_skip("example.com", 0, "example.org") == 0);

        /* Case insensitive */
        assert_se(dns_name_equal_skip("WWW.EXAMPLE.COM", 1, "example.com") > 0);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
