/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "dns-domain.h"
#include "string-util.h"
#include "tests.h"

TEST(dns_name_is_valid_basic) {
        assert_se(dns_name_is_valid("example.com") > 0);
        assert_se(dns_name_is_valid("www.example.com") > 0);
        /* Empty string is valid (represents root domain) */
        assert_se(dns_name_is_valid("") > 0);
        assert_se(dns_name_is_valid(".") > 0);
        assert_se(dns_name_is_valid("..") == 0);
        assert_se(dns_name_is_valid("example..com") == 0);
}

TEST(dns_name_normalize_basic) {
        _cleanup_free_ char *ret = NULL;

        assert_se(dns_name_normalize("example.com", 0, &ret) >= 0);
        assert_se(ret);
        ret = mfree(ret);

        assert_se(dns_name_normalize("", 0, &ret) >= 0);
        ret = mfree(ret);

        assert_se(dns_name_normalize("EXAMPLE.COM", 0, &ret) >= 0);
        assert_se(ret);
        /* Normalization preserves case */
        assert_se(streq(ret, "EXAMPLE.COM"));
}

TEST(dns_name_count_labels_basic) {
        assert_se(dns_name_count_labels("example.com") == 2);
        assert_se(dns_name_count_labels("www.example.com") == 3);
        assert_se(dns_name_count_labels("a.b.c.d") == 4);
        assert_se(dns_name_count_labels("") == 0);
        assert_se(dns_name_count_labels("com") == 1);
}

TEST(dns_name_suffix_basic) {
        const char *p;

        /* suffix(n) returns last n labels; ret = total - n */
        assert_se(dns_name_suffix("www.example.com", 1, &p) == 2);
        assert_se(streq(p, "com"));

        assert_se(dns_name_suffix("www.example.com", 2, &p) == 1);
        assert_se(streq(p, "example.com"));

        assert_se(dns_name_suffix("www.example.com", 3, &p) == 0);
        assert_se(streq(p, "www.example.com"));

        assert_se(dns_name_suffix("www.example.com", 4, &p) == -EINVAL);
}

TEST(dns_name_skip_basic) {
        const char *p;

        /* skip(n) skips first n labels */
        assert_se(dns_name_skip("www.example.com", 1, &p) > 0);
        assert_se(streq(p, "example.com"));

        assert_se(dns_name_skip("www.example.com", 2, &p) > 0);
        assert_se(streq(p, "com"));

        assert_se(dns_name_skip("www.example.com", 3, &p) > 0);
        assert_se(streq(p, ""));

        assert_se(dns_name_skip("www.example.com", 4, &p) == 0);
}

TEST(dns_name_equal_skip_basic) {
        assert_se(dns_name_equal_skip("www.example.com", 0, "www.example.com") > 0);
        assert_se(dns_name_equal_skip("www.example.com", 1, "example.com") > 0);
        assert_se(dns_name_equal_skip("www.example.com", 2, "com") > 0);
        assert_se(dns_name_equal_skip("www.example.com", 1, "www.example.com") == 0);
}

TEST(dns_name_concat_basic) {
        _cleanup_free_ char *ret = NULL;

        assert_se(dns_name_concat("www", "example.com", 0, &ret) >= 0);
        assert_se(streq(ret, "www.example.com"));
        ret = mfree(ret);

        assert_se(dns_name_concat("www", NULL, 0, &ret) >= 0);
        assert_se(streq(ret, "www"));
        ret = mfree(ret);

        assert_se(dns_name_concat(NULL, "example.com", 0, &ret) >= 0);
        assert_se(streq(ret, "example.com"));
}

TEST(dns_name_common_suffix_basic) {
        const char *ret = NULL;

        assert_se(dns_name_common_suffix("a.example.com", "b.example.com", &ret) >= 0);
        assert_se(ret);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
