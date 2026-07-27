/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "dns-domain.h"
#include "string-util.h"
#include "tests.h"

TEST(dns_name_common_suffix) {
        const char *ret = NULL;
        int r;

        /* Same suffix */
        r = dns_name_common_suffix("www.example.com", "mail.example.com", &ret);
        assert_se(r >= 0);
        assert_se(streq(ret, "example.com"));

        /* Identical names */
        r = dns_name_common_suffix("example.com", "example.com", &ret);
        assert_se(r >= 0);
        assert_se(streq(ret, "example.com"));

        /* Completely different TLD */
        r = dns_name_common_suffix("example.com", "example.org", &ret);
        assert_se(r >= 0);
        /* No common suffix (or just root) */
        assert_se(streq(ret, ""));

        /* One name is suffix of the other */
        r = dns_name_common_suffix("www.example.com", "example.com", &ret);
        assert_se(r >= 0);
        assert_se(streq(ret, "example.com"));

        /* Root names */
        r = dns_name_common_suffix("", "", &ret);
        assert_se(r >= 0);
        assert_se(streq(ret, ""));
}

TEST(dns_name_startswith) {
        /* Basic prefix matching */
        assert_se(dns_name_startswith("www.example.com", "www") > 0);
        assert_se(dns_name_startswith("www.example.com", "www.example") > 0);
        assert_se(dns_name_startswith("www.example.com", "www.example.com") > 0);

        /* Not a prefix */
        assert_se(dns_name_startswith("www.example.com", "mail") == 0);
        assert_se(dns_name_startswith("www.example.com", "example") == 0);

        /* Empty prefix matches everything */
        assert_se(dns_name_startswith("example.com", "") > 0);

        /* Case insensitive */
        assert_se(dns_name_startswith("WWW.EXAMPLE.COM", "www") > 0);
        assert_se(dns_name_startswith("www.example.com", "WWW") > 0);
}

TEST(dns_name_compare_func) {
        /* Equal names */
        assert_se(dns_name_compare_func("example.com", "example.com") == 0);
        assert_se(dns_name_compare_func("", "") == 0);

        /* Ordering: compares labels from the end (TLD first) */
        assert_se(dns_name_compare_func("a.com", "b.com") < 0);
        assert_se(dns_name_compare_func("b.com", "a.com") > 0);

        /* Case insensitive comparison */
        assert_se(dns_name_compare_func("EXAMPLE.COM", "example.com") == 0);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
