/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "dns-domain.h"
#include "string-util.h"
#include "tests.h"

TEST(dns_name_is_single_label) {
        /* Single label */
        assert_se(dns_name_is_single_label("www") == true);
        assert_se(dns_name_is_single_label("com") == true);
        assert_se(dns_name_is_single_label("a") == true);

        /* Multiple labels */
        assert_se(dns_name_is_single_label("www.example.com") == false);
        assert_se(dns_name_is_single_label("example.com") == false);

        /* Root */
        assert_se(dns_name_is_single_label("") == false);
        assert_se(dns_name_is_single_label(".") == false);
}

TEST(dns_name_suffix) {
        const char *ret = NULL;
        int r;

        /* Get the last label (suffix of 1) */
        r = dns_name_suffix("www.example.com", 1, &ret);
        assert_se(r >= 0);
        assert_se(streq(ret, "com"));

        /* Get last 2 labels */
        r = dns_name_suffix("www.example.com", 2, &ret);
        assert_se(r >= 0);
        assert_se(streq(ret, "example.com"));

        /* Get last 3 labels = entire name */
        r = dns_name_suffix("www.example.com", 3, &ret);
        assert_se(r >= 0);
        assert_se(streq(ret, "www.example.com"));

        /* Request more labels than available → error */
        r = dns_name_suffix("example.com", 3, &ret);
        assert_se(r == -EINVAL);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
