/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "dns-packet.h"
#include "string-util.h"
#include "tests.h"

TEST(format_dns_rcode) {
        char buf[DECIMAL_STR_MAX(int)];

        /* Known rcode */
        assert_se(streq(format_dns_rcode(DNS_RCODE_SUCCESS, buf), "SUCCESS"));
        assert_se(streq(format_dns_rcode(DNS_RCODE_SERVFAIL, buf), "SERVFAIL"));
        assert_se(streq(format_dns_rcode(DNS_RCODE_NXDOMAIN, buf), "NXDOMAIN"));

        /* Unknown rcode falls back to numeric */
        assert_se(streq(format_dns_rcode(9999, buf), "9999"));
}

TEST(format_dns_ede_rcode) {
        char buf[DECIMAL_STR_MAX(int)];

        /* Known ede rcode */
        assert_se(streq(format_dns_ede_rcode(DNS_EDE_RCODE_OTHER, buf), "Other"));
        assert_se(streq(format_dns_ede_rcode(DNS_EDE_RCODE_STALE_ANSWER, buf), "Stale Answer"));

        /* Unknown falls back to numeric */
        assert_se(streq(format_dns_ede_rcode(9999, buf), "9999"));
}

TEST(format_dns_svc_param_key) {
        char buf[DECIMAL_STR_MAX(uint16_t) + 3];

        /* Known key should return string */
        assert_se(format_dns_svc_param_key(DNS_SVC_PARAM_KEY_MANDATORY, buf));

        /* Unknown key falls back to "keyN" format */
        const char *r = format_dns_svc_param_key(9999, buf);
        assert_se(r);
        assert_se(startswith(r, "key"));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
