/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/resource.h>

#include "conf-parser.h"
#include "in-addr-prefix-util.h"
#include "in-addr-util.h"
#include "architecture.h"
#include "process-util.h"
#include "rlimit-util.h"
#include "string-util.h"
#include "tests.h"

static int call_parse_personality(const char *rvalue, unsigned long *out) {
        return config_parse_personality(
                        NULL, "test.conf", __LINE__, NULL, 0,
                        "TestPersonality", 0, rvalue, out, NULL);
}

TEST(config_parse_personality) {
        unsigned long val = PERSONALITY_INVALID;
        int r;

        /* Use native architecture name */
        r = call_parse_personality(architecture_to_string(native_architecture()), &val);
        assert_se(r > 0);
        assert_se(val != PERSONALITY_INVALID);

        /* Empty → PERSONALITY_INVALID */
        r = call_parse_personality("", &val);
        assert_se(r > 0);
        assert_se(val == PERSONALITY_INVALID);

        /* Known architecture (x86-64 → valid on x86-64 only, just test it doesn't crash) */
        r = call_parse_personality("x86-64", &val);
        /* Might return 0 if not native arch on this host, which is OK */

        /* Invalid */
        r = call_parse_personality("notanarch99", &val);
        assert_se(r == 0);
}

static int call_parse_in_addr_non_null(const char *rvalue, int family, void *out) {
        return config_parse_in_addr_non_null(
                        NULL, "test.conf", __LINE__, NULL, 0,
                        "TestAddr", family, rvalue, out, NULL);
}

TEST(config_parse_in_addr_non_null) {
        struct in_addr ipv4 = {};
        struct in6_addr ipv6 = {};
        int r;

        /* IPv4 valid */
        r = call_parse_in_addr_non_null("192.168.1.1", AF_INET, &ipv4);
        assert_se(r > 0);
        assert_se(ipv4.s_addr != 0);

        /* IPv4 empty → zeroed */
        r = call_parse_in_addr_non_null("", AF_INET, &ipv4);
        assert_se(r > 0);
        assert_se(ipv4.s_addr == 0);

        /* IPv4 ANY address → rejected */
        ipv4.s_addr = 99;
        r = call_parse_in_addr_non_null("0.0.0.0", AF_INET, &ipv4);
        assert_se(r == 0);

        /* IPv6 valid */
        r = call_parse_in_addr_non_null("::1", AF_INET6, &ipv6);
        assert_se(r > 0);

        /* IPv6 empty → zeroed */
        r = call_parse_in_addr_non_null("", AF_INET6, &ipv6);
        assert_se(r > 0);
        assert_se(memcmp(&ipv6, &(struct in6_addr){}, sizeof(ipv6)) == 0);

        /* Invalid address string */
        r = call_parse_in_addr_non_null("not_an_ip", AF_INET, &ipv4);
        assert_se(r == 0);
}

static int call_parse_in_addr_data(const char *rvalue, struct in_addr_data *out) {
        return config_parse_in_addr_data(
                        NULL, "test.conf", __LINE__, NULL, 0,
                        "TestAddrData", 0, rvalue, out, NULL);
}

TEST(config_parse_in_addr_data) {
        struct in_addr_data d = {};
        int r;

        /* IPv4 */
        r = call_parse_in_addr_data("10.0.0.1", &d);
        assert_se(r > 0);
        assert_se(d.family == AF_INET);

        /* IPv6 */
        r = call_parse_in_addr_data("::1", &d);
        assert_se(r > 0);
        assert_se(d.family == AF_INET6);

        /* Empty → zeroed */
        r = call_parse_in_addr_data("", &d);
        assert_se(r > 0);
        assert_se(d.family == AF_UNSPEC);

        /* Invalid */
        r = call_parse_in_addr_data("not_an_ip", &d);
        assert_se(r == 0);
}

static int call_parse_in_addr_prefix(const char *rvalue, int warn_missing_prefix, struct in_addr_prefix *out) {
        return config_parse_in_addr_prefix(
                        NULL, "test.conf", __LINE__, NULL, 0,
                        "TestPrefix", warn_missing_prefix, rvalue, out, NULL);
}

TEST(config_parse_in_addr_prefix) {
        struct in_addr_prefix p = {};
        int r;

        /* IPv4 with prefix */
        r = call_parse_in_addr_prefix("192.168.1.0/24", 0, &p);
        assert_se(r > 0);
        assert_se(p.family == AF_INET);
        assert_se(p.prefixlen == 24);

        /* IPv6 with prefix */
        r = call_parse_in_addr_prefix("::1/128", 0, &p);
        assert_se(r > 0);
        assert_se(p.family == AF_INET6);
        assert_se(p.prefixlen == 128);

        /* Empty → zeroed */
        r = call_parse_in_addr_prefix("", 0, &p);
        assert_se(r > 0);
        assert_se(p.family == AF_UNSPEC);

        /* Invalid */
        r = call_parse_in_addr_prefix("not_a_prefix", 0, &p);
        assert_se(r == 0);
}

static int call_parse_rlimit(const char *rvalue, int ltype, struct rlimit **rl) {
        return config_parse_rlimit(
                        NULL, "test.conf", __LINE__, NULL, 0,
                        "LimitNOFILE", ltype, rvalue, rl, NULL);
}

TEST(config_parse_rlimit) {
        _cleanup_free_ struct rlimit **rl = NULL;
        int r;

        /* Allocate rlimit array */
        rl = new0(struct rlimit*, _RLIMIT_MAX);
        assert_se(rl != NULL);

        /* Valid value: "1024:4096" (soft:hard) */
        r = call_parse_rlimit("1024:4096", RLIMIT_NOFILE, rl);
        assert_se(r > 0);
        assert_se(rl[RLIMIT_NOFILE] != NULL);
        assert_se(rl[RLIMIT_NOFILE]->rlim_cur == 1024);
        assert_se(rl[RLIMIT_NOFILE]->rlim_max == 4096);

        /* Value "infinity" */
        rl[RLIMIT_NOFILE] = mfree(rl[RLIMIT_NOFILE]);
        r = call_parse_rlimit("infinity", RLIMIT_NOFILE, rl);
        assert_se(r > 0);
        assert_se(rl[RLIMIT_NOFILE] != NULL);
        assert_se(rl[RLIMIT_NOFILE]->rlim_cur == RLIM_INFINITY);

        /* Single value (both soft and hard) */
        rl[RLIMIT_NOFILE] = mfree(rl[RLIMIT_NOFILE]);
        r = call_parse_rlimit("512", RLIMIT_NOFILE, rl);
        assert_se(r > 0);
        assert_se(rl[RLIMIT_NOFILE]->rlim_cur == 512);
        assert_se(rl[RLIMIT_NOFILE]->rlim_max == 512);

        /* Invalid: soft > hard → returns 0 */
        rl[RLIMIT_NOFILE] = mfree(rl[RLIMIT_NOFILE]);
        r = call_parse_rlimit("4096:1024", RLIMIT_NOFILE, rl);
        assert_se(r == 0);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
