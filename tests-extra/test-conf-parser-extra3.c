/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "conf-parser.h"
#include "string-util.h"
#include "strv.h"
#include "tests.h"
#include "time-util.h"

#include "id128-util.h"

/* Helper: invoke a config_parse_* function with minimal args */
#define PARSE_FUNC(func, rvalue, data) \
        func("test.unit", "test.conf", 1, "Section", 0, "key", 0, rvalue, &(data), NULL)

/* With ltype support */
#define PARSE_FUNC_LTYPE(func, rvalue, ltype, data) \
        func("test.unit", "test.conf", 1, "Section", 0, "key", ltype, rvalue, &(data), NULL)

TEST(config_parse_id128) {
        sd_id128_t val = SD_ID128_NULL;
        int r;

        /* Valid hex */
        r = PARSE_FUNC(config_parse_id128, "a1b2c3d4-e5f6-7890-abcd-12345678abcd", val);
        assert_se(r >= 0);

        /* Empty/all-zeros ID should be rejected */
        r = PARSE_FUNC(config_parse_id128, "00000000-0000-0000-0000-000000000000", val);
        assert_se(r == 0);
}

TEST(config_parse_path) {
        _cleanup_free_ char *val = NULL;
        int r;

        r = PARSE_FUNC(config_parse_path, "/tmp/test.conf", val);
        assert_se(r >= 0);
        assert_se(streq(val, "/tmp/test.conf"));

        /* Empty clears */
        r = PARSE_FUNC(config_parse_path, "", val);
        assert_se(r >= 0);
        assert_se(val == NULL);
}

TEST(config_parse_sec_def_unset) {
        usec_t val = 55;
        int r;

        r = PARSE_FUNC(config_parse_sec_def_unset, "", val);
        assert_se(r > 0);
        assert_se(val == USEC_INFINITY);
}

TEST(config_parse_sec_fix_0) {
        usec_t val = 99;
        int r;

        /* 0 should be treated as infinity */
        r = PARSE_FUNC(config_parse_sec_fix_0, "0", val);
        assert_se(r > 0);
        assert_se(val == USEC_INFINITY);

        /* Normal value */
        r = PARSE_FUNC(config_parse_sec_fix_0, "5s", val);
        assert_se(r > 0);
        assert_se(val == 5 * USEC_PER_SEC);
}

TEST(config_parse_hostname) {
        _cleanup_free_ char *val = NULL;
        int r;

        r = PARSE_FUNC(config_parse_hostname, "example.com", val);
        assert_se(r > 0);
        assert_se(streq(val, "example.com"));

        /* Empty clears */
        r = PARSE_FUNC(config_parse_hostname, "", val);
        assert_se(r > 0);
        assert_se(val == NULL);
}

TEST(config_parse_dns_name) {
        _cleanup_free_ char *val = NULL;
        int r;

        r = PARSE_FUNC(config_parse_dns_name, "example.com", val);
        assert_se(r > 0);
        assert_se(streq(val, "example.com"));

        /* Empty clears */
        r = PARSE_FUNC(config_parse_dns_name, "", val);
        assert_se(r > 0);
        assert_se(val == NULL);
}

TEST(config_parse_int32) {
        int32_t val = 0;
        int r;

        r = PARSE_FUNC(config_parse_int32, "42", val);
        assert_se(r > 0);
        assert_se(val == 42);

        r = PARSE_FUNC(config_parse_int32, "-7", val);
        assert_se(r > 0);
        assert_se(val == -7);
}

TEST(config_parse_mtu) {
        uint32_t val = 0;
        int r;

        r = PARSE_FUNC(config_parse_mtu, "1500", val);
        assert_se(r > 0);
        assert_se(val == 1500);

        /* Empty sets to 0 */
        r = PARSE_FUNC(config_parse_mtu, "", val);
        assert_se(r > 0);
        assert_se(val == 0);
}

TEST(config_parse_loadavg) {
        double val = 0;
        int r;

        r = PARSE_FUNC(config_parse_loadavg, "1.5", val);
        assert_se(r > 0);
}

TEST(config_parse_ip_protocol) {
        int val = 0;
        int r;

        r = PARSE_FUNC(config_parse_ip_protocol, "tcp", val);
        assert_se(r > 0);
        assert_se(val == IPPROTO_TCP);

        r = PARSE_FUNC(config_parse_ip_protocol, "udp", val);
        assert_se(r > 0);
        assert_se(val == IPPROTO_UDP);
}

TEST(config_parse_pid) {
        pid_t val = 0;
        int r;

        r = PARSE_FUNC(config_parse_pid, "1234", val);
        assert_se(r > 0);
        assert_se(val == 1234);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
