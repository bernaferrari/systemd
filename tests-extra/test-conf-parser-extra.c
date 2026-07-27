/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "conf-parser.h"
#include "parse-util.h"
#include "percent-util.h"
#include "string-util.h"
#include "strv.h"
#include "tests.h"
#include "time-util.h"

/* Helper: invoke a config_parse_* function directly with minimal args.
 * Note: config_parse_* functions always return >= 0 (1 on success, 0 on skip).
 * Invalid values are logged as warnings but don't cause failure. */
#define PARSE_FUNC(func, rvalue, data) \
        func("test.unit", "test.conf", 1, "Section", 0, "key", 0, rvalue, &(data), NULL)

TEST(config_parse_int) {
        int val = 0;

        assert_se(PARSE_FUNC(config_parse_int, "42", val) >= 0);
        assert_se(val == 42);

        assert_se(PARSE_FUNC(config_parse_int, "-7", val) >= 0);
        assert_se(val == -7);

        assert_se(PARSE_FUNC(config_parse_int, "0", val) >= 0);
        assert_se(val == 0);
}

TEST(config_parse_unsigned) {
        unsigned val = 0;

        assert_se(PARSE_FUNC(config_parse_unsigned, "42", val) >= 0);
        assert_se(val == 42);

        assert_se(PARSE_FUNC(config_parse_unsigned, "0", val) >= 0);
        assert_se(val == 0);
}

TEST(config_parse_long) {
        long val = 0;

        assert_se(PARSE_FUNC(config_parse_long, "12345", val) >= 0);
        assert_se(val == 12345);

        assert_se(PARSE_FUNC(config_parse_long, "-999", val) >= 0);
        assert_se(val == -999);
}

TEST(config_parse_uint8) {
        uint8_t val = 0;

        assert_se(PARSE_FUNC(config_parse_uint8, "200", val) >= 0);
        assert_se(val == 200);

        assert_se(PARSE_FUNC(config_parse_uint8, "0", val) >= 0);
        assert_se(val == 0);
}

TEST(config_parse_uint16) {
        uint16_t val = 0;

        assert_se(PARSE_FUNC(config_parse_uint16, "1000", val) >= 0);
        assert_se(val == 1000);

        assert_se(PARSE_FUNC(config_parse_uint16, "65535", val) >= 0);
        assert_se(val == 65535);
}

TEST(config_parse_uint32) {
        uint32_t val = 0;

        assert_se(PARSE_FUNC(config_parse_uint32, "1000000", val) >= 0);
        assert_se(val == 1000000);
}

TEST(config_parse_uint64) {
        uint64_t val = 0;

        assert_se(PARSE_FUNC(config_parse_uint64, "999999999", val) >= 0);
        assert_se(val == 999999999);

        assert_se(PARSE_FUNC(config_parse_uint64, "0", val) >= 0);
        assert_se(val == 0);
}

TEST(config_parse_double) {
        double val = 0;

        assert_se(PARSE_FUNC(config_parse_double, "3.14", val) >= 0);
        assert_se(val > 3.0 && val < 3.3);

        assert_se(PARSE_FUNC(config_parse_double, "-1.5", val) >= 0);
        assert_se(val < 0);
}

TEST(config_parse_bool) {
        bool val = false;

        assert_se(PARSE_FUNC(config_parse_bool, "true", val) >= 0);
        assert_se(val == true);

        assert_se(PARSE_FUNC(config_parse_bool, "yes", val) >= 0);
        assert_se(val == true);

        assert_se(PARSE_FUNC(config_parse_bool, "false", val) >= 0);
        assert_se(val == false);

        assert_se(PARSE_FUNC(config_parse_bool, "no", val) >= 0);
        assert_se(val == false);

        assert_se(PARSE_FUNC(config_parse_bool, "1", val) >= 0);
        assert_se(val == true);

        assert_se(PARSE_FUNC(config_parse_bool, "0", val) >= 0);
        assert_se(val == false);
}

TEST(config_parse_string) {
        char *val = NULL;

        assert_se(PARSE_FUNC(config_parse_string, "hello world", val) >= 0);
        assert_se(streq(val, "hello world"));
        val = mfree(val);

        /* Empty string clears */
        assert_se(PARSE_FUNC(config_parse_string, "", val) >= 0);
        assert_se(val == NULL);
}

TEST(config_parse_mode) {
        mode_t val = 0;

        assert_se(PARSE_FUNC(config_parse_mode, "0644", val) >= 0);
        assert_se(val == 0644);

        assert_se(PARSE_FUNC(config_parse_mode, "0755", val) >= 0);
        assert_se(val == 0755);
}

TEST(config_parse_sec) {
        usec_t val = 0;

        assert_se(PARSE_FUNC(config_parse_sec, "10s", val) >= 0);
        assert_se(val == 10 * USEC_PER_SEC);

        assert_se(PARSE_FUNC(config_parse_sec, "100ms", val) >= 0);
        assert_se(val == 100 * USEC_PER_MSEC);

        assert_se(PARSE_FUNC(config_parse_sec, "5min", val) >= 0);
        assert_se(val == 5 * USEC_PER_MINUTE);
}

TEST(config_parse_sec_def_infinity) {
        usec_t val = 55;

        assert_se(PARSE_FUNC(config_parse_sec_def_infinity, "infinity", val) >= 0);
        assert_se(val == USEC_INFINITY);
}

TEST(config_parse_nsec) {
        nsec_t val = 0;

        assert_se(PARSE_FUNC(config_parse_nsec, "100ns", val) >= 0);
        assert_se(val == 100);

        assert_se(PARSE_FUNC(config_parse_nsec, "5us", val) >= 0);
        assert_se(val == 5000);
}

TEST(config_parse_signal) {
        int val = 0;

        assert_se(PARSE_FUNC(config_parse_signal, "SIGTERM", val) >= 0);
        assert_se(val == SIGTERM);

        assert_se(PARSE_FUNC(config_parse_signal, "15", val) >= 0);
        assert_se(val == 15);
}

TEST(config_parse_log_level) {
        int val = 0;

        assert_se(PARSE_FUNC(config_parse_log_level, "debug", val) >= 0);
        assert_se(val == LOG_DEBUG);

        assert_se(PARSE_FUNC(config_parse_log_level, "info", val) >= 0);
        assert_se(val == LOG_INFO);

        assert_se(PARSE_FUNC(config_parse_log_level, "err", val) >= 0);
        assert_se(val == LOG_ERR);
}

TEST(config_parse_log_facility) {
        int val = 0;

        assert_se(PARSE_FUNC(config_parse_log_facility, "daemon", val) >= 0);
        assert_se(val == LOG_DAEMON);

        assert_se(PARSE_FUNC(config_parse_log_facility, "user", val) >= 0);
        assert_se(val == LOG_USER);
}

TEST(config_parse_iec_size) {
        size_t val = 0;

        assert_se(PARSE_FUNC(config_parse_iec_size, "1K", val) >= 0);
        assert_se(val == 1024);

        assert_se(PARSE_FUNC(config_parse_iec_size, "1M", val) >= 0);
        assert_se(val == 1024 * 1024);
}

TEST(config_parse_iec_uint64) {
        uint64_t val = 0;

        assert_se(PARSE_FUNC(config_parse_iec_uint64, "2K", val) >= 0);
        assert_se(val == 2 * 1024);
}

TEST(config_parse_si_uint64) {
        uint64_t val = 0;

        assert_se(PARSE_FUNC(config_parse_si_uint64, "1K", val) >= 0);
        assert_se(val == 1000);
}

TEST(config_parse_strv) {
        _cleanup_strv_free_ char **val = NULL;

        assert_se(PARSE_FUNC(config_parse_strv, "one two three", val) >= 0);
        assert_se(strv_length(val) == 3);
        assert_se(streq(val[0], "one"));
        assert_se(streq(val[1], "two"));
        assert_se(streq(val[2], "three"));
}

TEST(config_parse_tristate) {
        int val = -1;

        assert_se(PARSE_FUNC(config_parse_tristate, "true", val) >= 0);
        assert_se(val == true);

        assert_se(PARSE_FUNC(config_parse_tristate, "false", val) >= 0);
        assert_se(val == false);
}

TEST(config_parse_percent) {
        int val = 0;

        assert_se(PARSE_FUNC(config_parse_percent, "50%", val) >= 0);
        assert_se(val == 50);

        assert_se(PARSE_FUNC(config_parse_percent, "100%", val) >= 0);
        assert_se(val == 100);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
