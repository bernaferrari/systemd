/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/if_ether.h>

#include "conf-parser.h"
#include "string-util.h"
#include "strv.h"
#include "tests.h"

/* Helper: call config_parse_bool with minimal boilerplate */
static int call_parse_bool(const char *rvalue, bool fatal, bool *out) {
        return config_parse_bool(
                        NULL,               /* unit */
                        "test.conf",        /* filename */
                        __LINE__,           /* line */
                        NULL,               /* section */
                        0,                  /* section_line */
                        "TestBool",         /* lvalue */
                        fatal,              /* ltype (0=non-fatal, 1=fatal) */
                        rvalue,             /* rvalue */
                        out,                /* data */
                        NULL);              /* userdata */
}

TEST(config_parse_bool) {
        bool val = false;
        int r;

        /* true values */
        r = call_parse_bool("true", 0, &val);
        assert_se(r > 0);
        assert_se(val == true);

        r = call_parse_bool("yes", 0, &val);
        assert_se(r > 0);
        assert_se(val == true);

        r = call_parse_bool("1", 0, &val);
        assert_se(r > 0);
        assert_se(val == true);

        r = call_parse_bool("on", 0, &val);
        assert_se(r > 0);
        assert_se(val == true);

        /* false values */
        r = call_parse_bool("false", 0, &val);
        assert_se(r > 0);
        assert_se(val == false);

        r = call_parse_bool("no", 0, &val);
        assert_se(r > 0);
        assert_se(val == false);

        r = call_parse_bool("0", 0, &val);
        assert_se(r > 0);
        assert_se(val == false);

        r = call_parse_bool("off", 0, &val);
        assert_se(r > 0);
        assert_se(val == false);

        /* Invalid value, non-fatal: returns 0 */
        r = call_parse_bool("garbage", 0, &val);
        assert_se(r == 0);

        /* Invalid value, fatal: returns -ENOEXEC */
        r = call_parse_bool("garbage", 1, &val);
        assert_se(r == -ENOEXEC);
}

static int call_parse_iec_size(const char *rvalue, size_t *out) {
        return config_parse_iec_size(
                        NULL, "test.conf", __LINE__, NULL, 0,
                        "TestSize", 0, rvalue, out, NULL);
}

TEST(config_parse_iec_size) {
        size_t val = 0;
        int r;

        r = call_parse_iec_size("1024", &val);
        assert_se(r > 0);
        assert_se(val == 1024);

        r = call_parse_iec_size("4K", &val);
        assert_se(r > 0);
        assert_se(val == 4096);

        r = call_parse_iec_size("1M", &val);
        assert_se(r > 0);
        assert_se(val == 1024 * 1024);

        r = call_parse_iec_size("1G", &val);
        assert_se(r > 0);
        assert_se(val == (size_t)1024 * 1024 * 1024);

        r = call_parse_iec_size("0", &val);
        assert_se(r > 0);
        assert_se(val == 0);

        /* Invalid → config_parse_iec_size logs warning, returns 0 */
        r = call_parse_iec_size("abc", &val);
        assert_se(r == 0);
}

static int call_parse_iec_uint64(const char *rvalue, uint64_t *out) {
        return config_parse_iec_uint64(
                        NULL, "test.conf", __LINE__, NULL, 0,
                        "TestBytes", 0, rvalue, out, NULL);
}

TEST(config_parse_iec_uint64) {
        uint64_t val = 0;
        int r;

        r = call_parse_iec_uint64("1024", &val);
        assert_se(r > 0);
        assert_se(val == 1024);

        r = call_parse_iec_uint64("4K", &val);
        assert_se(r > 0);
        assert_se(val == 4096);

        r = call_parse_iec_uint64("1M", &val);
        assert_se(r > 0);
        assert_se(val == 1024 * 1024);

        /* Invalid → returns 0 (non-fatal via log_syntax_parse_error) */
        r = call_parse_iec_uint64("abc", &val);
        assert_se(r == 0);
}

static int call_parse_iec_uint64_infinity(const char *rvalue, uint64_t *out) {
        return config_parse_iec_uint64_infinity(
                        NULL, "test.conf", __LINE__, NULL, 0,
                        "TestInf", 0, rvalue, out, NULL);
}

TEST(config_parse_iec_uint64_infinity) {
        uint64_t val = 0;
        int r;

        /* "infinity" → UINT64_MAX */
        r = call_parse_iec_uint64_infinity("infinity", &val);
        assert_se(r > 0);
        assert_se(val == UINT64_MAX);

        /* Normal value delegates to config_parse_iec_uint64 */
        r = call_parse_iec_uint64_infinity("4K", &val);
        assert_se(r > 0);
        assert_se(val == 4096);
}

static int call_parse_si_uint64(const char *rvalue, uint64_t *out) {
        return config_parse_si_uint64(
                        NULL, "test.conf", __LINE__, NULL, 0,
                        "TestSI", 0, rvalue, out, NULL);
}

TEST(config_parse_si_uint64) {
        uint64_t val = 0;
        int r;

        r = call_parse_si_uint64("1000", &val);
        assert_se(r > 0);
        assert_se(val == 1000);

        r = call_parse_si_uint64("4K", &val);
        assert_se(r > 0);
        assert_se(val == 4000);

        r = call_parse_si_uint64("1M", &val);
        assert_se(r > 0);
        assert_se(val == 1000000);

        r = call_parse_si_uint64("abc", &val);
        assert_se(r == 0);
}

static int call_parse_tristate(const char *rvalue, int *out) {
        return config_parse_tristate(
                        NULL, "test.conf", __LINE__, NULL, 0,
                        "TestTri", 0, rvalue, out, NULL);
}

TEST(config_parse_tristate) {
        int val = -999;
        int r;

        /* true */
        r = call_parse_tristate("true", &val);
        assert_se(r > 0);
        assert_se(val == true);

        /* false */
        r = call_parse_tristate("false", &val);
        assert_se(r > 0);
        assert_se(val == false);

        /* empty → -1 (uninitialized) */
        r = call_parse_tristate("", &val);
        assert_se(r > 0);
        assert_se(val == -1);

        /* Invalid */
        r = call_parse_tristate("nonsense", &val);
        assert_se(r == 0);
}

static int call_parse_string(const char *rvalue, int ltype, char **out) {
        return config_parse_string(
                        NULL, "test.conf", __LINE__, NULL, 0,
                        "TestStr", ltype, rvalue, out, NULL);
}

TEST(config_parse_string) {
        _cleanup_free_ char *val = NULL;
        int r;

        r = call_parse_string("hello world", 0, &val);
        assert_se(r > 0);
        assert_se(streq(val, "hello world"));

        /* Empty → freed/NULL */
        r = call_parse_string("", 0, &val);
        assert_se(r > 0);
        assert_se(val == NULL);

        /* Replacement */
        r = call_parse_string("new value", 0, &val);
        assert_se(r > 0);
        assert_se(streq(val, "new value"));
}

static int call_parse_strv(const char *rvalue, int ltype, char ***out) {
        return config_parse_strv(
                        NULL, "test.conf", __LINE__, NULL, 0,
                        "TestStrv", ltype, rvalue, out, NULL);
}

TEST(config_parse_strv) {
        _cleanup_strv_free_ char **sv = NULL;
        int r;

        r = call_parse_strv("foo bar baz", 0, &sv);
        assert_se(r > 0);
        assert_se(strv_length(sv) == 3);
        assert_se(streq(sv[0], "foo"));
        assert_se(streq(sv[1], "bar"));
        assert_se(streq(sv[2], "baz"));

        /* Empty → freed/NULL */
        sv = strv_free(sv);
        r = call_parse_strv("", 0, &sv);
        assert_se(r > 0);
        assert_se(sv == NULL);

        /* Quoted value */
        r = call_parse_strv("\"hello world\" foo", 0, &sv);
        assert_se(r > 0);
        assert_se(strv_length(sv) == 2);
        assert_se(streq(sv[0], "hello world"));
        assert_se(streq(sv[1], "foo"));

        /* Dedup (ltype=true) */
        sv = strv_free(sv);
        r = call_parse_strv("a b a c", 1, &sv);
        assert_se(r > 0);
        assert_se(strv_length(sv) == 3);
        assert_se(streq(sv[0], "a"));
        assert_se(streq(sv[1], "b"));
        assert_se(streq(sv[2], "c"));
}

static int call_parse_log_facility(const char *rvalue, int *out) {
        return config_parse_log_facility(
                        NULL, "test.conf", __LINE__, NULL, 0,
                        "TestFacility", 0, rvalue, out, NULL);
}

TEST(config_parse_log_facility) {
        int val = LOG_USER | LOG_NOTICE; /* initial facility+level */
        int orig_pri = LOG_PRI(val);
        int r;

        r = call_parse_log_facility("daemon", &val);
        assert_se(r > 0);
        /* Facility changed to LOG_DAEMON, priority preserved */
        assert_se((val & LOG_FACMASK) == LOG_DAEMON);
        assert_se(LOG_PRI(val) == orig_pri);

        r = call_parse_log_facility("kern", &val);
        assert_se(r > 0);
        assert_se((val & LOG_FACMASK) == LOG_KERN);

        /* Invalid */
        r = call_parse_log_facility("invalid_facility", &val);
        assert_se(r == 0);
}

static int call_parse_log_level(const char *rvalue, int *out) {
        return config_parse_log_level(
                        NULL, "test.conf", __LINE__, NULL, 0,
                        "TestLevel", 0, rvalue, out, NULL);
}

TEST(config_parse_log_level) {
        int val = LOG_DAEMON | LOG_NOTICE; /* facility+level */
        int r;

        r = call_parse_log_level("err", &val);
        assert_se(r > 0);
        /* Facility preserved, level changed */
        assert_se((val & LOG_FACMASK) == LOG_DAEMON);
        assert_se(LOG_PRI(val) == LOG_ERR);

        r = call_parse_log_level("warning", &val);
        assert_se(r > 0);
        assert_se(LOG_PRI(val) == LOG_WARNING);

        /* Uninitialized (negative): sets just level, zero facility */
        int val2 = -1;
        r = call_parse_log_level("debug", &val2);
        assert_se(r > 0);
        assert_se(val2 == LOG_DEBUG);

        /* Invalid */
        r = call_parse_log_level("notalevel", &val);
        assert_se(r == 0);
}

static int call_parse_signal(const char *rvalue, int *out) {
        return config_parse_signal(
                        NULL, "test.conf", __LINE__, NULL, 0,
                        "TestSignal", 0, rvalue, out, NULL);
}

TEST(config_parse_signal) {
        int val = 0;
        int r;

        r = call_parse_signal("SIGTERM", &val);
        assert_se(r > 0);
        assert_se(val == SIGTERM);

        r = call_parse_signal("SIGKILL", &val);
        assert_se(r > 0);
        assert_se(val == SIGKILL);

        r = call_parse_signal("15", &val);
        assert_se(r > 0);
        assert_se(val == 15);

        /* Invalid signal */
        r = call_parse_signal("SIGFOOBAR99", &val);
        assert_se(r == 0);
}

static int call_parse_permille(const char *rvalue, unsigned *out) {
        return config_parse_permille(
                        NULL, "test.conf", __LINE__, NULL, 0,
                        "TestPermille", 0, rvalue, out, NULL);
}

TEST(config_parse_permille) {
        unsigned val = 0;
        int r;

        r = call_parse_permille("50%", &val);
        assert_se(r > 0);
        assert_se(val == 500);

        r = call_parse_permille("100%", &val);
        assert_se(r > 0);
        assert_se(val == 1000);

        r = call_parse_permille("0%", &val);
        assert_se(r > 0);
        assert_se(val == 0);

        /* Invalid */
        r = call_parse_permille("abc", &val);
        assert_se(r == 0);
}

static int call_parse_vlanprotocol(const char *rvalue, int *out) {
        return config_parse_vlanprotocol(
                        NULL, "test.conf", __LINE__, NULL, 0,
                        "TestVLANProto", 0, rvalue, out, NULL);
}

TEST(config_parse_vlanprotocol) {
        int val = 0;
        int r;

        r = call_parse_vlanprotocol("802.1q", &val);
        assert_se(r > 0);
        assert_se(val == ETH_P_8021Q);

        r = call_parse_vlanprotocol("802.1Q", &val);
        assert_se(r > 0);
        assert_se(val == ETH_P_8021Q);

        r = call_parse_vlanprotocol("802.1ad", &val);
        assert_se(r > 0);
        assert_se(val == ETH_P_8021AD);

        r = call_parse_vlanprotocol("802.1AD", &val);
        assert_se(r > 0);
        assert_se(val == ETH_P_8021AD);

        /* Empty → -1 */
        r = call_parse_vlanprotocol("", &val);
        assert_se(r > 0);
        assert_se(val == -1);

        /* Invalid */
        r = call_parse_vlanprotocol("invalid", &val);
        assert_se(r == 0);
}

static int call_parse_ip_port(const char *rvalue, uint16_t *out) {
        return config_parse_ip_port(
                        NULL, "test.conf", __LINE__, NULL, 0,
                        "TestPort", 0, rvalue, out, NULL);
}

TEST(config_parse_ip_port) {
        uint16_t val = 0;
        int r;

        r = call_parse_ip_port("80", &val);
        assert_se(r > 0);
        assert_se(val == 80);

        r = call_parse_ip_port("443", &val);
        assert_se(r > 0);
        assert_se(val == 443);

        r = call_parse_ip_port("65535", &val);
        assert_se(r > 0);
        assert_se(val == 65535);

        /* Empty → 0 */
        r = call_parse_ip_port("", &val);
        assert_se(r > 0);
        assert_se(val == 0);

        /* Invalid */
        r = call_parse_ip_port("abc", &val);
        assert_se(r == 0);
}

static int call_parse_percent(const char *rvalue, int *out) {
        return config_parse_percent(
                        NULL, "test.conf", __LINE__, NULL, 0,
                        "TestPercent", 0, rvalue, out, NULL);
}

TEST(config_parse_percent) {
        int val = -1;
        int r;

        r = call_parse_percent("50%", &val);
        assert_se(r > 0);
        assert_se(val == 50);

        r = call_parse_percent("100%", &val);
        assert_se(r > 0);
        assert_se(val == 100);

        r = call_parse_percent("0%", &val);
        assert_se(r > 0);
        assert_se(val == 0);

        /* Invalid */
        r = call_parse_percent("abc", &val);
        assert_se(r == 0);
}

static int call_parse_unsigned_bounded(const char *rvalue, unsigned min, unsigned max, bool ignoring, unsigned *out) {
        return config_parse_unsigned_bounded(
                        NULL, "test.conf", __LINE__, NULL, 0,
                        "TestBounded", rvalue, min, max, ignoring, out);
}

TEST(config_parse_unsigned_bounded) {
        unsigned val = 999;
        int r;

        r = call_parse_unsigned_bounded("50", 0, 100, false, &val);
        assert_se(r > 0);
        assert_se(val == 50);

        r = call_parse_unsigned_bounded("0", 0, 100, false, &val);
        assert_se(r > 0);
        assert_se(val == 0);

        r = call_parse_unsigned_bounded("100", 0, 100, false, &val);
        assert_se(r > 0);
        assert_se(val == 100);

        /* Out of range, ignoring=true → 0 */
        r = call_parse_unsigned_bounded("101", 0, 100, true, &val);
        assert_se(r == 0);

        /* Out of range, ignoring=false → negative */
        r = call_parse_unsigned_bounded("101", 0, 100, false, &val);
        assert_se(r < 0);

        /* Invalid string */
        r = call_parse_unsigned_bounded("abc", 0, 100, false, &val);
        assert_se(r < 0);
}

static int call_parse_uint32_flag(const char *rvalue, uint32_t ltype, uint32_t *out) {
        return config_parse_uint32_flag(
                        NULL, "test.conf", __LINE__, NULL, 0,
                        "TestFlag", ltype, rvalue, out, NULL);
}

TEST(config_parse_uint32_flag) {
        uint32_t flags = 0;
        int r;

        /* Set flag bit 1 */
        r = call_parse_uint32_flag("true", 0x02, &flags);
        assert_se(r > 0);
        assert_se(FLAGS_SET(flags, 0x02));

        /* Clear flag bit 1 */
        r = call_parse_uint32_flag("false", 0x02, &flags);
        assert_se(r > 0);
        assert_se(!FLAGS_SET(flags, 0x02));

        /* Set another flag bit */
        r = call_parse_uint32_flag("yes", 0x10, &flags);
        assert_se(r > 0);
        assert_se(FLAGS_SET(flags, 0x10));

        /* Empty → treated as false */
        flags = 0x04;
        r = call_parse_uint32_flag("", 0x04, &flags);
        assert_se(r > 0);
        assert_se(!FLAGS_SET(flags, 0x04));

        /* Invalid */
        r = call_parse_uint32_flag("garbage", 0x01, &flags);
        assert_se(r == 0);
}

static int call_parse_uint32_invert_flag(const char *rvalue, uint32_t ltype, uint32_t *out) {
        return config_parse_uint32_invert_flag(
                        NULL, "test.conf", __LINE__, NULL, 0,
                        "TestInvFlag", ltype, rvalue, out, NULL);
}

TEST(config_parse_uint32_invert_flag) {
        uint32_t flags = 0;
        int r;

        /* true → inverted, so bit is CLEARED */
        r = call_parse_uint32_invert_flag("true", 0x01, &flags);
        assert_se(r > 0);
        assert_se(!FLAGS_SET(flags, 0x01));

        /* false → inverted, so bit is SET */
        r = call_parse_uint32_invert_flag("false", 0x02, &flags);
        assert_se(r > 0);
        assert_se(FLAGS_SET(flags, 0x02));
}

static int call_parse_warn_compat(int ltype) {
        return config_parse_warn_compat(
                        NULL, "test.conf", __LINE__, NULL, 0,
                        "TestCompat", ltype, "ignored", NULL, NULL);
}

TEST(config_parse_warn_compat) {
        int r;

        r = call_parse_warn_compat(DISABLED_CONFIGURATION);
        assert_se(r == 0);

        r = call_parse_warn_compat(DISABLED_LEGACY);
        assert_se(r == 0);

        r = call_parse_warn_compat(DISABLED_EXPERIMENTAL);
        assert_se(r == 0);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
