/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "parse-util.h"
#include "tests.h"

/* Rust FFI */
#include "rust/parse_util.h"

/* ── parse_boolean ───────────────────────────────────────────────────────── */

TEST(parse_boolean_true) {
        const char *true_vals[] = { "1", "yes", "y", "true", "t", "on", NULL };
        for (int i = 0; true_vals[i]; i++) {
                assert_se(parse_boolean(true_vals[i]) == rs_parse_boolean(true_vals[i]));
                assert_se(parse_boolean(true_vals[i]) == 1);
        }
}

TEST(parse_boolean_false) {
        const char *false_vals[] = { "0", "no", "n", "false", "f", "off", NULL };
        for (int i = 0; false_vals[i]; i++) {
                assert_se(parse_boolean(false_vals[i]) == rs_parse_boolean(false_vals[i]));
                assert_se(parse_boolean(false_vals[i]) == 0);
        }
}

TEST(parse_boolean_case_insensitive) {
        assert_se(parse_boolean("YES") == rs_parse_boolean("YES"));
        assert_se(parse_boolean("True") == rs_parse_boolean("True"));
        assert_se(parse_boolean("ON") == rs_parse_boolean("ON"));
        assert_se(parse_boolean("No") == rs_parse_boolean("No"));
        assert_se(parse_boolean("FALSE") == rs_parse_boolean("FALSE"));
}

TEST(parse_boolean_invalid) {
        assert_se(parse_boolean(NULL) == rs_parse_boolean(NULL));
        assert_se(parse_boolean("") == rs_parse_boolean(""));
        assert_se(parse_boolean("bogus") == rs_parse_boolean("bogus"));
        assert_se(parse_boolean("2") == rs_parse_boolean("2"));
        assert_se(parse_boolean("maybe") == rs_parse_boolean("maybe"));
}

/* ── safe_atou ───────────────────────────────────────────────────────────── */

TEST(safe_atou_basic) {
        unsigned u;
        assert_se(safe_atou("0", &u) == rs_safe_atou("0", &u) && u == 0);
        assert_se(safe_atou("42", &u) == rs_safe_atou("42", &u) && u == 42);
        assert_se(safe_atou("4294967295", &u) == rs_safe_atou("4294967295", &u) && u == UINT_MAX);
}

TEST(safe_atou_whitespace) {
        unsigned u;
        assert_se(safe_atou("  42", &u) == rs_safe_atou("  42", &u));
        assert_se(safe_atou("42  ", &u) == rs_safe_atou("42  ", &u));
}

TEST(safe_atou_negative) {
        unsigned u;
        assert_se(safe_atou("-1", &u) == rs_safe_atou("-1", &u));
        assert_se(safe_atou("-1", &u) < 0);
}

TEST(safe_atou_invalid) {
        unsigned u;
        assert_se(safe_atou("", &u) == rs_safe_atou("", &u));
        assert_se(safe_atou("abc", &u) == rs_safe_atou("abc", &u));
        assert_se(safe_atou("12abc", &u) == rs_safe_atou("12abc", &u));
}

TEST(safe_atou_overflow) {
        unsigned u;
        assert_se(safe_atou("4294967296", &u) == rs_safe_atou("4294967296", &u));
        assert_se(safe_atou("99999999999", &u) == rs_safe_atou("99999999999", &u));
}

TEST(safe_atou_hex) {
        unsigned u;
        assert_se(safe_atou_full("0xff", 16, &u) == rs_safe_atou_full("0xff", 16, &u));
        assert_se(safe_atou_full("0xFF", 16, &u) == rs_safe_atou_full("0xFF", 16, &u));
        assert_se(u == 255);
}

/* ── safe_atoi ───────────────────────────────────────────────────────────── */

TEST(safe_atoi_basic) {
        int i;
        assert_se(safe_atoi("0", &i) == rs_safe_atoi("0", &i) && i == 0);
        assert_se(safe_atoi("42", &i) == rs_safe_atoi("42", &i) && i == 42);
        assert_se(safe_atoi("-42", &i) == rs_safe_atoi("-42", &i) && i == -42);
        assert_se(safe_atoi("2147483647", &i) == rs_safe_atoi("2147483647", &i) && i == INT_MAX);
        assert_se(safe_atoi("-2147483648", &i) == rs_safe_atoi("-2147483648", &i) && i == INT_MIN);
}

TEST(safe_atoi_invalid) {
        int i;
        assert_se(safe_atoi("", &i) == rs_safe_atoi("", &i));
        assert_se(safe_atoi("abc", &i) == rs_safe_atoi("abc", &i));
        assert_se(safe_atoi("12abc", &i) == rs_safe_atoi("12abc", &i));
}

TEST(safe_atoi_overflow) {
        int i;
        assert_se(safe_atoi("2147483648", &i) == rs_safe_atoi("2147483648", &i));
        assert_se(safe_atoi("-2147483649", &i) == rs_safe_atoi("-2147483649", &i));
}

/* ── safe_atolli ─────────────────────────────────────────────────────────── */

TEST(safe_atolli_basic) {
        long long ll;
        assert_se(safe_atolli("0", &ll) == rs_safe_atolli("0", &ll) && ll == 0);
        assert_se(safe_atolli("123456789012", &ll) == rs_safe_atolli("123456789012", &ll));
        assert_se(safe_atolli("-123456789012", &ll) == rs_safe_atolli("-123456789012", &ll));
}

TEST(safe_atolli_invalid) {
        long long ll;
        assert_se(safe_atolli("", &ll) == rs_safe_atolli("", &ll));
        assert_se(safe_atolli("abc", &ll) == rs_safe_atolli("abc", &ll));
}

/* ── safe_atollu ─────────────────────────────────────────────────────────── */

TEST(safe_atollu_basic) {
        unsigned long long llu;
        assert_se(safe_atollu("0", &llu) == rs_safe_atollu("0", &llu) && llu == 0);
        assert_se(safe_atollu("42", &llu) == rs_safe_atollu("42", &llu) && llu == 42);
}

TEST(safe_atollu_invalid) {
        unsigned long long llu;
        assert_se(safe_atollu("-1", &llu) == rs_safe_atollu("-1", &llu));
        assert_se(safe_atollu("", &llu) == rs_safe_atollu("", &llu));
        assert_se(safe_atollu("abc", &llu) == rs_safe_atollu("abc", &llu));
}

/* ── safe_atou_bounded ──────────────────────────────────────────────────── */

TEST(safe_atou_bounded_ok) {
        unsigned v;
        assert_se(safe_atou_bounded("5", 1, 10, &v) == rs_safe_atou_bounded("5", 1, 10, &v) && v == 5);
        assert_se(safe_atou_bounded("1", 1, 10, &v) == rs_safe_atou_bounded("1", 1, 10, &v) && v == 1);
        assert_se(safe_atou_bounded("10", 1, 10, &v) == rs_safe_atou_bounded("10", 1, 10, &v) && v == 10);
}

TEST(safe_atou_bounded_out_of_range) {
        unsigned v;
        assert_se(safe_atou_bounded("0", 1, 10, &v) == rs_safe_atou_bounded("0", 1, 10, &v));
        assert_se(safe_atou_bounded("11", 1, 10, &v) == rs_safe_atou_bounded("11", 1, 10, &v));
}

/* ── safe_atou8_full ─────────────────────────────────────────────────────── */

TEST(safe_atou8_basic) {
        uint8_t v;
        assert_se(safe_atou8("0", &v) == rs_safe_atou8_full("0", 0, &v) && v == 0);
        assert_se(safe_atou8("255", &v) == rs_safe_atou8_full("255", 0, &v) && v == 255);
        assert_se(safe_atou8("256", &v) == rs_safe_atou8_full("256", 0, &v));
        assert_se(safe_atou8("256", &v) < 0);
}

/* ── safe_atou16_full ────────────────────────────────────────────────────── */

TEST(safe_atou16_basic) {
        uint16_t v;
        assert_se(safe_atou16("0", &v) == rs_safe_atou16_full("0", 0, &v) && v == 0);
        assert_se(safe_atou16("65535", &v) == rs_safe_atou16_full("65535", 0, &v) && v == 65535);
        assert_se(safe_atou16("65536", &v) == rs_safe_atou16_full("65536", 0, &v));
        assert_se(safe_atou16("65536", &v) < 0);
}

/* ── parse_size ──────────────────────────────────────────────────────────── */

TEST(parse_size_simple) {
        uint64_t sz;
        assert_se(parse_size("1024", 1024, &sz) == rs_parse_size("1024", 1024, &sz) && sz == 1024);
        assert_se(parse_size("1K", 1024, &sz) == rs_parse_size("1K", 1024, &sz) && sz == 1024);
        assert_se(parse_size("1M", 1024, &sz) == rs_parse_size("1M", 1024, &sz) && sz == 1048576);
        assert_se(parse_size("1G", 1024, &sz) == rs_parse_size("1G", 1024, &sz) && sz == 1073741824);
}

TEST(parse_size_si) {
        uint64_t sz;
        assert_se(parse_size("1K", 1000, &sz) == rs_parse_size("1K", 1000, &sz) && sz == 1000);
        assert_se(parse_size("1M", 1000, &sz) == rs_parse_size("1M", 1000, &sz) && sz == 1000000);
}

TEST(parse_size_invalid) {
        uint64_t sz;
        assert_se(parse_size("", 1024, &sz) == rs_parse_size("", 1024, &sz));
        assert_se(parse_size("abc", 1024, &sz) == rs_parse_size("abc", 1024, &sz));
        assert_se(parse_size("-1", 1024, &sz) == rs_parse_size("-1", 1024, &sz));
}

TEST(parse_size_whitespace) {
        uint64_t sz;
        assert_se(parse_size("  1024  ", 1024, &sz) == rs_parse_size("  1024  ", 1024, &sz));
}

/* ── parse_pid ───────────────────────────────────────────────────────────── */

TEST(parse_pid_basic) {
        pid_t pid;
        assert_se(parse_pid("1", &pid) == rs_parse_pid("1", &pid) && pid == 1);
        assert_se(parse_pid("100", &pid) == rs_parse_pid("100", &pid) && pid == 100);
}

TEST(parse_pid_invalid) {
        pid_t pid;
        assert_se(parse_pid("-1", &pid) == rs_parse_pid("-1", &pid));
        assert_se(parse_pid("abc", &pid) == rs_parse_pid("abc", &pid));
        assert_se(parse_pid("0", &pid) == rs_parse_pid("0", &pid));
}

/* ── parse_mode ──────────────────────────────────────────────────────────── */

TEST(parse_mode_basic) {
        mode_t m;
        assert_se(parse_mode("0644", &m) == rs_parse_mode("0644", &m) && m == 0644);
        assert_se(parse_mode("0755", &m) == rs_parse_mode("0755", &m) && m == 0755);
        assert_se(parse_mode("777", &m) == rs_parse_mode("777", &m) && m == 0777);
}

TEST(parse_mode_invalid) {
        mode_t m;
        assert_se(parse_mode("10000", &m) == rs_parse_mode("10000", &m));
        assert_se(parse_mode("-644", &m) == rs_parse_mode("-644", &m));
}

/* ── parse_ifindex ───────────────────────────────────────────────────────── */

TEST(parse_ifindex_basic) {
        assert_se(parse_ifindex("1") == rs_parse_ifindex("1"));
        assert_se(parse_ifindex("42") == rs_parse_ifindex("42"));
}

TEST(parse_ifindex_invalid) {
        assert_se(parse_ifindex("0") == rs_parse_ifindex("0"));
        assert_se(parse_ifindex("-1") == rs_parse_ifindex("-1"));
        assert_se(parse_ifindex("abc") == rs_parse_ifindex("abc"));
}

/* ── parse_fd ────────────────────────────────────────────────────────────── */

TEST(parse_fd_basic) {
        assert_se(parse_fd("0") == rs_parse_fd("0"));
        assert_se(parse_fd("42") == rs_parse_fd("42"));
}

TEST(parse_fd_negative) {
        assert_se(parse_fd("-1") == rs_parse_fd("-1"));
        assert_se(parse_fd("-1") < 0);
}

/* ── parse_nice ──────────────────────────────────────────────────────────── */

TEST(parse_nice_basic) {
        int n;
        assert_se(parse_nice("0", &n) == rs_parse_nice("0", &n) && n == 0);
        assert_se(parse_nice("-20", &n) == rs_parse_nice("-20", &n) && n == -20);
        assert_se(parse_nice("19", &n) == rs_parse_nice("19", &n) && n == 19);
}

TEST(parse_nice_out_of_range) {
        int n;
        assert_se(parse_nice("-21", &n) == rs_parse_nice("-21", &n));
        assert_se(parse_nice("20", &n) == rs_parse_nice("20", &n));
}

/* ── parse_ip_port ───────────────────────────────────────────────────────── */

TEST(parse_ip_port_basic) {
        uint16_t port;
        assert_se(parse_ip_port("80", &port) == rs_parse_ip_port("80", &port) && port == 80);
        assert_se(parse_ip_port("443", &port) == rs_parse_ip_port("443", &port) && port == 443);
        assert_se(parse_ip_port("65535", &port) == rs_parse_ip_port("65535", &port) && port == 65535);
}

TEST(parse_ip_port_zero_rejected) {
        uint16_t port;
        assert_se(parse_ip_port("0", &port) == rs_parse_ip_port("0", &port));
        assert_se(parse_ip_port("0", &port) < 0);
}

TEST(parse_ip_port_out_of_range) {
        uint16_t port;
        assert_se(parse_ip_port("65536", &port) == rs_parse_ip_port("65536", &port));
}

/* ── parse_errno ─────────────────────────────────────────────────────────── */

TEST(parse_errno_basic) {
        assert_se(parse_errno("0") == rs_parse_errno("0"));
        assert_se(parse_errno("1") == rs_parse_errno("1"));
        assert_se(parse_errno("22") == rs_parse_errno("22"));
        assert_se(parse_errno("EINTR") == rs_parse_errno("EINTR"));
        assert_se(parse_errno("EINVAL") == rs_parse_errno("EINVAL"));
        assert_se(parse_errno("ENOMEM") == rs_parse_errno("ENOMEM"));
}

TEST(parse_errno_invalid) {
        assert_se(parse_errno("") == rs_parse_errno(""));
        assert_se(parse_errno("bogus") == rs_parse_errno("bogus"));
        assert_se(parse_errno("999999") == rs_parse_errno("999999"));
}

/* ── safe_atoi16 ─────────────────────────────────────────────────────────── */

TEST(safe_atoi16_basic) {
        int16_t v;
        assert_se(safe_atoi16("0", &v) == rs_safe_atoi16("0", &v) && v == 0);
        assert_se(safe_atoi16("32767", &v) == rs_safe_atoi16("32767", &v) && v == 32767);
        assert_se(safe_atoi16("-32768", &v) == rs_safe_atoi16("-32768", &v) && v == -32768);
        assert_se(safe_atoi16("-1", &v) == rs_safe_atoi16("-1", &v) && v == -1);
}

TEST(safe_atoi16_overflow) {
        int16_t v;
        assert_se(safe_atoi16("32768", &v) == rs_safe_atoi16("32768", &v));
        assert_se(safe_atoi16("-32769", &v) == rs_safe_atoi16("-32769", &v));
        assert_se(safe_atoi16("99999", &v) == rs_safe_atoi16("99999", &v));
}

/* ── safe_atollu_full ────────────────────────────────────────────────────── */

TEST(safe_atollu_full_decimal) {
        unsigned long long llu;
        assert_se(safe_atollu_full("0", 10, &llu) == rs_safe_atollu_full("0", 10, &llu) && llu == 0);
        assert_se(safe_atollu_full("42", 10, &llu) == rs_safe_atollu_full("42", 10, &llu) && llu == 42);
        assert_se(safe_atollu_full("18446744073709551615", 10, &llu) == rs_safe_atollu_full("18446744073709551615", 10, &llu));
}

TEST(safe_atollu_full_hex) {
        unsigned long long llu;
        assert_se(safe_atollu_full("ff", 16, &llu) == rs_safe_atollu_full("ff", 16, &llu) && llu == 255);
        assert_se(safe_atollu_full("0xFF", 16, &llu) == rs_safe_atollu_full("0xFF", 16, &llu) && llu == 255);
}

TEST(safe_atollu_full_invalid) {
        unsigned long long llu;
        assert_se(safe_atollu_full("", 10, &llu) == rs_safe_atollu_full("", 10, &llu));
        assert_se(safe_atollu_full("abc", 10, &llu) == rs_safe_atollu_full("abc", 10, &llu));
        assert_se(safe_atollu_full("-1", 10, &llu) == rs_safe_atollu_full("-1", 10, &llu));
}

/* ── main ────────────────────────────────────────────────────────────────── */

DEFINE_TEST_MAIN(LOG_INFO);
