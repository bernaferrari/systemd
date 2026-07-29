/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Shadow test: C vs Rust for remaining untested pure functions */
/* RUST-CONTRACT: strv-free-and-replace */

#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>

#include "tests.h"
#include "parse-util.h"
#include "path-util.h"
#include "strv.h"
#include "in-addr-util.h"
#include "mountpoint-util.h"
#include "rust/path_util.h"
#include "rust/strv.h"
#include "rust/in_addr_util.h"
#include "rust/parse_util.h"

/* ── path_is_absolute ─────────────────────────────────────────────── */

static void test_path_is_absolute_null(void) {
        assert_se(!path_is_absolute(NULL));
        assert_se(!rs_path_is_absolute(NULL));
}

static void test_path_is_absolute_absolute(void) {
        assert_se(path_is_absolute("/") == rs_path_is_absolute("/"));
        assert_se(path_is_absolute("/") == true);

        assert_se(path_is_absolute("/foo") == rs_path_is_absolute("/foo"));
        assert_se(path_is_absolute("/foo") == true);

        assert_se(path_is_absolute("/foo/bar") == rs_path_is_absolute("/foo/bar"));
        assert_se(path_is_absolute("/foo/bar") == true);
}

static void test_path_is_absolute_relative(void) {
        assert_se(!path_is_absolute("foo"));
        assert_se(!rs_path_is_absolute("foo"));

        assert_se(!path_is_absolute("foo/bar"));
        assert_se(!rs_path_is_absolute("foo/bar"));

        assert_se(!path_is_absolute(""));
        assert_se(!rs_path_is_absolute(""));
}

static void test_path_is_absolute_dot(void) {
        assert_se(!path_is_absolute("."));
        assert_se(!rs_path_is_absolute("."));

        assert_se(!path_is_absolute("./foo"));
        assert_se(!rs_path_is_absolute("./foo"));
}

/* ── path_is_normalized ───────────────────────────────────────────── */

static void test_path_is_normalized_valid(void) {
        assert_se(path_is_normalized("/") == rs_path_is_normalized("/"));
        assert_se(path_is_normalized("/") == true);

        assert_se(path_is_normalized("/foo") == rs_path_is_normalized("/foo"));
        assert_se(path_is_normalized("/foo") == true);

        assert_se(path_is_normalized("/foo/bar") == rs_path_is_normalized("/foo/bar"));
        assert_se(path_is_normalized("/foo/bar") == true);
}

static void test_path_is_normalized_trailing_slash(void) {
        assert_se(path_is_normalized("/foo/") == rs_path_is_normalized("/foo/"));
        assert_se(path_is_normalized("/foo/") == true);

        assert_se(path_is_normalized("/foo/bar/") == rs_path_is_normalized("/foo/bar/"));
        assert_se(path_is_normalized("/foo/bar/") == true);
}

static void test_path_is_normalized_dot(void) {
        assert_se(!path_is_normalized("."));
        assert_se(!rs_path_is_normalized("."));

        assert_se(!path_is_normalized("./foo"));
        assert_se(!rs_path_is_normalized("./foo"));

        assert_se(!path_is_normalized("/foo/."));
        assert_se(!rs_path_is_normalized("/foo/."));
}

static void test_path_is_normalized_double_slash(void) {
        assert_se(!path_is_normalized("//"));
        assert_se(!rs_path_is_normalized("//"));

        assert_se(!path_is_normalized("/foo//bar"));
        assert_se(!rs_path_is_normalized("/foo//bar"));
}

static void test_path_is_normalized_dotdot(void) {
        /* path_is_safe rejects .. so these should fail */
        assert_se(!path_is_normalized(".."));
        assert_se(!rs_path_is_normalized(".."));

        assert_se(!path_is_normalized("/foo/.."));
        assert_se(!rs_path_is_normalized("/foo/.."));
}

static void test_path_is_normalized_empty(void) {
        assert_se(!path_is_normalized(""));
        assert_se(!rs_path_is_normalized(""));
}

/* ── valid_device_allow_pattern ────────────────────────────────────── */

static void test_valid_device_allow_pattern_valid(void) {
        const char *valid[] = {
                "eth*",
                "wlan*",
                "enp*",
                "disk*",
                "ttyUSB*",
                "sd*",
                "loop*",
        };
        for (int i = 0; i < (int)ELEMENTSOF(valid); i++) {
                bool c = valid_device_allow_pattern(valid[i]);
                bool r = rs_valid_device_allow_pattern(valid[i]);
                assert_se(c == r);
        }
}

static void test_valid_device_allow_pattern_invalid(void) {
        /* These should be invalid patterns */
        const char *invalid[] = {
                "",
                "/dev/eth0",
                "../eth0",
        };
        for (int i = 0; i < (int)ELEMENTSOF(invalid); i++) {
                bool c = valid_device_allow_pattern(invalid[i]);
                bool r = rs_valid_device_allow_pattern(invalid[i]);
                assert_se(c == r);
        }
}

static void test_valid_device_allow_pattern_null(void) {
        /* C has path_is_safe -> assert(p), so only test Rust */
        assert_se(!rs_valid_device_allow_pattern(NULL));
}

/* ── valid_device_node_path ───────────────────────────────────────── */

static void test_valid_device_node_path_valid(void) {
        const char *valid[] = {
                "eth0",
                "wlan0",
                "sda",
                "ttyUSB0",
                "loop0",
                "nvme0n1",
                "veth0",
        };
        for (int i = 0; i < (int)ELEMENTSOF(valid); i++) {
                bool c = valid_device_node_path(valid[i]);
                bool r = rs_valid_device_node_path(valid[i]);
                assert_se(c == r);
        }
}

static void test_valid_device_node_path_with_dir(void) {
        /* Paths with directory components should be invalid */
        const char *invalid[] = {
                "/dev/eth0",
                "../eth0",
                "subdir/eth0",
        };
        for (int i = 0; i < (int)ELEMENTSOF(invalid); i++) {
                bool c = valid_device_node_path(invalid[i]);
                bool r = rs_valid_device_node_path(invalid[i]);
                assert_se(c == r);
        }
}

static void test_valid_device_node_path_null(void) {
        assert_se(!rs_valid_device_node_path(NULL));
}

/* ── strv_find_closest_prefix ──────────────────────────────────────── */
/* C function is static; use strv_find_closest (public wrapper) for
 * comparison when a prefix match exists. */

static void test_strv_find_closest_prefix(void) {
        char *haystack[] = { (char *)"foo", (char *)"foobar", (char *)"foobaz", NULL };
        /* "fooba" is a prefix of "foobar" (suffix 3) and "foobaz" (suffix 3).
         * strv_find_closest returns the first shortest-suffix match = "foobar". */
        const char *c_result = strv_find_closest(haystack, "fooba");
        const char *r_result = rs_strv_find_closest_prefix(haystack, "fooba");
        assert_se(c_result && r_result);
        assert_se(streq(c_result, r_result));
        assert_se(streq(r_result, "foobar"));
}

static void test_strv_find_closest_prefix_exact(void) {
        char *haystack[] = { (char *)"foo", (char *)"bar", (char *)"baz", NULL };
        /* "foo" exact match → prefix "" length 0, returns "foo" */
        const char *c_result = strv_find_closest(haystack, "foo");
        const char *r_result = rs_strv_find_closest_prefix(haystack, "foo");
        assert_se(c_result && r_result);
        assert_se(streq(c_result, r_result));
        assert_se(streq(r_result, "foo"));
}

static void test_strv_find_closest_prefix_no_match(void) {
        /* No prefix match exists; C static fn returns NULL.
         * strv_find_closest falls through to levenshtein so can't compare. */
        char *haystack[] = { (char *)"abc", (char *)"def", NULL };
        const char *r_result = rs_strv_find_closest_prefix(haystack, "xyz");
        assert_se(r_result == NULL);
}

static void test_strv_find_closest_prefix_empty(void) {
        /* Empty haystack → NULL */
        char *haystack[] = { NULL };
        const char *c_result = strv_find_closest(haystack, "foo");
        const char *r_result = rs_strv_find_closest_prefix(haystack, "foo");
        assert_se(c_result == NULL);
        assert_se(r_result == NULL);
}

/* ── strv_find_closest_by_levenshtein ─────────────────────────────── */
/* C function is static; use strv_find_closest (public wrapper) for
 * comparison when NO prefix match exists (so it falls through to levenshtein). */

static void test_strv_find_closest_by_levenshtein(void) {
        char *haystack[] = { (char *)"systemd", (char *)"system", (char *)"networkd", NULL };
        /* "sytemd" has no prefix match; levenshtein: systemd=1, system=1, networkd=3.
         * Returns first with min distance = "systemd". */
        const char *c_result = strv_find_closest(haystack, "sytemd");
        const char *r_result = rs_strv_find_closest_by_levenshtein(haystack, "sytemd");
        assert_se(c_result && r_result);
        assert_se(streq(c_result, r_result));
        assert_se(streq(r_result, "systemd"));
}

static void test_strv_find_closest_by_levenshtein_typo(void) {
        char *haystack[] = { (char *)"hello", (char *)"world", (char *)"foo", NULL };
        /* "helo" has no prefix match; levenshtein: hello=1, world=4, foo=3.
         * Returns "hello". */
        const char *c_result = strv_find_closest(haystack, "helo");
        const char *r_result = rs_strv_find_closest_by_levenshtein(haystack, "helo");
        assert_se(c_result && r_result);
        assert_se(streq(c_result, r_result));
        assert_se(streq(r_result, "hello"));
}

static void test_strv_find_closest_by_levenshtein_empty(void) {
        /* Empty haystack → NULL */
        char *haystack[] = { NULL };
        const char *c_result = strv_find_closest(haystack, "foo");
        const char *r_result = rs_strv_find_closest_by_levenshtein(haystack, "foo");
        assert_se(c_result == NULL);
        assert_se(r_result == NULL);
}

/* ── strv_free_and_replace ─────────────────────────────────────────── */

static void test_strv_free_and_replace(void) {
        /* Both C macro and Rust function free the old array pointer, so we
         * must use heap-allocated arrays (strv_new), not stack arrays. */
        char **c_strv = strv_new("a", "b", NULL);
        char **r_strv = strv_new("x", "y", "z", NULL);
        char **c_new = NULL, **r_new = NULL;

        assert_se(c_strv && r_strv);

        /* C macro: both args must be lvalues (macro takes & of each) */
        c_new = strv_copy(r_strv);
        strv_free_and_replace(c_strv, c_new);
        r_new = strv_copy(c_strv);
        rs_strv_free_and_replace(&r_strv, &r_new);

        assert_se(c_strv);
        assert_se(r_strv);
        assert_se(c_new == NULL);
        assert_se(r_new == NULL);
        assert_se(strv_equal(c_strv, r_strv));
        assert_se(streq(c_strv[0], "x"));
        assert_se(streq(c_strv[1], "y"));
        assert_se(streq(c_strv[2], "z"));

        c_strv = strv_free(c_strv);
        r_strv = strv_free(r_strv);
}

static void test_strv_free_and_replace_null(void) {
        /* Both NULL: should be no-op */
        char **c_strv = NULL, **r_strv = NULL, **r_new = NULL;
        char **c_null = NULL;

        strv_free_and_replace(c_strv, c_null);
        rs_strv_free_and_replace(&r_strv, &r_new);

        assert_se(c_strv == NULL);
        assert_se(r_strv == NULL);
}

static void test_strv_free_and_replace_with_null(void) {
        char **c_strv = NULL, **r_strv = NULL;
        char **c_new = NULL, **r_new = NULL;

        r_strv = strv_new("a", NULL);

        c_new = strv_copy(r_strv);
        strv_free_and_replace(c_strv, c_new);
        rs_strv_free_and_replace(&r_strv, &r_new);

        assert_se(c_strv);
        assert_se(r_strv == NULL);
        assert_se(streq(c_strv[0], "a"));

        c_strv = strv_free(c_strv);
}

/* ── in6_addr_prefix_covers_full ───────────────────────────────────── */

static void test_in6_addr_prefix_covers_full_exact(void) {
        struct in6_addr c_prefix = {}, c_addr = {};
        struct rs_In6Addr r_prefix = {}, r_addr = {};

        /* 2001:db8::/32 covers 2001:db8::1 */
        inet_pton(AF_INET6, "2001:0db8::", &c_prefix);
        inet_pton(AF_INET6, "2001:0db8::1", &c_addr);
        memcpy(&r_prefix, &c_prefix, sizeof(c_prefix));
        memcpy(&r_addr, &c_addr, sizeof(c_addr));

        int c = in6_addr_prefix_covers_full(&c_prefix, 32, &c_addr, 128);
        int r = rs_in6_addr_prefix_covers_full((const struct rs_In6Addr *)&r_prefix, 32, (const struct rs_In6Addr *)&r_addr, 128);
        assert_se(c == r);
        assert_se(c > 0);
}

static void test_in6_addr_prefix_covers_full_different_prefix(void) {
        struct in6_addr c_prefix = {}, c_addr = {};
        struct rs_In6Addr r_prefix = {}, r_addr = {};

        /* 2001:db8::/32 does NOT cover 2001:db9::1 */
        inet_pton(AF_INET6, "2001:0db8::", &c_prefix);
        inet_pton(AF_INET6, "2001:0db9::1", &c_addr);
        memcpy(&r_prefix, &c_prefix, sizeof(c_prefix));
        memcpy(&r_addr, &c_addr, sizeof(c_addr));

        int c = in6_addr_prefix_covers_full(&c_prefix, 32, &c_addr, 128);
        int r = rs_in6_addr_prefix_covers_full((const struct rs_In6Addr *)&r_prefix, 32, (const struct rs_In6Addr *)&r_addr, 128);
        assert_se(c == r);
        assert_se(c == 0);
}

static void test_in6_addr_prefix_covers_full_shorter_address(void) {
        struct in6_addr c_prefix = {}, c_addr = {};
        struct rs_In6Addr r_prefix = {}, r_addr = {};

        /* 2001:db8::/32 covers 2001:db8::/64 (address prefixlen < prefix prefixlen) */
        inet_pton(AF_INET6, "2001:0db8::", &c_prefix);
        inet_pton(AF_INET6, "2001:0db8::", &c_addr);
        memcpy(&r_prefix, &c_prefix, sizeof(c_prefix));
        memcpy(&r_addr, &c_addr, sizeof(c_addr));

        int c = in6_addr_prefix_covers_full(&c_prefix, 32, &c_addr, 64);
        int r = rs_in6_addr_prefix_covers_full((const struct rs_In6Addr *)&r_prefix, 32, (const struct rs_In6Addr *)&r_addr, 64);
        assert_se(c == r);
        assert_se(c > 0);
}

/* ── safe_atolu_full ──────────────────────────────────────────────── */

static void test_safe_atolu_full_decimal(void) {
        unsigned long c_val = 0, r_val = 0;
        int c = safe_atolu_full("12345", 10, &c_val);
        int r = rs_safe_atolu_full("12345", 10, &r_val);
        assert_se(c == r);
        assert_se(c == 0);
        assert_se(c_val == r_val);
        assert_se(c_val == 12345);
}

static void test_safe_atolu_full_zero(void) {
        unsigned long c_val = 0, r_val = 0;
        int c = safe_atolu_full("0", 10, &c_val);
        int r = rs_safe_atolu_full("0", 10, &r_val);
        assert_se(c == r);
        assert_se(c == 0);
        assert_se(c_val == 0);
}

static void test_safe_atolu_full_hex(void) {
        unsigned long c_val = 0, r_val = 0;
        int c = safe_atolu_full("ff", 16, &c_val);
        int r = rs_safe_atolu_full("ff", 16, &r_val);
        assert_se(c == r);
        assert_se(c == 0);
        assert_se(c_val == 255);
}

static void test_safe_atolu_full_auto_base(void) {
        /* base=0 → auto-detect: 0x prefix for hex, 0 prefix for octal */
        unsigned long c_val = 0, r_val = 0;
        int c = safe_atolu_full("0xff", 0, &c_val);
        int r = rs_safe_atolu_full("0xff", 0, &r_val);
        assert_se(c == r);
        assert_se(c == 0);
        assert_se(c_val == 255);

        c = safe_atolu_full("0777", 0, &c_val);
        r = rs_safe_atolu_full("0777", 0, &r_val);
        assert_se(c == r);
        assert_se(c == 0);
        assert_se(c_val == 511);
}

static void test_safe_atolu_full_invalid(void) {
        unsigned long c_val = 0, r_val = 0;
        int c = safe_atolu_full("abc", 10, &c_val);
        int r = rs_safe_atolu_full("abc", 10, &r_val);
        assert_se(c == r);
        assert_se(c < 0);
}

static void test_safe_atolu_full_empty(void) {
        unsigned long c_val = 0, r_val = 0;
        int c = safe_atolu_full("", 10, &c_val);
        int r = rs_safe_atolu_full("", 10, &r_val);
        assert_se(c == r);
        assert_se(c < 0);
}

int main(int argc, char *argv[]) {
        test_path_is_absolute_null();
        test_path_is_absolute_absolute();
        test_path_is_absolute_relative();
        test_path_is_absolute_dot();
        test_path_is_normalized_valid();
        test_path_is_normalized_trailing_slash();
        test_path_is_normalized_dot();
        test_path_is_normalized_double_slash();
        test_path_is_normalized_dotdot();
        test_path_is_normalized_empty();
        test_valid_device_allow_pattern_valid();
        test_valid_device_allow_pattern_invalid();
        test_valid_device_allow_pattern_null();
        test_valid_device_node_path_valid();
        test_valid_device_node_path_with_dir();
        test_valid_device_node_path_null();
        test_strv_find_closest_prefix();
        test_strv_find_closest_prefix_exact();
        test_strv_find_closest_prefix_no_match();
        test_strv_find_closest_prefix_empty();
        test_strv_find_closest_by_levenshtein();
        test_strv_find_closest_by_levenshtein_typo();
        test_strv_find_closest_by_levenshtein_empty();
        test_strv_free_and_replace();
        test_strv_free_and_replace_null();
        test_strv_free_and_replace_with_null();
        test_in6_addr_prefix_covers_full_exact();
        test_in6_addr_prefix_covers_full_different_prefix();
        test_in6_addr_prefix_covers_full_shorter_address();
        test_safe_atolu_full_decimal();
        test_safe_atolu_full_zero();
        test_safe_atolu_full_hex();
        test_safe_atolu_full_auto_base();
        test_safe_atolu_full_invalid();
        test_safe_atolu_full_empty();
        return 0;
}
