/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Shadow test: C bus-label vs Rust rs_bus_label */

#include <string.h>
#include <stdlib.h>

#include "bus-label.h"
#include "string-util.h"
#include "rust/bus_label.h"

/* ── bus_label_escape ──────────────────────────────────────────────────── */

static void test_bus_label_escape_empty(void) {
        char *c_ret = bus_label_escape("");
        char *r_ret = rs_bus_label_escape("");
        assert_se(c_ret != NULL);
        assert_se(r_ret != NULL);
        assert_se(streq(c_ret, "_"));
        assert_se(streq(r_ret, "_"));
        free(c_ret);
        free(r_ret);
}

static void test_bus_label_escape_simple(void) {
        char *c_ret = bus_label_escape("hello");
        char *r_ret = rs_bus_label_escape("hello");
        assert_se(c_ret != NULL);
        assert_se(r_ret != NULL);
        assert_se(streq(c_ret, r_ret));
        assert_se(streq(c_ret, "hello"));
        free(c_ret);
        free(r_ret);
}

static void test_bus_label_escape_digits_first(void) {
        /* Digits at start must be escaped */
        char *c_ret = bus_label_escape("123abc");
        char *r_ret = rs_bus_label_escape("123abc");
        assert_se(c_ret != NULL);
        assert_se(r_ret != NULL);
        assert_se(streq(c_ret, r_ret));
        /* '1' → '_31', '2' → '_32', '3' → '_33', 'abc' stays */
        free(c_ret);
        free(r_ret);
}

static void test_bus_label_escape_special(void) {
        /* Special chars must be escaped */
        char *c_ret = bus_label_escape("foo_bar.baz");
        char *r_ret = rs_bus_label_escape("foo_bar.baz");
        assert_se(c_ret != NULL);
        assert_se(r_ret != NULL);
        assert_se(streq(c_ret, r_ret));
        free(c_ret);
        free(r_ret);
}

static void test_bus_label_escape_unicode(void) {
        /* Non-ASCII bytes should be escaped */
        char input[] = { 'a', 0xc3, 0xa9, 0 }; /* a + é in UTF-8 */
        char *c_ret = bus_label_escape(input);
        char *r_ret = rs_bus_label_escape(input);
        assert_se(c_ret != NULL);
        assert_se(r_ret != NULL);
        assert_se(streq(c_ret, r_ret));
        assert_se(strlen(c_ret) > strlen(input)); /* Should be longer due to escaping */
        free(c_ret);
        free(r_ret);
}

static void test_bus_label_escape_leading_digit(void) {
        char *c_ret = bus_label_escape("0abc");
        char *r_ret = rs_bus_label_escape("0abc");
        assert_se(c_ret != NULL);
        assert_se(r_ret != NULL);
        assert_se(streq(c_ret, r_ret));
        /* '0' at position 0 gets escaped */
        assert_se(streq(c_ret, "_30abc"));
        free(c_ret);
        free(r_ret);
}

static void test_bus_label_escape_roundtrip(void) {
        /* Escape then unescape should return original */
        const char *test = "org_freedesktop_systemd1";
        char *escaped = rs_bus_label_escape(test);
        assert_se(escaped != NULL);

        char *unescaped = bus_label_unescape_n(escaped, SIZE_MAX);
        assert_se(unescaped != NULL);
        assert_se(streq(unescaped, test));

        free(escaped);
        free(unescaped);
}

/* ── bus_label_unescape_n ──────────────────────────────────────────────── */

static void test_bus_label_unescape_empty(void) {
        /* "_" → "" */
        char *c_ret = bus_label_unescape_n("_", 1);
        char *r_ret = rs_bus_label_unescape_n("_", 1);
        assert_se(c_ret != NULL);
        assert_se(r_ret != NULL);
        assert_se(streq(c_ret, ""));
        assert_se(streq(r_ret, ""));
        free(c_ret);
        free(r_ret);
}

static void test_bus_label_unescape_simple(void) {
        char *c_ret = bus_label_unescape_n("hello", 5);
        char *r_ret = rs_bus_label_unescape_n("hello", 5);
        assert_se(c_ret != NULL);
        assert_se(r_ret != NULL);
        assert_se(streq(c_ret, "hello"));
        assert_se(streq(r_ret, "hello"));
        free(c_ret);
        free(r_ret);
}

static void test_bus_label_unescape_hex(void) {
        /* '_2f' → '/' */
        char *c_ret = bus_label_unescape_n("_2f", 3);
        char *r_ret = rs_bus_label_unescape_n("_2f", 3);
        assert_se(c_ret != NULL);
        assert_se(r_ret != NULL);
        assert_se(streq(c_ret, "/"));
        assert_se(streq(r_ret, "/"));
        free(c_ret);
        free(r_ret);
}

static void test_bus_label_unescape_invalid_escape(void) {
        /* '_xz' → '_xz' (invalid hex, taken literal) */
        char *c_ret = bus_label_unescape_n("_xz", 3);
        char *r_ret = rs_bus_label_unescape_n("_xz", 3);
        assert_se(c_ret != NULL);
        assert_se(r_ret != NULL);
        assert_se(streq(c_ret, r_ret));
        free(c_ret);
        free(r_ret);
}

static void test_bus_label_unescape_truncated_escape(void) {
        /* '_' alone → '_' */
        char *c_ret = bus_label_unescape_n("_", 1);
        char *r_ret = rs_bus_label_unescape_n("_", 1);
        assert_se(c_ret != NULL);
        assert_se(r_ret != NULL);
        assert_se(streq(c_ret, ""));
        assert_se(streq(r_ret, ""));
        free(c_ret);
        free(r_ret);
}

static void test_bus_label_unescape_truncated_escape2(void) {
        /* '_2' (only 2 chars after _) → '_2' literal */
        char *c_ret = bus_label_unescape_n("_2", 2);
        char *r_ret = rs_bus_label_unescape_n("_2", 2);
        assert_se(c_ret != NULL);
        assert_se(r_ret != NULL);
        assert_se(streq(c_ret, r_ret));
        free(c_ret);
        free(r_ret);
}

static void test_bus_label_unescape_mixed(void) {
        /* 'foo_2fbar_5f' → 'foo/bar_' */
        char *c_ret = bus_label_unescape_n("foo_2fbar_5f", 12);
        char *r_ret = rs_bus_label_unescape_n("foo_2fbar_5f", 12);
        assert_se(c_ret != NULL);
        assert_se(r_ret != NULL);
        assert_se(streq(c_ret, "foo/bar_"));
        assert_se(streq(r_ret, "foo/bar_"));
        free(c_ret);
        free(r_ret);
}

/* ── Main ───────────────────────────────────────────────────────────────── */

int main(int argc, char **argv) {
        test_bus_label_escape_empty();
        test_bus_label_escape_simple();
        test_bus_label_escape_digits_first();
        test_bus_label_escape_special();
        test_bus_label_escape_unicode();
        test_bus_label_escape_leading_digit();
        test_bus_label_escape_roundtrip();

        test_bus_label_unescape_empty();
        test_bus_label_unescape_simple();
        test_bus_label_unescape_hex();
        test_bus_label_unescape_invalid_escape();
        test_bus_label_unescape_truncated_escape();
        test_bus_label_unescape_truncated_escape2();
        test_bus_label_unescape_mixed();

        return 0;
}
