/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* RUST-CONTRACT: nulstr-get */
/* RUST-CONTRACT: strv-parse-nulstr-full */

#include <string.h>

#include "nulstr-util.h"
#include "strv.h"
#include "tests.h"

/* Rust FFI */
#include "rust/nulstr_util.h"

/* ── nulstr_get ─────────────────────────────────────────────────────────── */

/* A NULSTR is a sequence of NUL-terminated strings, terminated by an empty string (double NUL) */
static const char test_nulstr[] = "one\0two\0three\0four\0\0";

TEST(nulstr_get_found) {
        const char *cr = nulstr_get(test_nulstr, "two");
        const char *rr = rs_nulstr_get(test_nulstr, "two");
        assert_se(cr != NULL);
        assert_se(rr != NULL);
        assert_se(cr == rr);
}

TEST(nulstr_get_first) {
        const char *cr = nulstr_get(test_nulstr, "one");
        const char *rr = rs_nulstr_get(test_nulstr, "one");
        assert_se(cr != NULL);
        assert_se(rr != NULL);
        assert_se(cr == rr);
}

TEST(nulstr_get_last) {
        const char *cr = nulstr_get(test_nulstr, "four");
        const char *rr = rs_nulstr_get(test_nulstr, "four");
        assert_se(cr != NULL);
        assert_se(rr != NULL);
        assert_se(cr == rr);
}

TEST(nulstr_get_not_found) {
        const char *cr = nulstr_get(test_nulstr, "five");
        const char *rr = rs_nulstr_get(test_nulstr, "five");
        assert_se(cr == NULL);
        assert_se(rr == NULL);
}

TEST(nulstr_get_null) {
        const char *cr = nulstr_get(NULL, "one");
        const char *rr = rs_nulstr_get(NULL, "one");
        assert_se(cr == NULL);
        assert_se(rr == NULL);
}

TEST(nulstr_get_empty_needle) {
        /* Empty string is the terminator — should not be found */
        const char *cr = nulstr_get(test_nulstr, "");
        const char *rr = rs_nulstr_get(test_nulstr, "");
        assert_se(cr == NULL);
        assert_se(rr == NULL);
}

/* ── strv_parse_nulstr_full ────────────────────────────────────────────── */

TEST(strv_parse_nulstr_full_basic) {
        /* "a\0b\0c\0" — three strings */
        const char data[] = "alpha\0bravo\0charlie\0";
        char **cr = strv_parse_nulstr_full(data, sizeof(data) - 1, false);
        char **rr = rs_strv_parse_nulstr_full(data, sizeof(data) - 1, false);
        assert_se(cr != NULL);
        assert_se(rr != NULL);
        assert_se(streq(cr[0], rr[0]));
        assert_se(streq(cr[1], rr[1]));
        assert_se(streq(cr[2], rr[2]));
        assert_se(cr[3] == NULL);
        assert_se(rr[3] == NULL);
        strv_free(cr);
        strv_free(rr);
}

TEST(strv_parse_nulstr_full_empty) {
        char **cr = strv_parse_nulstr_full("", 0, false);
        char **rr = rs_strv_parse_nulstr_full("", 0, false);
        assert_se(cr != NULL);
        assert_se(rr != NULL);
        assert_se(cr[0] == NULL);
        assert_se(rr[0] == NULL);
        strv_free(cr);
        strv_free(rr);
}

TEST(strv_parse_nulstr_full_trailing_nuls) {
        /* "a\0\0\0" — with drop_trailing_nuls, should become just "a" */
        const char data[] = "alpha\0\0\0";
        char **cr = strv_parse_nulstr_full(data, sizeof(data) - 1, true);
        char **rr = rs_strv_parse_nulstr_full(data, sizeof(data) - 1, true);
        assert_se(cr != NULL);
        assert_se(rr != NULL);
        assert_se(streq(cr[0], rr[0]));
        assert_se(streq(cr[0], "alpha"));
        assert_se(cr[1] == NULL);
        assert_se(rr[1] == NULL);
        strv_free(cr);
        strv_free(rr);
}

TEST(strv_parse_nulstr_full_no_trailing_nul) {
        /* "a\0b" — last entry doesn't end with NUL */
        const char data[] = { 'a', 0, 'b' };
        char **cr = strv_parse_nulstr_full(data, sizeof(data), false);
        char **rr = rs_strv_parse_nulstr_full(data, sizeof(data), false);
        assert_se(cr != NULL);
        assert_se(rr != NULL);
        assert_se(streq(cr[0], rr[0]));
        assert_se(streq(cr[0], "a"));
        assert_se(streq(cr[1], rr[1]));
        assert_se(streq(cr[1], "b"));
        assert_se(cr[2] == NULL);
        assert_se(rr[2] == NULL);
        strv_free(cr);
        strv_free(rr);
}

TEST(strv_parse_nulstr_full_single) {
        const char data[] = "hello\0";
        char **cr = strv_parse_nulstr_full(data, sizeof(data) - 1, false);
        char **rr = rs_strv_parse_nulstr_full(data, sizeof(data) - 1, false);
        assert_se(cr != NULL);
        assert_se(rr != NULL);
        assert_se(streq(cr[0], "hello"));
        assert_se(streq(rr[0], "hello"));
        assert_se(cr[1] == NULL);
        assert_se(rr[1] == NULL);
        strv_free(cr);
        strv_free(rr);
}

/* ── main ────────────────────────────────────────────────────────────────── */

DEFINE_TEST_MAIN(LOG_INFO);
