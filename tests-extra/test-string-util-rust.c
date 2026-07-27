/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdlib.h>
#include <string.h>

#include "json-util.h"
#include "string-util.h"
#include "tests.h"

/* Rust FFI */
#include "rust/string_util.h"

/* ── ascii_tolower / ascii_toupper ───────────────────────────────────────── */

TEST(ascii_tolower) {
        for (char c = 'A'; c <= 'Z'; c++) {
                assert_se(ascii_tolower(c) == rs_ascii_tolower(c));
                assert_se(ascii_tolower(c) == (char)(c + 32));
        }
        for (char c = 'a'; c <= 'z'; c++) {
                assert_se(ascii_tolower(c) == rs_ascii_tolower(c));
                assert_se(ascii_tolower(c) == c);
        }
        assert_se(ascii_tolower('0') == rs_ascii_tolower('0'));
        assert_se(ascii_tolower(' ') == rs_ascii_tolower(' '));
}

TEST(ascii_toupper) {
        for (char c = 'a'; c <= 'z'; c++) {
                assert_se(ascii_toupper(c) == rs_ascii_toupper(c));
                assert_se(ascii_toupper(c) == (char)(c - 32));
        }
        for (char c = 'A'; c <= 'Z'; c++) {
                assert_se(ascii_toupper(c) == rs_ascii_toupper(c));
                assert_se(ascii_toupper(c) == c);
        }
        assert_se(ascii_toupper('0') == rs_ascii_toupper('0'));
}

/* ── ascii_strcasecmp_n ──────────────────────────────────────────────────── */

TEST(ascii_strcasecmp_n_equal) {
        assert_se(ascii_strcasecmp_n("Hello", "HELLO", 5) == rs_ascii_strcasecmp_n("Hello", "HELLO", 5));
        assert_se(ascii_strcasecmp_n("Hello", "HELLO", 5) == 0);
}

TEST(ascii_strcasecmp_n_prefix) {
        assert_se(ascii_strcasecmp_n("HelloWorld", "HELLO", 5) == rs_ascii_strcasecmp_n("HelloWorld", "HELLO", 5));
        assert_se(ascii_strcasecmp_n("HelloWorld", "HELLO", 5) == 0);
}

TEST(ascii_strcasecmp_n_different) {
        assert_se(ascii_strcasecmp_n("abc", "abd", 3) == rs_ascii_strcasecmp_n("abc", "abd", 3));
        assert_se(ascii_strcasecmp_n("abc", "abd", 3) < 0);
}

TEST(ascii_strcasecmp_n_empty) {
        assert_se(ascii_strcasecmp_n("", "", 0) == rs_ascii_strcasecmp_n("", "", 0));
        assert_se(ascii_strcasecmp_n("", "", 0) == 0);
}

/* ── ascii_strcasecmp_nn ─────────────────────────────────────────────────── */

TEST(ascii_strcasecmp_nn_equal) {
        assert_se(ascii_strcasecmp_nn("hello", 5, "HELLO", 5) == rs_ascii_strcasecmp_nn("hello", 5, "HELLO", 5));
        assert_se(ascii_strcasecmp_nn("hello", 5, "HELLO", 5) == 0);
}

TEST(ascii_strcasecmp_nn_different_len) {
        assert_se(ascii_strcasecmp_nn("abc", 3, "abcd", 4) == rs_ascii_strcasecmp_nn("abc", 3, "abcd", 4));
        assert_se(ascii_strcasecmp_nn("abc", 3, "abcd", 4) < 0);
}

/* ── chars_intersect ─────────────────────────────────────────────────────── */

TEST(chars_intersect_yes) {
        assert_se(chars_intersect("abc", "x") == rs_chars_intersect("abc", "x"));
        assert_se(chars_intersect("abc", "x") == false);
        assert_se(chars_intersect("hello", "z") == rs_chars_intersect("hello", "z"));
        assert_se(chars_intersect("abc", "c") == rs_chars_intersect("abc", "c"));
        assert_se(chars_intersect("abc", "c") == true);
}

TEST(chars_intersect_no) {
        assert_se(chars_intersect("abc", "xyz") == rs_chars_intersect("abc", "xyz"));
        assert_se(chars_intersect("abc", "xyz") == false);
}

/* ── string_has_cc ───────────────────────────────────────────────────────── */

TEST(string_has_cc_clean) {
        assert_se(string_has_cc("hello world", NULL) == rs_string_has_cc("hello world", NULL));
        assert_se(string_has_cc("hello world", NULL) == false);
}

TEST(string_has_cc_control) {
        assert_se(string_has_cc("hello\x01world", NULL) == rs_string_has_cc("hello\x01world", NULL));
        assert_se(string_has_cc("hello\x01world", NULL) == true);
}

TEST(string_has_cc_tab) {
        /* Tab, newline are control chars — string_has_cc returns true */
        assert_se(string_has_cc("hello\tworld\n", NULL) == rs_string_has_cc("hello\tworld\n", NULL));
        assert_se(string_has_cc("hello\tworld\n", NULL) == true);
}

TEST(string_has_cc_with_ok) {
        assert_se(string_has_cc("hello\x01world", "\x01") == rs_string_has_cc("hello\x01world", "\x01"));
        assert_se(string_has_cc("hello\x01world", "\x01") == false);

        /* The exemption applies to DEL just like every other control byte. */
        assert_se(string_has_cc("hello\x7fworld", "\x7f") == rs_string_has_cc("hello\x7fworld", "\x7f"));
        assert_se(string_has_cc("hello\x7fworld", "\x7f") == false);
}

/* ── strdup_to_full ──────────────────────────────────────────────────────── */

TEST(strdup_to_full_normal) {
        char *c_ret = NULL, *rs_ret = NULL;
        int cr = strdup_to_full(&c_ret, "hello");
        int rr = rs_strdup_to_full(&rs_ret, "hello");
        assert_se(cr == rr && cr == 1);
        assert_se(streq(c_ret, rs_ret));
        assert_se(streq(c_ret, "hello"));
        free(c_ret); free(rs_ret);
}

TEST(strdup_to_full_null) {
        char *c_ret = (char*)1, *rs_ret = (char*)1;
        int cr = strdup_to_full(&c_ret, NULL);
        int rr = rs_strdup_to_full(&rs_ret, NULL);
        assert_se(cr == rr && cr == 0);
        assert_se(c_ret == NULL);
        assert_se(rs_ret == NULL);
}

TEST(strdup_to_full_optional_output) {
        assert_se(strdup_to_full(NULL, "hello") == rs_strdup_to_full(NULL, "hello"));
        assert_se(rs_strdup_to_full(NULL, "hello") == 1);
}

/* ── free_and_strdup ─────────────────────────────────────────────────────── */

TEST(free_and_strdup_normal) {
        char *c_p = strdup("old");
        char *rs_p = strdup("old");
        int cr = free_and_strdup(&c_p, "new");
        int rr = rs_free_and_strdup(&rs_p, "new");
        assert_se(cr == rr && cr == 1);
        assert_se(streq(c_p, rs_p));
        assert_se(streq(c_p, "new"));
        free(c_p); free(rs_p);
}

TEST(free_and_strdup_null_src) {
        char *c_p = strdup("old");
        char *rs_p = strdup("old");
        int cr = free_and_strdup(&c_p, NULL);
        int rr = rs_free_and_strdup(&rs_p, NULL);
        assert_se(cr == rr && cr == 1);
        assert_se(c_p == NULL);
        assert_se(rs_p == NULL);
}

TEST(free_and_strdup_same_content_preserves_allocation) {
        char *c_p = strdup("same");
        char *rs_p = strdup("same");
        char *c_before = c_p;
        char *rs_before = rs_p;

        assert_se(c_p && rs_p);
        assert_se(free_and_strdup(&c_p, "same") == rs_free_and_strdup(&rs_p, "same"));
        assert_se(c_p == c_before);
        assert_se(rs_p == rs_before);
        free(c_p);
        free(rs_p);
}

TEST(free_and_strdup_alias_source) {
        char *c_p = strdup("same");
        char *rs_p = strdup("same");

        assert_se(c_p && rs_p);
        assert_se(free_and_strdup(&c_p, c_p) == rs_free_and_strdup(&rs_p, rs_p));
        ASSERT_STREQ(c_p, rs_p);
        free(c_p);
        free(rs_p);
}

/* ── split_pair ──────────────────────────────────────────────────────────── */

TEST(split_pair_simple) {
        char *c_a = NULL, *c_b = NULL, *rs_a = NULL, *rs_b = NULL;
        int cr = split_pair("hello=world", "=", &c_a, &c_b);
        int rr = rs_split_pair("hello=world", "=", &rs_a, &rs_b);
        assert_se(cr == rr && cr == 0);
        assert_se(streq(c_a, rs_a) && streq(c_a, "hello"));
        assert_se(streq(c_b, rs_b) && streq(c_b, "world"));
        free(c_a); free(c_b); free(rs_a); free(rs_b);
}

TEST(split_pair_no_sep) {
        char *a = NULL, *b = NULL;
        int r = rs_split_pair("hello", "=", &a, &b);
        assert_se(r == -EINVAL);
}

TEST(split_pair_multi_sep) {
        char *a = NULL, *b = NULL;
        int r = rs_split_pair("hello", "==", &a, &b);
        assert_se(r == -EINVAL);
}

TEST(split_pair_optional_output) {
        char *c_second = NULL, *rs_second = NULL;

        assert_se(split_pair("first==second", "==", NULL, &c_second) ==
                  rs_split_pair("first==second", "==", NULL, &rs_second));
        ASSERT_STREQ(c_second, rs_second);
        ASSERT_STREQ(c_second, "second");
        free(c_second);
        free(rs_second);
}

/* ── str_common_prefix ───────────────────────────────────────────────────── */

TEST(str_common_prefix_simple) {
        size_t cr = str_common_prefix("hello", "help");
        size_t rr = rs_str_common_prefix("hello", "help");
        assert_se(cr == rr);
        assert_se(cr == 3);
}

TEST(str_common_prefix_none) {
        assert_se(str_common_prefix("abc", "xyz") == rs_str_common_prefix("abc", "xyz"));
        assert_se(str_common_prefix("abc", "xyz") == 0);
}

TEST(str_common_prefix_identical) {
        assert_se(str_common_prefix("hello", "hello") == rs_str_common_prefix("hello", "hello"));
        assert_se(str_common_prefix("hello", "hello") == SIZE_MAX);
}

TEST(str_common_prefix_prefix) {
        assert_se(str_common_prefix("hel", "hello") == rs_str_common_prefix("hel", "hello"));
        assert_se(str_common_prefix("hel", "hello") == 3);
}

/* ── strspn_from_end ─────────────────────────────────────────────────────── */

TEST(strspn_from_end_trailing) {
        assert_se(strspn_from_end("hello   ", " ") == rs_strspn_from_end("hello   ", " "));
        assert_se(strspn_from_end("hello   ", " ") == 3);
}

TEST(strspn_from_end_no_match) {
        assert_se(strspn_from_end("hello", " ") == rs_strspn_from_end("hello", " "));
        assert_se(strspn_from_end("hello", " ") == 0);
}

TEST(strspn_from_end_all) {
        assert_se(strspn_from_end("   ", " ") == rs_strspn_from_end("   ", " "));
        assert_se(strspn_from_end("   ", " ") == 3);
}

TEST(strspn_from_end_mixed) {
        assert_se(strspn_from_end("hello!!!", "!") == rs_strspn_from_end("hello!!!", "!"));
        assert_se(strspn_from_end("hello!!!", "!") == 3);
}

/* ── streq_skip_trailing_chars ───────────────────────────────────────────── */

TEST(streq_skip_trailing_chars_none) {
        assert_se(streq_skip_trailing_chars("hello", "hello", ".") ==
                  rs_streq_skip_trailing_chars("hello", "hello", "."));
        assert_se(streq_skip_trailing_chars("hello", "hello", ".") == true);
}

TEST(streq_skip_trailing_chars_skip) {
        assert_se(streq_skip_trailing_chars("hello", "hello...", ".") ==
                  rs_streq_skip_trailing_chars("hello", "hello...", "."));
        assert_se(streq_skip_trailing_chars("hello", "hello...", ".") == true);
}

TEST(streq_skip_trailing_chars_mismatch) {
        assert_se(streq_skip_trailing_chars("hello", "world", ".") ==
                  rs_streq_skip_trailing_chars("hello", "world", "."));
        assert_se(streq_skip_trailing_chars("hello", "world", ".") == false);
}

/* ── strdupspn ─────────────────────────────────────────────────────────── */

TEST(strdupspn_c_vs_rs) {
        _cleanup_free_ char *c_ret = strdupspn("hello world", "helo ");
        _cleanup_free_ char *rs_ret = rs_strdupspn("hello world", "helo ");
        assert_se(c_ret);
        assert_se(rs_ret);
        ASSERT_STREQ(c_ret, rs_ret);
        ASSERT_STREQ(c_ret, "hello ");
}

TEST(strdupspn_empty) {
        _cleanup_free_ char *c_ret = strdupspn("", "abc");
        _cleanup_free_ char *rs_ret = rs_strdupspn("", "abc");
        assert_se(c_ret);
        assert_se(rs_ret);
        ASSERT_STREQ(c_ret, rs_ret);
}

TEST(strdupspn_no_match) {
        _cleanup_free_ char *c_ret = strdupspn("hello", "xyz");
        _cleanup_free_ char *rs_ret = rs_strdupspn("hello", "xyz");
        assert_se(c_ret);
        assert_se(rs_ret);
        ASSERT_STREQ(c_ret, rs_ret);
        ASSERT_STREQ(c_ret, "");
}

/* ── strdupcspn ────────────────────────────────────────────────────────── */

TEST(strdupcspn_c_vs_rs) {
        _cleanup_free_ char *c_ret = strdupcspn("hello world", " w");
        _cleanup_free_ char *rs_ret = rs_strdupcspn("hello world", " w");
        assert_se(c_ret);
        assert_se(rs_ret);
        ASSERT_STREQ(c_ret, rs_ret);
        ASSERT_STREQ(c_ret, "hello");
}

TEST(strdupcspn_empty_input) {
        _cleanup_free_ char *c_ret = strdupcspn("", "abc");
        _cleanup_free_ char *rs_ret = rs_strdupcspn("", "abc");
        assert_se(c_ret);
        assert_se(rs_ret);
        ASSERT_STREQ(c_ret, rs_ret);
        ASSERT_STREQ(c_ret, "");
}

TEST(strdupcspn_empty_reject) {
        _cleanup_free_ char *c_ret = strdupcspn("hello", "");
        _cleanup_free_ char *rs_ret = rs_strdupcspn("hello", "");
        assert_se(c_ret);
        assert_se(rs_ret);
        ASSERT_STREQ(c_ret, rs_ret);
        ASSERT_STREQ(c_ret, "hello");
}

TEST(strdupcspn_no_match) {
        _cleanup_free_ char *c_ret = strdupcspn("hello", "xyz");
        _cleanup_free_ char *rs_ret = rs_strdupcspn("hello", "xyz");
        assert_se(c_ret);
        assert_se(rs_ret);
        ASSERT_STREQ(c_ret, rs_ret);
        ASSERT_STREQ(c_ret, "hello");
}

/* ── string_replace_char ───────────────────────────────────────────────── */

TEST(string_replace_char_c_vs_rs) {
        char c_buf[] = "hello world";
        char rs_buf[] = "hello world";

        assert_se(string_replace_char(c_buf, 'o', '0') == c_buf);
        assert_se(rs_string_replace_char(rs_buf, 'o', '0') == rs_buf);
        assert_se(streq(c_buf, rs_buf));
        assert_se(streq(c_buf, "hell0 w0rld"));
}

TEST(string_replace_char_no_match) {
        char c_buf[] = "hello";
        char rs_buf[] = "hello";

        string_replace_char(c_buf, 'x', 'y');
        rs_string_replace_char(rs_buf, 'x', 'y');

        assert_se(streq(c_buf, rs_buf));
        assert_se(streq(c_buf, "hello"));
}

/* ── strreplace ─────────────────────────────────────────────────────────── */

TEST(strreplace_c_vs_rs) {
        _cleanup_free_ char *c_ret = strreplace("one-two-one", "one", "1");
        _cleanup_free_ char *rs_ret = rs_strreplace("one-two-one", "one", "1");

        assert_se(c_ret);
        assert_se(rs_ret);
        ASSERT_STREQ(c_ret, rs_ret);
        ASSERT_STREQ(c_ret, "1-two-1");
}

TEST(strreplace_null_text) {
        assert_se(strreplace(NULL, "one", "1") == NULL);
        assert_se(rs_strreplace(NULL, "one", "1") == NULL);
}

/* ── JSON separator normalization ───────────────────────────────────────── */

TEST(json_underscorify_c_vs_rs) {
        char c_buf[] = "one-two+three_four";
        char rs_buf[] = "one-two+three_four";

        assert_se(json_underscorify(c_buf) == c_buf);
        assert_se(rs_json_underscorify(rs_buf) == rs_buf);
        ASSERT_STREQ(c_buf, rs_buf);
        ASSERT_STREQ(c_buf, "one_two_three_four");
}

TEST(json_dashify_c_vs_rs) {
        char c_buf[] = "one-two+three_four";
        char rs_buf[] = "one-two+three_four";

        assert_se(json_dashify(c_buf) == c_buf);
        assert_se(rs_json_dashify(rs_buf) == rs_buf);
        ASSERT_STREQ(c_buf, rs_buf);
        ASSERT_STREQ(c_buf, "one-two-three-four");
}

/* ── in_charset / strgrowpad0 ────────────────────────────────────────────── */

TEST(in_charset_c_vs_rs) {
        assert_se(in_charset("abc", "cba") == rs_in_charset("abc", "cba"));
        assert_se(in_charset("abcd", "cba") == rs_in_charset("abcd", "cba"));
        assert_se(rs_in_charset("abc", "cba"));
        assert_se(!rs_in_charset("abcd", "cba"));
}

TEST(strgrowpad0_c_vs_rs) {
        _cleanup_free_ char *c_buf = strdup("abc");
        _cleanup_free_ char *rs_buf = strdup("abc");

        assert_se(c_buf && rs_buf);
        assert_se(strgrowpad0(&c_buf, 8) == rs_strgrowpad0(&rs_buf, 8));
        ASSERT_STREQ(c_buf, rs_buf);
        assert_se(memcmp(c_buf + 4, rs_buf + 4, 4) == 0);
        assert_se(memcmp(c_buf + 4, "\0\0\0\0", 4) == 0);
}

/* ── main ────────────────────────────────────────────────────────────────── */

DEFINE_TEST_MAIN(LOG_INFO);
