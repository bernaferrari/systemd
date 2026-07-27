/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdlib.h>
#include <string.h>

#include "extract-word.h"
#include "tests.h"

/* Rust FFI */
#include "rust/extract_word.h"

/* ── extract_first_word: basic cases ─────────────────────────────────────── */

TEST(extract_first_word_simple) {
        const char *c_input = "hello world";
        const char *rs_input = "hello world";
        char *c_word = NULL, *rs_word = NULL;

        int cr = extract_first_word(&c_input, &c_word, NULL, 0);
        int rr = rs_extract_first_word(&rs_input, &rs_word, NULL, 0);
        assert_se(cr == rr && cr == 1);
        assert_se(streq(c_word, rs_word));
        assert_se(streq(c_word, "hello"));
        free(c_word);
        free(rs_word);

        /* Both pointers should now point past "hello " */
        assert_se(streq(c_input, rs_input));
        assert_se(streq(c_input, "world"));
}

TEST(extract_first_word_empty) {
        const char *c_input = "";
        const char *rs_input = "";
        char *c_word = NULL, *rs_word = NULL;

        int cr = extract_first_word(&c_input, &c_word, NULL, 0);
        int rr = rs_extract_first_word(&rs_input, &rs_word, NULL, 0);
        assert_se(cr == rr && cr == 0);
        assert_se(c_word == NULL);
        assert_se(rs_word == NULL);
        assert_se(c_input == NULL);
        assert_se(rs_input == NULL);
}

TEST(extract_first_word_null) {
        const char *c_input = NULL;
        const char *rs_input = NULL;
        char *c_word = NULL, *rs_word = NULL;

        int cr = extract_first_word(&c_input, &c_word, NULL, 0);
        int rr = rs_extract_first_word(&rs_input, &rs_word, NULL, 0);
        assert_se(cr == rr && cr == 0);
        assert_se(c_word == NULL);
        assert_se(rs_word == NULL);
}

TEST(extract_first_word_whitespace_only) {
        const char *c_input = "   \t\n";
        const char *rs_input = "   \t\n";
        char *c_word = NULL, *rs_word = NULL;

        int cr = extract_first_word(&c_input, &c_word, NULL, 0);
        int rr = rs_extract_first_word(&rs_input, &rs_word, NULL, 0);
        assert_se(cr == rr && cr == 0);
}

TEST(extract_first_word_leading_whitespace) {
        const char *c_input = "   hello";
        const char *rs_input = "   hello";
        char *c_word = NULL, *rs_word = NULL;

        int cr = extract_first_word(&c_input, &c_word, NULL, 0);
        int rr = rs_extract_first_word(&rs_input, &rs_word, NULL, 0);
        assert_se(cr == rr && cr == 1);
        assert_se(streq(c_word, rs_word));
        assert_se(streq(c_word, "hello"));
        free(c_word);
        free(rs_word);
}

TEST(extract_first_word_trailing_whitespace) {
        const char *c_input = "hello   ";
        const char *rs_input = "hello   ";
        char *c_word = NULL, *rs_word = NULL;

        int cr = extract_first_word(&c_input, &c_word, NULL, 0);
        int rr = rs_extract_first_word(&rs_input, &rs_word, NULL, 0);
        assert_se(cr == rr && cr == 1);
        assert_se(streq(c_word, rs_word));
        assert_se(streq(c_word, "hello"));
        free(c_word);
        free(rs_word);
}

/* ── extract_first_word: quoting ─────────────────────────────────────────── */

TEST(extract_first_word_double_quote) {
        const char *c_input = "\"hello world\" rest";
        const char *rs_input = "\"hello world\" rest";
        char *c_word = NULL, *rs_word = NULL;

        int cr = extract_first_word(&c_input, &c_word, NULL, EXTRACT_UNQUOTE);
        int rr = rs_extract_first_word(&rs_input, &rs_word, NULL, EXTRACT_UNQUOTE);
        assert_se(cr == rr && cr == 1);
        assert_se(streq(c_word, rs_word));
        assert_se(streq(c_word, "hello world"));
        free(c_word);
        free(rs_word);
}

TEST(extract_first_word_single_quote) {
        const char *c_input = "'hello world' rest";
        const char *rs_input = "'hello world' rest";
        char *c_word = NULL, *rs_word = NULL;

        int cr = extract_first_word(&c_input, &c_word, NULL, EXTRACT_UNQUOTE);
        int rr = rs_extract_first_word(&rs_input, &rs_word, NULL, EXTRACT_UNQUOTE);
        assert_se(cr == rr && cr == 1);
        assert_se(streq(c_word, rs_word));
        assert_se(streq(c_word, "hello world"));
        free(c_word);
        free(rs_word);
}

TEST(extract_first_word_keep_quote) {
        const char *c_input = "\"hello world\" rest";
        const char *rs_input = "\"hello world\" rest";
        char *c_word = NULL, *rs_word = NULL;

        int cr = extract_first_word(&c_input, &c_word, NULL, EXTRACT_KEEP_QUOTE);
        int rr = rs_extract_first_word(&rs_input, &rs_word, NULL, EXTRACT_KEEP_QUOTE);
        assert_se(cr == rr && cr == 1);
        assert_se(streq(c_word, rs_word));
        assert_se(streq(c_word, "\"hello world\""));
        free(c_word);
        free(rs_word);
}

TEST(extract_first_word_unbalanced_quote_relax) {
        const char *c_input = "\"hello world";
        const char *rs_input = "\"hello world";
        char *c_word = NULL, *rs_word = NULL;

        int cr = extract_first_word(&c_input, &c_word, NULL, EXTRACT_UNQUOTE | EXTRACT_RELAX);
        int rr = rs_extract_first_word(&rs_input, &rs_word, NULL, EXTRACT_UNQUOTE | EXTRACT_RELAX);
        assert_se(cr == rr && cr == 1);
        assert_se(streq(c_word, rs_word));
        assert_se(streq(c_word, "hello world"));
        free(c_word);
        free(rs_word);
        assert_se(c_input == NULL);
        assert_se(rs_input == NULL);
}

TEST(extract_first_word_unbalanced_quote_strict) {
        const char *c_input = "\"hello world";
        const char *rs_input = "\"hello world";
        char *c_word = NULL, *rs_word = NULL;

        int cr = extract_first_word(&c_input, &c_word, NULL, EXTRACT_UNQUOTE);
        int rr = rs_extract_first_word(&rs_input, &rs_word, NULL, EXTRACT_UNQUOTE);
        assert_se(cr == rr && cr == -EINVAL);
}

/* ── extract_first_word: escaping ────────────────────────────────────────── */

TEST(extract_first_word_backslash) {
        const char *c_input = "hello\\ world";
        const char *rs_input = "hello\\ world";
        char *c_word = NULL, *rs_word = NULL;

        int cr = extract_first_word(&c_input, &c_word, NULL, 0);
        int rr = rs_extract_first_word(&rs_input, &rs_word, NULL, 0);
        assert_se(cr == rr && cr == 1);
        assert_se(streq(c_word, rs_word));
        assert_se(streq(c_word, "hello world"));
        free(c_word);
        free(rs_word);
}

TEST(extract_first_word_cunescape) {
        const char *c_input = "hello\\nworld";
        const char *rs_input = "hello\\nworld";
        char *c_word = NULL, *rs_word = NULL;

        int cr = extract_first_word(&c_input, &c_word, NULL, EXTRACT_CUNESCAPE);
        int rr = rs_extract_first_word(&rs_input, &rs_word, NULL, EXTRACT_CUNESCAPE);
        assert_se(cr == rr && cr == 1);
        assert_se(streq(c_word, rs_word));
        /* \n becomes actual newline */
        assert_se(strlen(c_word) == 11);
        free(c_word);
        free(rs_word);
}

TEST(extract_first_word_retain_escape) {
        const char *c_input = "hello\\ world";
        const char *rs_input = "hello\\ world";
        char *c_word = NULL, *rs_word = NULL;

        int cr = extract_first_word(&c_input, &c_word, NULL, EXTRACT_RETAIN_ESCAPE);
        int rr = rs_extract_first_word(&rs_input, &rs_word, NULL, EXTRACT_RETAIN_ESCAPE);
        assert_se(cr == rr && cr == 1);
        assert_se(streq(c_word, rs_word));
        /* Backslash is treated as literal */
        assert_se(streq(c_word, "hello\\"));
        free(c_word);
        free(rs_word);
}

TEST(extract_first_word_trailing_backslash_relax) {
        const char *c_input = "hello\\";
        const char *rs_input = "hello\\";
        char *c_word = NULL, *rs_word = NULL;

        int cr = extract_first_word(&c_input, &c_word, NULL, EXTRACT_RELAX);
        int rr = rs_extract_first_word(&rs_input, &rs_word, NULL, EXTRACT_RELAX);
        assert_se(cr == rr && cr == 1);
        assert_se(streq(c_word, rs_word));
        free(c_word);
        free(rs_word);
}

TEST(extract_first_word_trailing_backslash_strict) {
        const char *c_input = "hello\\";
        const char *rs_input = "hello\\";
        char *c_word = NULL, *rs_word = NULL;

        int cr = extract_first_word(&c_input, &c_word, NULL, 0);
        int rr = rs_extract_first_word(&rs_input, &rs_word, NULL, 0);
        assert_se(cr == rr && cr == -EINVAL);
}

TEST(extract_first_word_unescape_relax) {
        const char *c_input = "hello\\zworld";
        const char *rs_input = "hello\\zworld";
        char *c_word = NULL, *rs_word = NULL;

        /* \z is not a valid escape; with UNESCAPE_RELAX it should be kept verbatim */
        int cr = extract_first_word(&c_input, &c_word, NULL, EXTRACT_CUNESCAPE | EXTRACT_UNESCAPE_RELAX);
        int rr = rs_extract_first_word(&rs_input, &rs_word, NULL, EXTRACT_CUNESCAPE | EXTRACT_UNESCAPE_RELAX);
        assert_se(cr == rr && cr == 1);
        assert_se(streq(c_word, rs_word));
        free(c_word);
        free(rs_word);
}

TEST(extract_first_word_unescape_invalid_strict) {
        const char *c_input = "hello\\zworld";
        const char *rs_input = "hello\\zworld";
        char *c_word = NULL, *rs_word = NULL;

        int cr = extract_first_word(&c_input, &c_word, NULL, EXTRACT_CUNESCAPE);
        int rr = rs_extract_first_word(&rs_input, &rs_word, NULL, EXTRACT_CUNESCAPE);
        assert_se(cr == rr && cr == -EINVAL);
}

/* ── extract_first_word: custom separators ───────────────────────────────── */

TEST(extract_first_word_custom_separators) {
        const char *c_input = "hello,world,rest";
        const char *rs_input = "hello,world,rest";
        char *c_word = NULL, *rs_word = NULL;

        int cr = extract_first_word(&c_input, &c_word, ",", 0);
        int rr = rs_extract_first_word(&rs_input, &rs_word, ",", 0);
        assert_se(cr == rr && cr == 1);
        assert_se(streq(c_word, rs_word));
        assert_se(streq(c_word, "hello"));
        free(c_word);
        free(rs_word);
}

/* ── extract_first_word: DONT_COALESCE_SEPARATORS ────────────────────────── */

TEST(extract_first_word_dont_coalesce) {
        const char *c_input = "  hello";
        const char *rs_input = "  hello";
        char *c_word = NULL, *rs_word = NULL;

        int cr = extract_first_word(&c_input, &c_word, NULL, EXTRACT_DONT_COALESCE_SEPARATORS);
        int rr = rs_extract_first_word(&rs_input, &rs_word, NULL, EXTRACT_DONT_COALESCE_SEPARATORS);
        assert_se(cr == rr && cr == 1);
        assert_se(streq(c_word, rs_word));
        assert_se(streq(c_word, ""));
        free(c_word);
        free(rs_word);
}

/* ── extract_first_word: multiple words sequentially ─────────────────────── */

TEST(extract_first_word_sequential) {
        const char *c_input = "one two three";
        const char *rs_input = "one two three";
        char *c_word = NULL, *rs_word = NULL;
        int cr, rr;

        cr = extract_first_word(&c_input, &c_word, NULL, 0);
        rr = rs_extract_first_word(&rs_input, &rs_word, NULL, 0);
        assert_se(cr == rr && cr == 1);
        assert_se(streq(c_word, rs_word) && streq(c_word, "one"));
        free(c_word); free(rs_word);

        cr = extract_first_word(&c_input, &c_word, NULL, 0);
        rr = rs_extract_first_word(&rs_input, &rs_word, NULL, 0);
        assert_se(cr == rr && cr == 1);
        assert_se(streq(c_word, rs_word) && streq(c_word, "two"));
        free(c_word); free(rs_word);

        cr = extract_first_word(&c_input, &c_word, NULL, 0);
        rr = rs_extract_first_word(&rs_input, &rs_word, NULL, 0);
        assert_se(cr == rr && cr == 1);
        assert_se(streq(c_word, rs_word) && streq(c_word, "three"));
        free(c_word); free(rs_word);

        cr = extract_first_word(&c_input, &c_word, NULL, 0);
        rr = rs_extract_first_word(&rs_input, &rs_word, NULL, 0);
        assert_se(cr == rr && cr == 0);
}

/* ── extract_first_word: quoted with escape ──────────────────────────────── */

TEST(extract_first_word_quoted_escape) {
        const char *c_input = "\"hello\\nworld\" rest";
        const char *rs_input = "\"hello\\nworld\" rest";
        char *c_word = NULL, *rs_word = NULL;

        int cr = extract_first_word(&c_input, &c_word, NULL, EXTRACT_CUNESCAPE | EXTRACT_UNQUOTE);
        int rr = rs_extract_first_word(&rs_input, &rs_word, NULL, EXTRACT_CUNESCAPE | EXTRACT_UNQUOTE);
        assert_se(cr == rr && cr == 1);
        assert_se(streq(c_word, rs_word));
        assert_se(strlen(c_word) == 11); /* "hello\nworld" with actual newline */
        free(c_word);
        free(rs_word);
}

TEST(extract_first_word_empty_quotes) {
        const char *c_input = "\"\" rest";
        const char *rs_input = "\"\" rest";
        char *c_word = NULL, *rs_word = NULL;

        int cr = extract_first_word(&c_input, &c_word, NULL, EXTRACT_UNQUOTE);
        int rr = rs_extract_first_word(&rs_input, &rs_word, NULL, EXTRACT_UNQUOTE);
        assert_se(cr == rr && cr == 1);
        assert_se(streq(c_word, rs_word));
        assert_se(streq(c_word, ""));
        free(c_word);
        free(rs_word);
}

/* ── main ────────────────────────────────────────────────────────────────── */

DEFINE_TEST_MAIN(LOG_INFO);
