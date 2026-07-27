/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdlib.h>
#include <string.h>

#include "escape.h"
#include "tests.h"

/* Rust FFI */
#include "rust/escape.h"

/* ── cescape_char ────────────────────────────────────────────────────────── */

TEST(cescape_char_simple) {
        char c_buf[4], rs_buf[4];
        const char *test_chars = "abcxyz";

        for (int i = 0; test_chars[i]; i++) {
                int cl = cescape_char(test_chars[i], c_buf);
                int rl = rs_cescape_char(test_chars[i], rs_buf);
                assert_se(cl == rl);
                assert_se(cl == 1);
                assert_se(memcmp(c_buf, rs_buf, cl) == 0);
        }
}

TEST(cescape_char_control) {
        char c_buf[4], rs_buf[4];

        /* Test all named control chars */
        const char *controls = "\a\b\f\n\r\t\v\\\"\'";
        for (int i = 0; controls[i]; i++) {
                int cl = cescape_char(controls[i], c_buf);
                int rl = rs_cescape_char(controls[i], rs_buf);
                assert_se(cl == rl);
                assert_se(cl == 2);
                assert_se(memcmp(c_buf, rs_buf, cl) == 0);
        }
}

TEST(cescape_char_octal) {
        char c_buf[4], rs_buf[4];

        /* Byte 0x01 → \001 */
        int cl = cescape_char('\x01', c_buf);
        int rl = rs_cescape_char('\x01', rs_buf);
        assert_se(cl == rl);
        assert_se(cl == 4);
        assert_se(memcmp(c_buf, rs_buf, cl) == 0);

        /* Byte 0xFF → \377 */
        cl = cescape_char('\xff', c_buf);
        rl = rs_cescape_char('\xff', rs_buf);
        assert_se(cl == rl);
        assert_se(cl == 4);
        assert_se(memcmp(c_buf, rs_buf, cl) == 0);

        /* Byte 0x7F (DEL) → \177 */
        cl = cescape_char('\x7f', c_buf);
        rl = rs_cescape_char('\x7f', rs_buf);
        assert_se(cl == rl);
        assert_se(cl == 4);
        assert_se(memcmp(c_buf, rs_buf, cl) == 0);
}

TEST(cescape_char_space) {
        /* Space (0x20) should NOT be escaped */
        char c_buf[4], rs_buf[4];
        int cl = cescape_char(' ', c_buf);
        int rl = rs_cescape_char(' ', rs_buf);
        assert_se(cl == rl);
        assert_se(cl == 1);
}

/* ── cescape ────────────────────────────────────────────────────────────── */

TEST(cescape_simple) {
        char *c_str = cescape("hello world");
        char *rs_str = rs_cescape("hello world");
        assert_se(c_str && rs_str);
        assert_se(streq(c_str, rs_str));
        free(c_str);
        free(rs_str);
}

TEST(cescape_with_control) {
        const char *input = "hello\tworld\n";
        char *c_str = cescape(input);
        char *rs_str = rs_cescape(input);
        assert_se(c_str && rs_str);
        assert_se(streq(c_str, rs_str));
        free(c_str);
        free(rs_str);
}

TEST(cescape_with_quotes) {
        const char *input = "say \"hello\"";
        char *c_str = cescape(input);
        char *rs_str = rs_cescape(input);
        assert_se(c_str && rs_str);
        assert_se(streq(c_str, rs_str));
        free(c_str);
        free(rs_str);
}

TEST(cescape_empty) {
        char *c_str = cescape("");
        char *rs_str = rs_cescape("");
        assert_se(c_str && rs_str);
        assert_se(streq(c_str, rs_str));
        assert_se(streq(c_str, ""));
        free(c_str);
        free(rs_str);
}

TEST(cescape_high_bytes) {
        const char input[] = { 'a', 0x01, 'b', 0xFF, '\0' };
        char *c_str = cescape(input);
        char *rs_str = rs_cescape(input);
        assert_se(c_str && rs_str);
        assert_se(streq(c_str, rs_str));
        free(c_str);
        free(rs_str);
}

/* ── cescape_length ─────────────────────────────────────────────────────── */

TEST(cescape_length_basic) {
        char *c_str = cescape_length("hello", 5);
        char *rs_str = rs_cescape_length("hello", 5);
        assert_se(c_str && rs_str);
        assert_se(streq(c_str, rs_str));
        free(c_str);
        free(rs_str);
}

TEST(cescape_length_with_nul) {
        /* cescape_length respects the length, not NUL terminator */
        const char buf[] = { 'a', 'b', '\0', 'c', 'd' };
        char *c_str = cescape_length(buf, 5);
        char *rs_str = rs_cescape_length(buf, 5);
        assert_se(c_str && rs_str);
        assert_se(streq(c_str, rs_str));
        free(c_str);
        free(rs_str);
}

TEST(cescape_length_with_controls) {
        const char buf[] = { 'a', '\t', '\n', '\0' };
        char *c_str = cescape_length(buf, 3);
        char *rs_str = rs_cescape_length(buf, 3);
        assert_se(c_str && rs_str);
        assert_se(streq(c_str, rs_str));
        free(c_str);
        free(rs_str);
}

TEST(cescape_length_binary_and_null_contract) {
        static const char input[] = { 'a', '\0', '\xff', '\n' };
        char *c_str = cescape_length(input, sizeof(input));
        char *rs_str = rs_cescape_length(input, sizeof(input));
        assert_se(c_str && rs_str);
        assert_se(streq(c_str, rs_str));
        free(c_str);
        free(rs_str);

        /* The production assertion is disabled in release builds; the Rust
         * shadow deliberately fails closed for malformed pointer input. */
        assert_se(rs_cescape(NULL) == NULL);
        assert_se(rs_cescape_length(NULL, 1) == NULL);
        rs_str = rs_cescape_length(NULL, 0);
        assert_se(rs_str);
        assert_se(streq(rs_str, ""));
        free(rs_str);
}

/* ── cunescape_one ───────────────────────────────────────────────────────── */

TEST(cunescape_one_simple) {
        char32_t c_val, rs_val;
        bool c_eight, rs_eight;

        const char *escapes = "abfnrtv\\\"\'s";
        for (int i = 0; escapes[i]; i++) {
                int cr = cunescape_one(&escapes[i], SIZE_MAX, &c_val, &c_eight, false);
                int rr = rs_cunescape_one(&escapes[i], SIZE_MAX, &rs_val, &rs_eight, false);
                assert_se(cr == rr);
                assert_se(cr == 1);
                assert_se(c_val == rs_val);
                /* eight_bit is only set for \x, \u, \U, and octal, not for named escapes */
        }
}

TEST(cunescape_one_hex) {
        char32_t c_val, rs_val;
        bool eight;

        /* \x41 = 'A' */
        int cr = cunescape_one("x41", SIZE_MAX, &c_val, &eight, false);
        int rr = rs_cunescape_one("x41", SIZE_MAX, &rs_val, &eight, false);
        assert_se(cr == rr && cr == 3);
        assert_se(c_val == rs_val && c_val == 'A');
        assert_se(eight == true);

        /* \xff */
        cr = cunescape_one("xff", SIZE_MAX, &c_val, &eight, false);
        rr = rs_cunescape_one("xff", SIZE_MAX, &rs_val, &eight, false);
        assert_se(cr == rr && cr == 3);
        assert_se(c_val == rs_val && c_val == 0xFF);
}

TEST(cunescape_one_unicode_u) {
        char32_t c_val, rs_val;
        bool c_eight = false, rs_eight = false;

        /* \u0041 = 'A' */
        int cr = cunescape_one("u0041", SIZE_MAX, &c_val, &c_eight, false);
        int rr = rs_cunescape_one("u0041", SIZE_MAX, &rs_val, &rs_eight, false);
        assert_se(cr == rr && cr == 5);
        assert_se(c_val == rs_val && c_val == 'A');
}

TEST(cunescape_one_unicode_U) {
        char32_t c_val, rs_val;
        bool c_eight = false, rs_eight = false;

        /* \U00000041 = 'A' */
        int cr = cunescape_one("U00000041", SIZE_MAX, &c_val, &c_eight, false);
        int rr = rs_cunescape_one("U00000041", SIZE_MAX, &rs_val, &rs_eight, false);
        assert_se(cr == rr && cr == 9);
        assert_se(c_val == rs_val && c_val == 'A');

        /* \U0001F600 = 😀 */
        cr = cunescape_one("U0001F600", SIZE_MAX, &c_val, &c_eight, false);
        rr = rs_cunescape_one("U0001F600", SIZE_MAX, &rs_val, &rs_eight, false);
        assert_se(cr == rr && cr == 9);
        assert_se(c_val == rs_val && c_val == 0x1F600);
}

TEST(cunescape_one_octal) {
        char32_t c_val, rs_val;
        bool eight;

        /* \101 = 'A' (65) */
        int cr = cunescape_one("101", SIZE_MAX, &c_val, &eight, false);
        int rr = rs_cunescape_one("101", SIZE_MAX, &rs_val, &eight, false);
        assert_se(cr == rr && cr == 3);
        assert_se(c_val == rs_val && c_val == 'A');
        assert_se(eight == true);

        /* \377 = 255 */
        cr = cunescape_one("377", SIZE_MAX, &c_val, &eight, false);
        rr = rs_cunescape_one("377", SIZE_MAX, &rs_val, &eight, false);
        assert_se(cr == rr && cr == 3);
        assert_se(c_val == rs_val && c_val == 255);
}

TEST(cunescape_one_invalid) {
        char32_t val;
        bool eight = false;
        int r;

        r = rs_cunescape_one("z", SIZE_MAX, &val, &eight, false);
        assert_se(r == -EINVAL);

        r = rs_cunescape_one("", SIZE_MAX, &val, &eight, false);
        assert_se(r == -EINVAL);

        /* Invalid hex */
        r = rs_cunescape_one("GG", SIZE_MAX, &val, &eight, false);
        assert_se(r == -EINVAL);
}

TEST(cunescape_one_length_nul_and_eight_bit_contract) {
        static const char hex[] = { 'x', '4', '1', '\0', 'z' };
        char32_t c_value = 0, rs_value = 0;
        bool c_eight = false, rs_eight = false;

        int cr = cunescape_one(hex, 3, &c_value, &c_eight, false);
        int rr = rs_cunescape_one(hex, 3, &rs_value, &rs_eight, false);
        assert_se(cr == rr && cr == 3);
        assert_se(c_value == rs_value && rs_value == 'A');
        assert_se(c_eight == rs_eight && rs_eight);

        /* Current C writes eight_bit only for octal and \\x. Its value is
         * otherwise caller-owned, so the Rust adapter must leave it alone. */
        rs_eight = true;
        rr = rs_cunescape_one("n", SIZE_MAX, &rs_value, &rs_eight, false);
        assert_se(rr == 1 && rs_value == '\n' && rs_eight);

        assert_se(rs_cunescape_one("x41", SIZE_MAX, &rs_value, NULL, false) == -EINVAL);
        assert_se(rs_cunescape_one("n", SIZE_MAX, &rs_value, NULL, false) == -EINVAL);
        assert_se(rs_cunescape_one(NULL, 0, &rs_value, &rs_eight, false) == -EINVAL);
        assert_se(rs_cunescape_one("n", SIZE_MAX, NULL, &rs_eight, false) == -EINVAL);
}

/* ── cunescape ───────────────────────────────────────────────────────────── */

TEST(cunescape_simple) {
        char *c_str = NULL, *rs_str = NULL;
        int cr = cunescape("hello world", 0, &c_str);
        int rr = rs_cunescape("hello world", 0, &rs_str);
        assert_se(cr >= 0 && rr >= 0);
        assert_se(cr == rr);
        assert_se(streq(c_str, rs_str));
        free(c_str);
        free(rs_str);
}

TEST(cunescape_backslash) {
        char *c_str = NULL, *rs_str = NULL;
        int cr = cunescape("hello\\\\world", 0, &c_str);
        int rr = rs_cunescape("hello\\\\world", 0, &rs_str);
        assert_se(cr >= 0 && rr >= 0);
        assert_se(cr == rr);
        assert_se(streq(c_str, rs_str));
        assert_se(streq(c_str, "hello\\world"));
        free(c_str);
        free(rs_str);
}

TEST(cunescape_newline) {
        char *c_str = NULL, *rs_str = NULL;
        int cr = cunescape("line1\\nline2", 0, &c_str);
        int rr = rs_cunescape("line1\\nline2", 0, &rs_str);
        assert_se(cr >= 0 && rr >= 0);
        assert_se(cr == rr);
        assert_se(streq(c_str, rs_str));
        assert_se(streq(c_str, "line1\nline2"));
        free(c_str);
        free(rs_str);
}

TEST(cunescape_hex_escape) {
        char *c_str = NULL, *rs_str = NULL;
        int cr = cunescape("\\x41\\x42", 0, &c_str);
        int rr = rs_cunescape("\\x41\\x42", 0, &rs_str);
        assert_se(cr >= 0 && rr >= 0);
        assert_se(cr == rr);
        assert_se(streq(c_str, rs_str));
        assert_se(streq(c_str, "AB"));
        free(c_str);
        free(rs_str);
}

TEST(cunescape_relax) {
        char *c_str = NULL, *rs_str = NULL;
        /* \z is invalid, but UNESCAPE_RELAX copies it verbatim */
        int cr = cunescape("\\z", UNESCAPE_RELAX, &c_str);
        int rr = rs_cunescape("\\z", UNESCAPE_RELAX, &rs_str);
        assert_se(cr >= 0 && rr >= 0);
        assert_se(cr == rr);
        assert_se(streq(c_str, rs_str));
        free(c_str);
        free(rs_str);
}

TEST(cunescape_explicit_length_and_failure_publication) {
        static const char escaped[] = { 'a', '\\', 'x', '0', '0', 'b' };
        char *c_str = NULL;
        char *rs_str = (char*) 0x1;

        int cr = cunescape_length(escaped, sizeof(escaped), UNESCAPE_ACCEPT_NUL, &c_str);
        ssize_t rr = rs_cunescape_length_with_prefix(escaped, sizeof(escaped), NULL, UNESCAPE_ACCEPT_NUL, &rs_str);
        assert_se(cr == rr && rr == 3);
        assert_se(memcmp(c_str, rs_str, 3) == 0);
        free(c_str);
        free(rs_str);

        /* Allocation ownership is published only after parsing succeeds. */
        rs_str = (char*) 0x1;
        assert_se(rs_cunescape("\\q", 0, &rs_str) == -EINVAL);
        assert_se(rs_str == (char*) 0x1);
        assert_se(rs_cunescape(NULL, 0, &rs_str) == -EINVAL);
        assert_se(rs_cunescape("", 0, NULL) == -EINVAL);
}

/* ── roundtrip: cescape → cunescape ─────────────────────────────────────── */

TEST(cescape_cunescape_roundtrip) {
        const char *inputs[] = {
                "hello world",
                "tab\there",
                "quote\"inside",
                "back\\slash",
                "mixed\t\"\\'\n\r",
                NULL,
        };

        for (int i = 0; inputs[i]; i++) {
                char *escaped = cescape(inputs[i]);
                assert_se(escaped);

                char *unescaped = NULL;
                int r = cunescape(escaped, 0, &unescaped);
                assert_se(r >= 0);
                assert_se(streq(unescaped, inputs[i]));

                free(escaped);
                free(unescaped);
        }
}

TEST(rs_cescape_cunescape_roundtrip) {
        const char *inputs[] = {
                "hello world",
                "tab\there",
                "quote\"inside",
                "back\\slash",
                "mixed\t\"\\'\n\r",
                NULL,
        };

        for (int i = 0; inputs[i]; i++) {
                char *escaped = rs_cescape(inputs[i]);
                assert_se(escaped);

                char *unescaped = NULL;
                ssize_t r = rs_cunescape(escaped, 0, &unescaped);
                assert_se(r >= 0);
                assert_se(streq(unescaped, inputs[i]));

                free(escaped);
                free(unescaped);
        }
}

/* ── main ────────────────────────────────────────────────────────────────── */

DEFINE_TEST_MAIN(LOG_INFO);
