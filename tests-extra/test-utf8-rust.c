/* SPDX-License-Identifier: LGPL-2.1-or-later */

/*
 * Shadow test: verify Rust utf8 port matches C behavior exactly.
 * This test links against both the C (via libshared) and Rust (via
 * libsystemd_basic_rs.a) implementations and compares outputs for
 * every ported function.
 */

#include <stdlib.h>
#include <string.h>
#include <uchar.h>

#include "utf8.h"
#include "rust/utf8.h"
#include "tests.h"

/* ── unichar_is_valid ──────────────────────────────────────────────────── */

TEST(unichar_is_valid_basic_c_vs_rs) {
        /* Valid codepoints */
        for (char32_t c = 0x20; c < 0x7F; c++) {
                ASSERT_EQ(unichar_is_valid(c), rs_unichar_is_valid(c));
                ASSERT_TRUE(rs_unichar_is_valid(c));
        }

        /* Multibyte boundary */
        ASSERT_TRUE(rs_unichar_is_valid(0x80));
        ASSERT_TRUE(rs_unichar_is_valid(0x800));
        ASSERT_TRUE(rs_unichar_is_valid(0x10000));
        /* 0x10FFFF is a noncharacter (ends in FFFF) — compare with C */
        assert_se(unichar_is_valid(0x10FFFF) == rs_unichar_is_valid(0x10FFFF));

        /* Invalid: surrogates */
        for (char32_t c = 0xD800; c <= 0xDFFF; c++) {
                ASSERT_EQ(unichar_is_valid(c), rs_unichar_is_valid(c));
                ASSERT_FALSE(rs_unichar_is_valid(c));
        }

        /* Invalid: beyond unicode */
        ASSERT_EQ(unichar_is_valid(0x110000), rs_unichar_is_valid(0x110000));
        ASSERT_FALSE(rs_unichar_is_valid(0x110000));

        /* Invalid: noncharacters */
        ASSERT_EQ(unichar_is_valid(0xFDD0), rs_unichar_is_valid(0xFDD0));
        ASSERT_EQ(unichar_is_valid(0xFDEF), rs_unichar_is_valid(0xFDEF));
        ASSERT_EQ(unichar_is_valid(0xFFFE), rs_unichar_is_valid(0xFFFE));
        ASSERT_EQ(unichar_is_valid(0xFFFF), rs_unichar_is_valid(0xFFFF));
}

/* ── utf8_is_valid_n / utf8_is_valid ──────────────────────────────────── */

TEST(utf8_is_valid_ascii_c_vs_rs) {
        const char *s = "hello world";
        ASSERT_NOT_NULL(rs_utf8_is_valid_n(s, SIZE_MAX));
        assert_se(utf8_is_valid(s) == rs_utf8_is_valid_n(s, SIZE_MAX));
}

TEST(utf8_is_valid_multibyte_c_vs_rs) {
        /* "café" in UTF-8 */
        const char *s = "caf\xc3\xa9";
        ASSERT_NOT_NULL(rs_utf8_is_valid_n(s, SIZE_MAX));
        assert_se(utf8_is_valid(s) == rs_utf8_is_valid_n(s, SIZE_MAX));
}

TEST(utf8_is_valid_bounded_c_vs_rs) {
        const char *s = "caf\xc3\xa9";
        /* Valid within first 3 bytes ("caf") */
        ASSERT_NOT_NULL(rs_utf8_is_valid_n(s, 3));
        assert_se(utf8_is_valid_n(s, 3) == rs_utf8_is_valid_n(s, 3));
        /* Valid for all 5 bytes */
        assert_se(utf8_is_valid_n(s, 5) == rs_utf8_is_valid_n(s, 5));
        ASSERT_NOT_NULL(rs_utf8_is_valid_n(s, 5));
}

TEST(utf8_is_valid_invalid_c_vs_rs) {
        /* Invalid continuation byte */
        const char *s = "abc\x80\x81";
        ASSERT_NULL(utf8_is_valid(s));
        ASSERT_NULL(rs_utf8_is_valid_n(s, SIZE_MAX));
}

TEST(utf8_is_valid_embedded_nul_c_vs_rs) {
        /* String with embedded NUL */
        const char s[] = {'a', 'b', '\0', 'c', '\0'};
        ASSERT_NULL(utf8_is_valid_n(s, 4));
        ASSERT_NULL(rs_utf8_is_valid_n(s, 4));
}

/* ── ascii_is_valid_n ─────────────────────────────────────────────────── */

TEST(ascii_is_valid_c_vs_rs) {
        const char *s = "Hello World 123!";
        ASSERT_NOT_NULL(rs_ascii_is_valid_n(s, SIZE_MAX));
        assert_se(ascii_is_valid(s) == rs_ascii_is_valid_n(s, SIZE_MAX));
}

TEST(ascii_is_valid_high_byte_c_vs_rs) {
        const char *s = "caf\xc3\xa9";
        ASSERT_NULL(ascii_is_valid(s));
        ASSERT_NULL(rs_ascii_is_valid_n(s, SIZE_MAX));
}

TEST(ascii_is_valid_bounded_c_vs_rs) {
        const char *s = "Hello\x80World";
        assert_se(ascii_is_valid_n(s, 5) == rs_ascii_is_valid_n(s, 5));
        ASSERT_NOT_NULL(rs_ascii_is_valid_n(s, 5));
}

/* ── utf8_to_ascii ────────────────────────────────────────────────────── */

TEST(utf8_to_ascii_simple_c_vs_rs) {
        _cleanup_free_ char *c_ret = NULL;
        _cleanup_free_ char *rs_ret = NULL;
        const char *s = "caf\xc3\xa9";

        ASSERT_EQ(0, utf8_to_ascii(s, '?', &c_ret));
        ASSERT_EQ(0, rs_utf8_to_ascii(s, '?', &rs_ret));
        ASSERT_STREQ(c_ret, rs_ret);
        ASSERT_STREQ(rs_ret, "caf?");
}

TEST(utf8_to_ascii_all_ascii_c_vs_rs) {
        _cleanup_free_ char *c_ret = NULL;
        _cleanup_free_ char *rs_ret = NULL;
        const char *s = "hello";

        ASSERT_EQ(0, utf8_to_ascii(s, '?', &c_ret));
        ASSERT_EQ(0, rs_utf8_to_ascii(s, '?', &rs_ret));
        ASSERT_STREQ(c_ret, rs_ret);
        ASSERT_STREQ(rs_ret, "hello");
}

TEST(utf8_to_ascii_invalid_input_c_vs_rs) {
        _cleanup_free_ char *c_ret = NULL;
        _cleanup_free_ char *rs_ret = NULL;
        const char *s = "abc\x80";

        int c_rc = utf8_to_ascii(s, '?', &c_ret);
        int rs_rc = rs_utf8_to_ascii(s, '?', &rs_ret);
        ASSERT_EQ(c_rc, rs_rc);
        ASSERT_LT(rs_rc, 0);
}

/* ── utf8_escape_invalid ──────────────────────────────────────────────── */

TEST(utf8_escape_invalid_clean_c_vs_rs) {
        _cleanup_free_ char *c_ret = NULL;
        _cleanup_free_ char *rs_ret = NULL;
        const char *s = "hello";

        c_ret = utf8_escape_invalid(s);
        rs_ret = rs_utf8_escape_invalid(s);
        ASSERT_NOT_NULL(c_ret);
        ASSERT_NOT_NULL(rs_ret);
        ASSERT_STREQ(c_ret, rs_ret);
        ASSERT_STREQ(rs_ret, "hello");
}

TEST(utf8_escape_invalid_with_bad_bytes_c_vs_rs) {
        _cleanup_free_ char *c_ret = NULL;
        _cleanup_free_ char *rs_ret = NULL;
        /* Valid UTF-8 "café" followed by invalid byte 0x80 */
        const char *s = "caf\xc3\xa9\x80test";

        c_ret = utf8_escape_invalid(s);
        rs_ret = rs_utf8_escape_invalid(s);
        ASSERT_NOT_NULL(c_ret);
        ASSERT_NOT_NULL(rs_ret);
        ASSERT_STREQ(c_ret, rs_ret);
}

/* ── utf8_is_printable_newline ────────────────────────────────────────── */

TEST(utf8_is_printable_c_vs_rs) {
        ASSERT_EQ(utf8_is_printable("hello", 5), rs_utf8_is_printable_newline("hello", 5, true));
        ASSERT_TRUE(rs_utf8_is_printable_newline("hello", 5, true));
}

TEST(utf8_is_printable_control_c_vs_rs) {
        /* Tab is printable, NUL is not */
        ASSERT_EQ(utf8_is_printable("\t", 1), rs_utf8_is_printable_newline("\t", 1, true));
        ASSERT_EQ(utf8_is_printable("\x01", 1), rs_utf8_is_printable_newline("\x01", 1, true));
        ASSERT_FALSE(rs_utf8_is_printable_newline("\x01", 1, true));
}

TEST(utf8_is_printable_newline_flag_c_vs_rs) {
        ASSERT_TRUE(rs_utf8_is_printable_newline("\n", 1, true));
        ASSERT_FALSE(rs_utf8_is_printable_newline("\n", 1, false));
        ASSERT_EQ(utf8_is_printable_newline("\n", 1, false), rs_utf8_is_printable_newline("\n", 1, false));
}

/* ── utf8_escape_non_printable_full ───────────────────────────────────── */

TEST(utf8_escape_non_printable_simple_c_vs_rs) {
        _cleanup_free_ char *c_ret = NULL;
        _cleanup_free_ char *rs_ret = NULL;

        c_ret = utf8_escape_non_printable_full("hello", 80, false);
        rs_ret = rs_utf8_escape_non_printable_full("hello", 80, false);
        ASSERT_NOT_NULL(c_ret);
        ASSERT_NOT_NULL(rs_ret);
        ASSERT_STREQ(c_ret, rs_ret);
}

TEST(utf8_escape_non_printable_with_control_c_vs_rs) {
        _cleanup_free_ char *c_ret = NULL;
        _cleanup_free_ char *rs_ret = NULL;

        /* Use array init to avoid \x hex-escape ambiguity in C string literals.
         * "a\x01b" would be parsed as a + \x01b (= byte 0x1B), not a + 0x01 + b. */
        const char s[] = { 'a', '\x01', 'b', '\0' };
        c_ret = utf8_escape_non_printable_full(s, 80, false);
        rs_ret = rs_utf8_escape_non_printable_full(s, 80, false);
        ASSERT_NOT_NULL(c_ret);
        ASSERT_NOT_NULL(rs_ret);
        ASSERT_STREQ(c_ret, rs_ret);
}

TEST(utf8_escape_non_printable_truncate_c_vs_rs) {
        _cleanup_free_ char *c_ret = NULL;
        _cleanup_free_ char *rs_ret = NULL;

        /* Width of 5 should truncate "hello world" */
        c_ret = utf8_escape_non_printable_full("hello world", 5, false);
        rs_ret = rs_utf8_escape_non_printable_full("hello world", 5, false);
        ASSERT_NOT_NULL(c_ret);
        ASSERT_NOT_NULL(rs_ret);
        ASSERT_STREQ(c_ret, rs_ret);
}

TEST(utf8_escape_non_printable_zero_width_c_vs_rs) {
        _cleanup_free_ char *c_ret = NULL;
        _cleanup_free_ char *rs_ret = NULL;

        c_ret = utf8_escape_non_printable_full("hello", 0, false);
        rs_ret = rs_utf8_escape_non_printable_full("hello", 0, false);
        ASSERT_NOT_NULL(c_ret);
        ASSERT_NOT_NULL(rs_ret);
        ASSERT_STREQ(c_ret, rs_ret);
        ASSERT_STREQ(rs_ret, "");
}

TEST(utf8_escape_non_printable_force_ellipsis_c_vs_rs) {
        _cleanup_free_ char *c_ret = NULL;
        _cleanup_free_ char *rs_ret = NULL;

        c_ret = utf8_escape_non_printable_full("abc", 80, true);
        rs_ret = rs_utf8_escape_non_printable_full("abc", 80, true);
        ASSERT_NOT_NULL(c_ret);
        ASSERT_NOT_NULL(rs_ret);
        ASSERT_STREQ(c_ret, rs_ret);
}

/* ── utf8_encode_unichar ──────────────────────────────────────────────── */

TEST(utf8_encode_unichar_c_vs_rs) {
        char c_buf[4] = {};
        char rs_buf[4] = {};

        /* ASCII */
        size_t c_len = utf8_encode_unichar(c_buf, 'A');
        size_t rs_len = rs_utf8_encode_unichar(rs_buf, 'A');
        ASSERT_EQ(c_len, rs_len);
        ASSERT_EQ(c_len, 1u);
        ASSERT_EQ(c_buf[0], rs_buf[0]);

        /* 2-byte: U+00E9 (é) */
        memset(c_buf, 0, sizeof(c_buf));
        memset(rs_buf, 0, sizeof(rs_buf));
        c_len = utf8_encode_unichar(c_buf, 0xE9);
        rs_len = rs_utf8_encode_unichar(rs_buf, 0xE9);
        ASSERT_EQ(c_len, rs_len);
        ASSERT_EQ(c_len, 2u);
        ASSERT_EQ(memcmp(c_buf, rs_buf, 2), 0);

        /* 3-byte: U+4E16 (世) */
        memset(c_buf, 0, sizeof(c_buf));
        memset(rs_buf, 0, sizeof(rs_buf));
        c_len = utf8_encode_unichar(c_buf, 0x4E16);
        rs_len = rs_utf8_encode_unichar(rs_buf, 0x4E16);
        ASSERT_EQ(c_len, rs_len);
        ASSERT_EQ(c_len, 3u);
        ASSERT_EQ(memcmp(c_buf, rs_buf, 3), 0);

        /* 4-byte: U+1F600 */
        memset(c_buf, 0, sizeof(c_buf));
        memset(rs_buf, 0, sizeof(rs_buf));
        c_len = utf8_encode_unichar(c_buf, 0x1F600);
        rs_len = rs_utf8_encode_unichar(rs_buf, 0x1F600);
        ASSERT_EQ(c_len, rs_len);
        ASSERT_EQ(c_len, 4u);
        ASSERT_EQ(memcmp(c_buf, rs_buf, 4), 0);

        /* NULL out: just get length */
        c_len = utf8_encode_unichar(NULL, 0x1F600);
        rs_len = rs_utf8_encode_unichar(NULL, 0x1F600);
        ASSERT_EQ(c_len, rs_len);
}

/* ── utf8_encoded_valid_unichar ───────────────────────────────────────── */

TEST(utf8_encoded_valid_unichar_ascii_c_vs_rs) {
        ASSERT_EQ(utf8_encoded_valid_unichar("A", 1), rs_utf8_encoded_valid_unichar("A", 1));
        ASSERT_EQ(rs_utf8_encoded_valid_unichar("A", 1), 1);
}

TEST(utf8_encoded_valid_unichar_2byte_c_vs_rs) {
        const char *s = "\xc3\xa9"; /* é */
        ASSERT_EQ(utf8_encoded_valid_unichar(s, 2), rs_utf8_encoded_valid_unichar(s, 2));
        ASSERT_EQ(rs_utf8_encoded_valid_unichar(s, 2), 2);
}

TEST(utf8_encoded_valid_unichar_3byte_c_vs_rs) {
        const char *s = "\xe4\xb8\x96"; /* 世 */
        ASSERT_EQ(utf8_encoded_valid_unichar(s, 3), rs_utf8_encoded_valid_unichar(s, 3));
        ASSERT_EQ(rs_utf8_encoded_valid_unichar(s, 3), 3);
}

TEST(utf8_encoded_valid_unichar_4byte_c_vs_rs) {
        const char *s = "\xf0\x9f\x98\x80"; /* 😀 */
        ASSERT_EQ(utf8_encoded_valid_unichar(s, 4), rs_utf8_encoded_valid_unichar(s, 4));
        ASSERT_EQ(rs_utf8_encoded_valid_unichar(s, 4), 4);
}

TEST(utf8_encoded_valid_unichar_truncated_c_vs_rs) {
        const char *s = "\xc3"; /* incomplete 2-byte */
        ASSERT_EQ(utf8_encoded_valid_unichar(s, 1), rs_utf8_encoded_valid_unichar(s, 1));
        ASSERT_LT(rs_utf8_encoded_valid_unichar(s, 1), 0);
}

TEST(utf8_encoded_valid_unichar_invalid_c_vs_rs) {
        const char *s = "\x80"; /* continuation byte as leading */
        ASSERT_EQ(utf8_encoded_valid_unichar(s, 1), rs_utf8_encoded_valid_unichar(s, 1));
        ASSERT_LT(rs_utf8_encoded_valid_unichar(s, 1), 0);
}

/* ── utf8_encoded_to_unichar ──────────────────────────────────────────── */

TEST(utf8_encoded_to_unichar_ascii_c_vs_rs) {
        char32_t c_val = 0, rs_val = 0;
        ASSERT_EQ(utf8_encoded_to_unichar("A", &c_val), rs_utf8_encoded_to_unichar("A", &rs_val));
        ASSERT_EQ(c_val, rs_val);
        ASSERT_EQ(c_val, (char32_t)'A');
}

TEST(utf8_encoded_to_unichar_2byte_c_vs_rs) {
        char32_t c_val = 0, rs_val = 0;
        const char *s = "\xc3\xa9"; /* é = U+00E9 */
        ASSERT_EQ(utf8_encoded_to_unichar(s, &c_val), rs_utf8_encoded_to_unichar(s, &rs_val));
        ASSERT_EQ(c_val, rs_val);
        ASSERT_EQ(c_val, (char32_t)0xE9);
}

TEST(utf8_encoded_to_unichar_3byte_c_vs_rs) {
        char32_t c_val = 0, rs_val = 0;
        const char *s = "\xe4\xb8\x96"; /* 世 = U+4E16 */
        ASSERT_EQ(utf8_encoded_to_unichar(s, &c_val), rs_utf8_encoded_to_unichar(s, &rs_val));
        ASSERT_EQ(c_val, rs_val);
        ASSERT_EQ(c_val, (char32_t)0x4E16);
}

/* ── utf8_n_codepoints ────────────────────────────────────────────────── */

TEST(utf8_n_codepoints_c_vs_rs) {
        ASSERT_EQ(utf8_n_codepoints("hello"), rs_utf8_n_codepoints("hello"));
        ASSERT_EQ(rs_utf8_n_codepoints("hello"), 5u);

        /* "café" = 4 codepoints */
        const char *s = "caf\xc3\xa9";
        ASSERT_EQ(utf8_n_codepoints(s), rs_utf8_n_codepoints(s));
        ASSERT_EQ(rs_utf8_n_codepoints(s), 4u);
}

TEST(utf8_n_codepoints_invalid_c_vs_rs) {
        const char *s = "abc\x80";
        ASSERT_EQ(utf8_n_codepoints(s), rs_utf8_n_codepoints(s));
        ASSERT_EQ(rs_utf8_n_codepoints(s), SIZE_MAX);
}

TEST(utf8_n_codepoints_empty_c_vs_rs) {
        ASSERT_EQ(utf8_n_codepoints(""), rs_utf8_n_codepoints(""));
        ASSERT_EQ(rs_utf8_n_codepoints(""), 0u);
}

/* ── utf8_char_console_width ──────────────────────────────────────────── */

TEST(utf8_char_console_width_ascii_c_vs_rs) {
        ASSERT_EQ(utf8_char_console_width("A"), rs_utf8_char_console_width("A"));
        ASSERT_EQ(rs_utf8_char_console_width("A"), 1);
}

TEST(utf8_char_console_width_tab_c_vs_rs) {
        ASSERT_EQ(utf8_char_console_width("\t"), rs_utf8_char_console_width("\t"));
        ASSERT_EQ(rs_utf8_char_console_width("\t"), 8);
}

/* ── utf8_console_width ───────────────────────────────────────────────── */

TEST(utf8_console_width_c_vs_rs) {
        ASSERT_EQ(utf8_console_width("hello"), rs_utf8_console_width("hello"));
        ASSERT_EQ(rs_utf8_console_width("hello"), (size_t)5);
}

TEST(utf8_console_width_empty_c_vs_rs) {
        ASSERT_EQ(utf8_console_width(""), rs_utf8_console_width(""));
        ASSERT_EQ(rs_utf8_console_width(""), (size_t)0);
}

TEST(utf8_console_width_tab_c_vs_rs) {
        ASSERT_EQ(utf8_console_width("\t"), rs_utf8_console_width("\t"));
        ASSERT_EQ(rs_utf8_console_width("\t"), (size_t)8);
}

/* ── utf8_last_length ─────────────────────────────────────────────────── */

TEST(utf8_last_length_ascii_c_vs_rs) {
        ASSERT_EQ(utf8_last_length("hello", SIZE_MAX), rs_utf8_last_length("hello", SIZE_MAX));
        ASSERT_EQ(rs_utf8_last_length("hello", SIZE_MAX), 1u);
}

TEST(utf8_last_length_multibyte_c_vs_rs) {
        /* "café" last char is é = 2 bytes */
        const char *s = "caf\xc3\xa9";
        ASSERT_EQ(utf8_last_length(s, SIZE_MAX), rs_utf8_last_length(s, SIZE_MAX));
        ASSERT_EQ(rs_utf8_last_length(s, SIZE_MAX), 2u);
}

TEST(utf8_last_length_bounded_c_vs_rs) {
        const char *s = "caf\xc3\xa9";
        ASSERT_EQ(utf8_last_length(s, 3), rs_utf8_last_length(s, 3));
        ASSERT_EQ(rs_utf8_last_length(s, 3), 1u); /* 'f' is 1 byte */
}

TEST(utf8_last_length_empty_c_vs_rs) {
        ASSERT_EQ(utf8_last_length("", SIZE_MAX), rs_utf8_last_length("", SIZE_MAX));
        ASSERT_EQ(rs_utf8_last_length("", SIZE_MAX), 0u);
}

/* ── char16_strlen / char16_strsize ───────────────────────────────────── */

TEST(char16_strlen_c_vs_rs) {
        const char16_t s[] = { 'h', 'e', 'l', 'l', 'o', 0 };
        ASSERT_EQ(char16_strlen(s), rs_char16_strlen(s));
        ASSERT_EQ(rs_char16_strlen(s), 5u);
}

TEST(char16_strlen_empty_c_vs_rs) {
        const char16_t s[] = { 0 };
        ASSERT_EQ(char16_strlen(s), rs_char16_strlen(s));
        ASSERT_EQ(rs_char16_strlen(s), 0u);
}

TEST(char16_strsize_c_vs_rs) {
        const char16_t s[] = { 'a', 'b', 0 };
        ASSERT_EQ(char16_strsize(s), rs_char16_strsize(s));
        ASSERT_EQ(rs_char16_strsize(s), 3 * sizeof(char16_t));
}

TEST(char16_strsize_null_c_vs_rs) {
        ASSERT_EQ(char16_strsize(NULL), rs_char16_strsize(NULL));
        ASSERT_EQ(rs_char16_strsize(NULL), 0u);
}

/* ── utf16_encode_unichar ─────────────────────────────────────────────── */

TEST(utf16_encode_unichar_bmp_c_vs_rs) {
        char16_t c_out[2] = {};
        char16_t rs_out[2] = {};

        size_t c_len = utf16_encode_unichar(c_out, 'A');
        size_t rs_len = rs_utf16_encode_unichar(rs_out, 'A');
        ASSERT_EQ(c_len, rs_len);
        ASSERT_EQ(c_len, 1u);
        ASSERT_EQ(c_out[0], rs_out[0]);

        /* BMP: U+4E16 (世) */
        memset(c_out, 0, sizeof(c_out));
        memset(rs_out, 0, sizeof(rs_out));
        c_len = utf16_encode_unichar(c_out, 0x4E16);
        rs_len = rs_utf16_encode_unichar(rs_out, 0x4E16);
        ASSERT_EQ(c_len, rs_len);
        ASSERT_EQ(c_len, 1u);
        ASSERT_EQ(c_out[0], rs_out[0]);
}

TEST(utf16_encode_unichar_supplementary_c_vs_rs) {
        char16_t c_out[2] = {};
        char16_t rs_out[2] = {};

        /* Supplementary: U+1F600 (😀) */
        size_t c_len = utf16_encode_unichar(c_out, 0x1F600);
        size_t rs_len = rs_utf16_encode_unichar(rs_out, 0x1F600);
        ASSERT_EQ(c_len, rs_len);
        ASSERT_EQ(c_len, 2u);
        ASSERT_EQ(c_out[0], rs_out[0]);
        ASSERT_EQ(c_out[1], rs_out[1]);
}

TEST(utf16_encode_unichar_surrogate_c_vs_rs) {
        char16_t c_out[2] = {};
        char16_t rs_out[2] = {};

        /* Surrogate: should return 0 */
        size_t c_len = utf16_encode_unichar(c_out, 0xD800);
        size_t rs_len = rs_utf16_encode_unichar(rs_out, 0xD800);
        ASSERT_EQ(c_len, rs_len);
        ASSERT_EQ(c_len, 0u);
}

/* ── utf16_to_utf8 ────────────────────────────────────────────────────── */

TEST(utf16_to_utf8_simple_c_vs_rs) {
        const char16_t s[] = { 'h', 'i', 0 };
        _cleanup_free_ char *c_ret = utf16_to_utf8(s, SIZE_MAX);
        _cleanup_free_ char *rs_ret = rs_utf16_to_utf8(s, SIZE_MAX);

        ASSERT_NOT_NULL(c_ret);
        ASSERT_NOT_NULL(rs_ret);
        ASSERT_STREQ(c_ret, rs_ret);
        ASSERT_STREQ(rs_ret, "hi");
}

TEST(utf16_to_utf8_empty_c_vs_rs) {
        _cleanup_free_ char *c_ret = utf16_to_utf8(NULL, 0);
        _cleanup_free_ char *rs_ret = rs_utf16_to_utf8(NULL, 0);

        ASSERT_NOT_NULL(c_ret);
        ASSERT_NOT_NULL(rs_ret);
        ASSERT_STREQ(c_ret, rs_ret);
        ASSERT_STREQ(rs_ret, "");
}

TEST(utf16_to_utf8_surrogate_pair_c_vs_rs) {
        /* U+1F600 encoded as surrogate pair */
        char16_t s[3];
        utf16_encode_unichar(s, 0x1F600);
        s[2] = 0;

        _cleanup_free_ char *c_ret = utf16_to_utf8(s, SIZE_MAX);
        _cleanup_free_ char *rs_ret = rs_utf16_to_utf8(s, SIZE_MAX);

        ASSERT_NOT_NULL(c_ret);
        ASSERT_NOT_NULL(rs_ret);
        ASSERT_STREQ(c_ret, rs_ret);
}

/* ── utf8_to_utf16 ────────────────────────────────────────────────────── */

TEST(utf8_to_utf16_simple_c_vs_rs) {
        const char *s = "hi";
        _cleanup_free_ char16_t *c_ret = utf8_to_utf16(s, SIZE_MAX);
        _cleanup_free_ char16_t *rs_ret = rs_utf8_to_utf16(s, SIZE_MAX);

        ASSERT_NOT_NULL(c_ret);
        ASSERT_NOT_NULL(rs_ret);
        ASSERT_EQ(char16_strlen(c_ret), char16_strlen(rs_ret));
        /* Compare word by word */
        for (size_t i = 0; i <= char16_strlen(c_ret); i++)
                ASSERT_EQ(c_ret[i], rs_ret[i]);
}

TEST(utf8_to_utf16_empty_c_vs_rs) {
        _cleanup_free_ char16_t *c_ret = utf8_to_utf16(NULL, 0);
        _cleanup_free_ char16_t *rs_ret = rs_utf8_to_utf16(NULL, 0);

        ASSERT_NOT_NULL(c_ret);
        ASSERT_NOT_NULL(rs_ret);
        ASSERT_EQ(c_ret[0], rs_ret[0]);
}

TEST(utf8_to_utf16_multibyte_c_vs_rs) {
        /* "café" */
        const char *s = "caf\xc3\xa9";
        _cleanup_free_ char16_t *c_ret = utf8_to_utf16(s, SIZE_MAX);
        _cleanup_free_ char16_t *rs_ret = rs_utf8_to_utf16(s, SIZE_MAX);

        ASSERT_NOT_NULL(c_ret);
        ASSERT_NOT_NULL(rs_ret);
        ASSERT_EQ(char16_strlen(c_ret), char16_strlen(rs_ret));
        for (size_t i = 0; i <= char16_strlen(c_ret); i++)
                ASSERT_EQ(c_ret[i], rs_ret[i]);
}

TEST(utf8_to_utf16_invalid_c_vs_rs) {
        /* Invalid byte should be copied as-is.
         * Use array init to avoid \x80b being parsed as \x80 + b. */
        const char s[] = { 'a', '\x80', 'b', '\0' };
        _cleanup_free_ char16_t *c_ret = utf8_to_utf16(s, SIZE_MAX);
        _cleanup_free_ char16_t *rs_ret = rs_utf8_to_utf16(s, SIZE_MAX);

        ASSERT_NOT_NULL(c_ret);
        ASSERT_NOT_NULL(rs_ret);
        ASSERT_EQ(char16_strlen(c_ret), char16_strlen(rs_ret));
        for (size_t i = 0; i <= char16_strlen(c_ret); i++)
                ASSERT_EQ(c_ret[i], rs_ret[i]);
}

DEFINE_TEST_MAIN(LOG_INFO);
