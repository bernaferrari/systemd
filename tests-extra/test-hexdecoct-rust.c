/* SPDX-License-Identifier: LGPL-2.1-or-later */

/*
 * Shadow test: verify Rust hexdecoct port matches C behavior exactly.
 * This test links against both the C (via libbasic) and Rust (via
 * libsystemd_basic_rs.a) implementations and compares outputs for
 * every ported function.
 */

#include "hexdecoct.h"
#include "rust/hexdecoct.h"
#include "memory-util.h"
#include "tests.h"

/* ── Octal ──────────────────────────────────────────────────────────────── */

TEST(octchar_c_vs_rs) {
        for (int i = 0; i < 8; i++)
                ASSERT_EQ(octchar(i), rs_octchar(i));
        /* Out-of-range: masked */
        ASSERT_EQ(octchar(8), rs_octchar(8));
        ASSERT_EQ(octchar(15), rs_octchar(15));
        ASSERT_EQ(octchar(-1), rs_octchar(-1));
        ASSERT_EQ(octchar(255), rs_octchar(255));
}

TEST(unoctchar_c_vs_rs) {
        for (int i = '0'; i <= '7'; i++)
                ASSERT_EQ(unoctchar(i), rs_unoctchar(i));
        /* Invalid chars */
        ASSERT_EQ(unoctchar('8'), rs_unoctchar('8'));
        ASSERT_EQ(unoctchar('a'), rs_unoctchar('a'));
        ASSERT_EQ(unoctchar(' '), rs_unoctchar(' '));
        ASSERT_EQ(unoctchar(-1), rs_unoctchar(-1));
}

/* ── Decimal ────────────────────────────────────────────────────────────── */

TEST(decchar_c_vs_rs) {
        for (int i = 0; i < 10; i++)
                ASSERT_EQ(decchar(i), rs_decchar(i));
        ASSERT_EQ(decchar(10), rs_decchar(10));
        ASSERT_EQ(decchar(-1), rs_decchar(-1));
}

TEST(undecchar_c_vs_rs) {
        for (int i = '0'; i <= '9'; i++)
                ASSERT_EQ(undecchar(i), rs_undecchar(i));
        ASSERT_EQ(undecchar('a'), rs_undecchar('a'));
        ASSERT_EQ(undecchar(' '), rs_undecchar(' '));
}

/* ── Hex ────────────────────────────────────────────────────────────────── */

TEST(hexchar_c_vs_rs) {
        for (int i = 0; i < 16; i++)
                ASSERT_EQ(hexchar(i), rs_hexchar(i));
        ASSERT_EQ(hexchar(16), rs_hexchar(16));
        ASSERT_EQ(hexchar(31), rs_hexchar(31));
        ASSERT_EQ(hexchar(-1), rs_hexchar(-1));
        ASSERT_EQ(hexchar(255), rs_hexchar(255));
}

TEST(unhexchar_c_vs_rs) {
        /* 0-9 */
        for (int i = '0'; i <= '9'; i++)
                ASSERT_EQ(unhexchar(i), rs_unhexchar(i));
        /* a-f */
        for (int i = 'a'; i <= 'f'; i++)
                ASSERT_EQ(unhexchar(i), rs_unhexchar(i));
        /* A-F */
        for (int i = 'A'; i <= 'F'; i++)
                ASSERT_EQ(unhexchar(i), rs_unhexchar(i));
        /* Invalid */
        ASSERT_EQ(unhexchar('g'), rs_unhexchar('g'));
        ASSERT_EQ(unhexchar(' '), rs_unhexchar(' '));
        ASSERT_EQ(unhexchar('@'), rs_unhexchar('@'));
}

/* ── hexmem ─────────────────────────────────────────────────────────────── */

TEST(hexmem_c_vs_rs) {
        const uint8_t data[] = {0xde, 0xad, 0xbe, 0xef, 0x00, 0xff};
        _cleanup_free_ char *c_hex = hexmem(data, sizeof(data));
        _cleanup_free_ char *rs_hex = rs_hexmem(data, sizeof(data));
        assert_se(c_hex);
        assert_se(rs_hex);
        ASSERT_STREQ(c_hex, rs_hex);
}

TEST(hexmem_empty_c_vs_rs) {
        _cleanup_free_ char *c_hex = hexmem(NULL, 0);
        _cleanup_free_ char *rs_hex = rs_hexmem(NULL, 0);
        assert_se(c_hex);
        assert_se(rs_hex);
        ASSERT_STREQ(c_hex, rs_hex);
        ASSERT_EQ(strlen(c_hex), 0u);
}

/* ── unhexmem ───────────────────────────────────────────────────────────── */

TEST(unhexmem_c_vs_rs) {
        _cleanup_free_ void *c_data = NULL;
        _cleanup_free_ void *rs_data = NULL;
        size_t c_size = 0, rs_size = 0;

        assert_se(unhexmem("deadbeef", &c_data, &c_size) >= 0);
        assert_se(rs_unhexmem_full("deadbeef", SIZE_MAX, false, &rs_data, &rs_size) >= 0);
        assert_se(c_data);
        assert_se(rs_data);
        ASSERT_EQ(c_size, rs_size);
        ASSERT_EQ(memcmp(c_data, rs_data, c_size), 0);
}

TEST(unhexmem_whitespace_c_vs_rs) {
        _cleanup_free_ void *c_data = NULL;
        _cleanup_free_ void *rs_data = NULL;
        size_t c_size = 0, rs_size = 0;

        assert_se(unhexmem("de ad be ef", &c_data, &c_size) >= 0);
        assert_se(rs_unhexmem_full("de ad be ef", SIZE_MAX, false, &rs_data, &rs_size) >= 0);
        assert_se(c_data);
        assert_se(rs_data);
        ASSERT_EQ(c_size, rs_size);
        ASSERT_EQ(memcmp(c_data, rs_data, c_size), 0);
}

TEST(unhexmem_invalid_c_vs_rs) {
        _cleanup_free_ void *c_data = NULL;
        _cleanup_free_ void *rs_data = NULL;
        size_t c_size = 0, rs_size = 0;

        int c_ret = unhexmem("gh", &c_data, &c_size);
        int rs_ret = rs_unhexmem_full("gh", SIZE_MAX, false, &rs_data, &rs_size);
        ASSERT_EQ(c_ret, rs_ret);
        ASSERT_LT(c_ret, 0);
}

/* ── Base32hex ──────────────────────────────────────────────────────────── */

TEST(base32hexchar_c_vs_rs) {
        for (int i = 0; i < 32; i++)
                ASSERT_EQ(base32hexchar(i), rs_base32hexchar(i));
        ASSERT_EQ(base32hexchar(32), rs_base32hexchar(32));
        ASSERT_EQ(base32hexchar(255), rs_base32hexchar(255));
}

TEST(unbase32hexchar_c_vs_rs) {
        for (int i = '0'; i <= '9'; i++)
                ASSERT_EQ(unbase32hexchar(i), rs_unbase32hexchar(i));
        for (int i = 'A'; i <= 'V'; i++)
                ASSERT_EQ(unbase32hexchar(i), rs_unbase32hexchar(i));
        ASSERT_EQ(unbase32hexchar('W'), rs_unbase32hexchar('W'));
}

TEST(base32hexmem_roundtrip_c_vs_rs) {
        const uint8_t data[] = {0xde, 0xad, 0xbe, 0xef};

        _cleanup_free_ char *c_enc = base32hexmem(data, sizeof(data), true);
        _cleanup_free_ char *rs_enc = rs_base32hexmem(data, sizeof(data), true);
        assert_se(c_enc);
        assert_se(rs_enc);
        ASSERT_STREQ(c_enc, rs_enc);
}

TEST(base32hexmem_nopad_roundtrip_c_vs_rs) {
        const uint8_t data[] = {0xde, 0xad, 0xbe, 0xef};

        _cleanup_free_ char *c_enc = base32hexmem(data, sizeof(data), false);
        _cleanup_free_ char *rs_enc = rs_base32hexmem(data, sizeof(data), false);
        assert_se(c_enc);
        assert_se(rs_enc);
        ASSERT_STREQ(c_enc, rs_enc);
}

TEST(base32hex_decode_c_vs_rs) {
        const uint8_t data[] = "Hello";
        _cleanup_free_ char *encoded = base32hexmem(data, 5, true);
        assert_se(encoded);

        _cleanup_free_ void *c_dec = NULL;
        _cleanup_free_ void *rs_dec = NULL;
        size_t c_size = 0, rs_size = 0;

        assert_se(unbase32hexmem(encoded, SIZE_MAX, true, &c_dec, &c_size) >= 0);
        assert_se(rs_unbase32hexmem(encoded, SIZE_MAX, true, &rs_dec, &rs_size) >= 0);
        ASSERT_EQ(c_size, rs_size);
        ASSERT_EQ(c_size, 5u);
        ASSERT_EQ(memcmp(c_dec, rs_dec, c_size), 0);
}

/* ── Base64 ─────────────────────────────────────────────────────────────── */

TEST(base64char_c_vs_rs) {
        for (int i = 0; i < 64; i++)
                ASSERT_EQ(base64char(i), rs_base64char(i));
        ASSERT_EQ(base64char(64), rs_base64char(64));
}

TEST(urlsafe_base64char_c_vs_rs) {
        ASSERT_EQ(urlsafe_base64char(62), rs_urlsafe_base64char(62));
        ASSERT_EQ(urlsafe_base64char(63), rs_urlsafe_base64char(63));
        ASSERT_EQ(urlsafe_base64char(0), rs_urlsafe_base64char(0));
}

TEST(unbase64char_c_vs_rs) {
        /* Regular alphabet */
        for (int i = 'A'; i <= 'Z'; i++)
                ASSERT_EQ(unbase64char(i), rs_unbase64char(i));
        for (int i = 'a'; i <= 'z'; i++)
                ASSERT_EQ(unbase64char(i), rs_unbase64char(i));
        for (int i = '0'; i <= '9'; i++)
                ASSERT_EQ(unbase64char(i), rs_unbase64char(i));
        ASSERT_EQ(unbase64char('+'), rs_unbase64char('+'));
        ASSERT_EQ(unbase64char('/'), rs_unbase64char('/'));
        /* URL-safe */
        ASSERT_EQ(unbase64char('-'), rs_unbase64char('-'));
        ASSERT_EQ(unbase64char('_'), rs_unbase64char('_'));
        /* Invalid */
        ASSERT_EQ(unbase64char(' '), rs_unbase64char(' '));
        ASSERT_EQ(unbase64char('@'), rs_unbase64char('@'));
}

TEST(base64mem_roundtrip_c_vs_rs) {
        const uint8_t data[] = "Hello, World! This is a test of base64 encoding.";
        size_t data_len = strlen((const char *)data);

        _cleanup_free_ char *c_enc = NULL;
        _cleanup_free_ char *rs_enc = NULL;
        ssize_t c_len = base64mem(data, data_len, &c_enc);
        ssize_t rs_len = rs_base64mem_full(data, data_len, SIZE_MAX, &rs_enc);
        ASSERT_EQ(c_len, rs_len);
        assert_se(c_enc);
        assert_se(rs_enc);
        ASSERT_STREQ(c_enc, rs_enc);

        /* Verify decode matches */
        _cleanup_free_ void *c_dec = NULL;
        _cleanup_free_ void *rs_dec = NULL;
        size_t c_dec_size = 0, rs_dec_size = 0;
        assert_se(unbase64mem(c_enc, &c_dec, &c_dec_size) >= 0);
        assert_se(rs_unbase64mem_full(rs_enc, SIZE_MAX, false, &rs_dec, &rs_dec_size) >= 0);
        ASSERT_EQ(c_dec_size, rs_dec_size);
        ASSERT_EQ(c_dec_size, data_len);
        ASSERT_EQ(memcmp(c_dec, data, data_len), 0);
}

TEST(base64mem_empty_c_vs_rs) {
        _cleanup_free_ char *c_enc = NULL;
        _cleanup_free_ char *rs_enc = NULL;
        ssize_t c_len = base64mem(NULL, 0, &c_enc);
        ssize_t rs_len = rs_base64mem_full(NULL, 0, SIZE_MAX, &rs_enc);
        ASSERT_EQ(c_len, rs_len);
        ASSERT_GE(c_len, 0);
        assert_se(c_enc);
        assert_se(rs_enc);
        ASSERT_STREQ(c_enc, rs_enc);
        ASSERT_EQ(strlen(c_enc), 0u);
}

TEST(base64mem_with_linebreak_c_vs_rs) {
        const uint8_t data[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17};
        size_t data_len = sizeof(data);

        _cleanup_free_ char *c_enc = NULL;
        _cleanup_free_ char *rs_enc = NULL;
        ssize_t c_len = base64mem_full(data, data_len, 16, &c_enc);
        ssize_t rs_len = rs_base64mem_full(data, data_len, 16, &rs_enc);
        ASSERT_EQ(c_len, rs_len);
        assert_se(c_enc);
        assert_se(rs_enc);
        ASSERT_STREQ(c_enc, rs_enc);
}

TEST(base64mem_binary_roundtrip_c_vs_rs) {
        /* Test with all 256 byte values */
        uint8_t data[256];
        for (int i = 0; i < 256; i++)
                data[i] = (uint8_t)i;

        _cleanup_free_ char *c_enc = NULL;
        _cleanup_free_ char *rs_enc = NULL;
        ssize_t c_len = base64mem(data, 256, &c_enc);
        ssize_t rs_len = rs_base64mem_full(data, 256, SIZE_MAX, &rs_enc);
        ASSERT_EQ(c_len, rs_len);
        assert_se(c_enc);
        assert_se(rs_enc);
        ASSERT_STREQ(c_enc, rs_enc);

        /* Verify round-trip */
        _cleanup_free_ void *c_dec = NULL;
        size_t c_dec_size = 0;
        assert_se(unbase64mem(c_enc, &c_dec, &c_dec_size) >= 0);
        ASSERT_EQ(c_dec_size, 256u);
        ASSERT_EQ(memcmp(c_dec, data, 256), 0);
}

TEST(unbase64mem_whitespace_c_vs_rs) {
        _cleanup_free_ void *c_dec = NULL;
        _cleanup_free_ void *rs_dec = NULL;
        size_t c_size = 0, rs_size = 0;

        assert_se(unbase64mem("SGVsbG8=", &c_dec, &c_size) >= 0);
        assert_se(rs_unbase64mem_full("SGVsbG8=", SIZE_MAX, false, &rs_dec, &rs_size) >= 0);
        ASSERT_EQ(c_size, rs_size);
        ASSERT_EQ(c_size, 5u);
        ASSERT_EQ(memcmp(c_dec, rs_dec, c_size), 0);
}

TEST(unbase64mem_invalid_c_vs_rs) {
        _cleanup_free_ void *c_dec = NULL;
        _cleanup_free_ void *rs_dec = NULL;
        size_t c_size = 0, rs_size = 0;

        int c_ret = unbase64mem("YQ", &c_dec, &c_size);
        int rs_ret = rs_unbase64mem_full("YQ", SIZE_MAX, false, &rs_dec, &rs_size);
        ASSERT_EQ(c_ret, rs_ret);
        ASSERT_LT(c_ret, 0);
}

/* ── Secure wipe ────────────────────────────────────────────────────────── */

TEST(unhexmem_secure_c_vs_rs) {
        char c_buf[] = "deadbeef";
        char rs_buf[] = "deadbeef";
        _cleanup_free_ void *c_data = NULL;
        _cleanup_free_ void *rs_data = NULL;
        size_t c_size = 0, rs_size = 0;

        assert_se(unhexmem_full(c_buf, SIZE_MAX, true, &c_data, &c_size) >= 0);
        assert_se(rs_unhexmem_full(rs_buf, SIZE_MAX, true, &rs_data, &rs_size) >= 0);
        assert_se(c_data);
        assert_se(rs_data);
        ASSERT_EQ(c_size, rs_size);
        ASSERT_EQ(memcmp(c_data, rs_data, c_size), 0);
}

TEST(unbase64mem_secure_c_vs_rs) {
        char c_buf[] = "SGVsbG8=";
        char rs_buf[] = "SGVsbG8=";
        _cleanup_free_ void *c_data = NULL;
        _cleanup_free_ void *rs_data = NULL;
        size_t c_size = 0, rs_size = 0;

        assert_se(unbase64mem_full(c_buf, SIZE_MAX, true, &c_data, &c_size) >= 0);
        assert_se(rs_unbase64mem_full(rs_buf, SIZE_MAX, true, &rs_data, &rs_size) >= 0);
        assert_se(c_data);
        assert_se(rs_data);
        ASSERT_EQ(c_size, rs_size);
        ASSERT_EQ(c_size, 5u);
        ASSERT_EQ(memcmp(c_data, rs_data, c_size), 0);
}

/* ── base64_append ──────────────────────────────────────────────────────── */

TEST(base64_append_c_vs_rs) {
        const uint8_t data[] = "Hello, World! This is a test.";
        size_t data_len = strlen((const char *)data);

        /* C version */
        _cleanup_free_ char *c_prefix = strdup("PREFIX=");
        size_t c_plen = strlen("PREFIX=");
        ssize_t c_ret = base64_append(&c_prefix, c_plen, data, data_len, 4, 76);
        assert_se(c_ret >= 0);

        /* Rust version */
        _cleanup_free_ char *rs_prefix = strdup("PREFIX=");
        size_t rs_plen = strlen("PREFIX=");
        ssize_t rs_ret = rs_base64_append(&rs_prefix, rs_plen, data, data_len, 4, 76);
        assert_se(rs_ret >= 0);

        ASSERT_EQ(c_ret, rs_ret);
        ASSERT_STREQ(c_prefix, rs_prefix);
}

TEST(base64_append_short_prefix_c_vs_rs) {
        const uint8_t data[] = {0, 1, 2, 3, 4, 5};
        size_t data_len = sizeof(data);

        _cleanup_free_ char *c_prefix = strdup("X");
        size_t c_plen = 1;
        ssize_t c_ret = base64_append(&c_prefix, c_plen, data, data_len, 4, 20);
        assert_se(c_ret >= 0);

        _cleanup_free_ char *rs_prefix = strdup("X");
        size_t rs_plen = 1;
        ssize_t rs_ret = rs_base64_append(&rs_prefix, rs_plen, data, data_len, 4, 20);
        assert_se(rs_ret >= 0);

        ASSERT_EQ(c_ret, rs_ret);
        ASSERT_STREQ(c_prefix, rs_prefix);
}

TEST(base64_append_empty_data_c_vs_rs) {
        _cleanup_free_ char *c_prefix = strdup("X");
        size_t c_plen = 1;
        ssize_t c_ret = base64_append(&c_prefix, c_plen, NULL, 0, 4, 76);

        _cleanup_free_ char *rs_prefix = strdup("X");
        size_t rs_plen = 1;
        ssize_t rs_ret = rs_base64_append(&rs_prefix, rs_plen, NULL, 0, 4, 76);

        ASSERT_EQ(c_ret, rs_ret);
        ASSERT_EQ(c_ret, 1); /* returns plen when data is empty */
}

DEFINE_TEST_MAIN(LOG_INFO);
