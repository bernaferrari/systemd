/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <string.h>

#include "tests.h"
#include "sha256.h"
#include "hmac.h"

/* Rust FFI */
#include "rust/sha256_hmac.h"

/* ── sha256_is_valid ─────────────────────────────────────────────────── */

TEST(sha256_is_valid_correct) {
        const char *valid = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        assert_se(sha256_is_valid(valid) == rs_sha256_is_valid(valid));
        assert_se(sha256_is_valid(valid));
}

TEST(sha256_is_valid_uppercase) {
        const char *valid = "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855";
        assert_se(sha256_is_valid(valid) == rs_sha256_is_valid(valid));
        assert_se(sha256_is_valid(valid));
}

TEST(sha256_is_valid_mixed) {
        const char *valid = "e3B0c44298Fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        assert_se(sha256_is_valid(valid) == rs_sha256_is_valid(valid));
        assert_se(sha256_is_valid(valid));
}

TEST(sha256_is_valid_too_short) {
        const char *s = "e3b0c44298fc1c149afbf4c8996fb924";
        assert_se(sha256_is_valid(s) == rs_sha256_is_valid(s));
        assert_se(!sha256_is_valid(s));
}

TEST(sha256_is_valid_too_long) {
        const char *s = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85500";
        assert_se(sha256_is_valid(s) == rs_sha256_is_valid(s));
        assert_se(!sha256_is_valid(s));
}

TEST(sha256_is_valid_invalid_chars) {
        const char *s = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85g";
        assert_se(sha256_is_valid(s) == rs_sha256_is_valid(s));
        assert_se(!sha256_is_valid(s));
}

TEST(sha256_is_valid_null) {
        assert_se(sha256_is_valid(NULL) == rs_sha256_is_valid(NULL));
        assert_se(!sha256_is_valid(NULL));
}

TEST(sha256_is_valid_empty) {
        assert_se(sha256_is_valid("") == rs_sha256_is_valid(""));
        assert_se(!sha256_is_valid(""));
}

/* ── parse_sha256 ────────────────────────────────────────────────────── */

TEST(parse_sha256_correct) {
        const char *hex = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        uint8_t c_ret[32], r_ret[32];

        int cr = parse_sha256(hex, c_ret);
        int rr = rs_parse_sha256(hex, r_ret);

        assert_se(cr == rr);
        assert_se(cr >= 0);
        assert_se(memcmp(c_ret, r_ret, 32) == 0);
}

TEST(parse_sha256_invalid) {
        const char *hex = "not-a-sha256";
        uint8_t c_ret[32], r_ret[32];

        int cr = parse_sha256(hex, c_ret);
        int rr = rs_parse_sha256(hex, r_ret);

        assert_se(cr == rr);
        assert_se(cr < 0);
}

TEST(parse_sha256_empty_string) {
        uint8_t c_ret[32], r_ret[32];

        int cr = parse_sha256("", c_ret);
        int rr = rs_parse_sha256("", r_ret);

        assert_se(cr == rr);
        assert_se(cr < 0);
}

/* ── hmac_sha256 ─────────────────────────────────────────────────────── */

/* Known test vector: RFC 4231 Test Case 2 */
TEST(hmac_sha256_rfc4231_tc2) {
        const char *key = "Jefe";
        const char *data = "what do ya want for nothing?";
        /* Expected HMAC-SHA256: 5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843 */
        const uint8_t expected[32] = {
                0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e,
                0x6a, 0x04, 0x24, 0x26, 0x08, 0x95, 0x75, 0xc7,
                0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27, 0x39, 0x83,
                0x9d, 0xec, 0x58, 0xb9, 0x64, 0xec, 0x38, 0x43,
        };

        uint8_t c_res[32], r_res[32];
        memset(c_res, 0, sizeof(c_res));
        memset(r_res, 0, sizeof(r_res));

        hmac_sha256(key, strlen(key), data, strlen(data), c_res);
        rs_hmac_sha256(key, strlen(key), data, strlen(data), r_res);

        assert_se(memcmp(c_res, r_res, 32) == 0);
        assert_se(memcmp(c_res, expected, 32) == 0);
}

/* Known test vector: RFC 4231 Test Case 1 (key < block size) */
TEST(hmac_sha256_rfc4231_tc1) {
        const uint8_t key[20] = {
                0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
                0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
                0x0b, 0x0b, 0x0b, 0x0b,
        };
        const char *data = "Hi There";
        /* Expected: b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7 */
        const uint8_t expected[32] = {
                0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53,
                0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b, 0xf1, 0x2b,
                0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7,
                0x26, 0xe9, 0x37, 0x6c, 0x2e, 0x32, 0xcf, 0xf7,
        };

        uint8_t c_res[32], r_res[32];

        hmac_sha256(key, 20, data, strlen(data), c_res);
        rs_hmac_sha256(key, 20, data, strlen(data), r_res);

        assert_se(memcmp(c_res, r_res, 32) == 0);
        assert_se(memcmp(c_res, expected, 32) == 0);
}

/* Test with key > block size (hashes key first) */
TEST(hmac_sha256_long_key) {
        /* 80-byte key (longer than 64-byte block size) */
        uint8_t key[80];
        for (int i = 0; i < 80; i++)
                key[i] = (uint8_t)(0xaa);

        const char *data = "Test Using Larger Than Block-Size Key - Hash Key First";

        uint8_t c_res[32], r_res[32];

        hmac_sha256(key, 80, data, strlen(data), c_res);
        rs_hmac_sha256(key, 80, data, strlen(data), r_res);

        assert_se(memcmp(c_res, r_res, 32) == 0);
}

/* Empty input data */
TEST(hmac_sha256_empty_input) {
        const char *key = "key";
        uint8_t c_res[32], r_res[32];

        hmac_sha256(key, strlen(key), "", 0, c_res);
        rs_hmac_sha256(key, strlen(key), "", 0, r_res);

        assert_se(memcmp(c_res, r_res, 32) == 0);
}

/* ── main ────────────────────────────────────────────────────────────── */

DEFINE_TEST_MAIN(LOG_INFO);
