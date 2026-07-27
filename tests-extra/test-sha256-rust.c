/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Shadow test: C SHA-256 core functions vs native Rust SHA-256 */

#include <assert.h>
#include <string.h>
#include "tests.h"
#include "sha256.h"
#include "hmac.h"
#include "hexdecoct.h"

/* Rust FFI */
#include "rust/sha256_hmac.h"

/* Helper: hex-encode a 32-byte digest for comparison */
static char *digest_hex(const uint8_t *digest) {
        char *hex;
        assert_se(hex = new(char, 65));
        for (int i = 0; i < 32; i++)
                sprintf(hex + i * 2, "%02x", digest[i]);
        hex[64] = '\0';
        return hex;
}

static void test_sha256_direct(void) {
        uint8_t c_result[32], rs_result[32];
        _cleanup_free_ char *c_hex = NULL, *rs_hex = NULL;

        /* Empty string */
        sha256_direct("", 0, c_result);
        rs_sha256_direct("", 0, rs_result);
        assert_se(memcmp(c_result, rs_result, 32) == 0);

        /* "abc" — FIPS 180-2 test vector */
        sha256_direct("abc", 3, c_result);
        rs_sha256_direct("abc", 3, rs_result);
        assert_se(memcmp(c_result, rs_result, 32) == 0);

        /* Known test vector from test-sha256.c */
        sha256_direct("abcdefghijklmnopqrstuvwxyz", 26, c_result);
        rs_sha256_direct("abcdefghijklmnopqrstuvwxyz", 26, rs_result);
        c_hex = digest_hex(c_result);
        rs_hex = digest_hex(rs_result);
        assert_se(streq(c_hex, rs_hex));
        assert_se(streq(c_hex, "71c480df93d6ae2f1efad1447c66c9525e316218cf51fc8d9ed832f2daf18b73"));
        free(c_hex); c_hex = NULL; free(rs_hex); rs_hex = NULL;

        /* Multi-block input (> 64 bytes) */
        const char *long_input = "0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789";
        sha256_direct(long_input, strlen(long_input), c_result);
        rs_sha256_direct(long_input, strlen(long_input), rs_result);
        c_hex = digest_hex(c_result);
        rs_hex = digest_hex(rs_result);
        assert_se(streq(c_hex, rs_hex));
        free(c_hex); c_hex = NULL; free(rs_hex); rs_hex = NULL;

        /* Exactly one block (64 bytes) */
        sha256_direct(long_input, 64, c_result);
        rs_sha256_direct(long_input, 64, rs_result);
        assert_se(memcmp(c_result, rs_result, 32) == 0);

        /* Exactly 55 bytes (padding fits in one block) */
        sha256_direct("abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstu", 55, c_result);
        rs_sha256_direct("abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstu", 55, rs_result);
        assert_se(memcmp(c_result, rs_result, 32) == 0);

        /* Exactly 56 bytes (needs extra block for padding) */
        sha256_direct("abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuv", 56, c_result);
        rs_sha256_direct("abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuv", 56, rs_result);
        assert_se(memcmp(c_result, rs_result, 32) == 0);

        /* One byte */
        sha256_direct("x", 1, c_result);
        rs_sha256_direct("x", 1, rs_result);
        assert_se(memcmp(c_result, rs_result, 32) == 0);

        /* 63 bytes (one short of a block) */
        {
                uint8_t data[63];
                memset(data, 0x42, sizeof(data));
                sha256_direct(data, 63, c_result);
                rs_sha256_direct(data, 63, rs_result);
                if (memcmp(c_result, rs_result, 32) != 0) {
                        fprintf(stderr, "C:  "); for (int i = 0; i < 32; i++) fprintf(stderr, "%02x", c_result[i]); fprintf(stderr, "\n");
                        fprintf(stderr, "RS: "); for (int i = 0; i < 32; i++) fprintf(stderr, "%02x", rs_result[i]); fprintf(stderr, "\n");
                }
                assert_se(memcmp(c_result, rs_result, 32) == 0);
        }

        /* 65 bytes (one past block boundary) */
        {
                uint8_t data[65];
                memset(data, 0x41, sizeof(data));
                sha256_direct(data, 65, c_result);
                rs_sha256_direct(data, 65, rs_result);
                assert_se(memcmp(c_result, rs_result, 32) == 0);
        }
}

static void test_sha256_incremental(void) {
        struct sha256_ctx c_ctx;
        struct rs_sha256_ctx rs_ctx;
        uint8_t c_result[32], rs_result[32];
        const char *input = "The quick brown fox jumps over the lazy dog";
        size_t len = strlen(input);

        /* Incremental: 10 + 20 + remaining */
        sha256_init_ctx(&c_ctx);
        sha256_process_bytes(input, 10, &c_ctx);
        sha256_process_bytes(input + 10, 20, &c_ctx);
        sha256_process_bytes(input + 30, len - 30, &c_ctx);
        sha256_finish_ctx(&c_ctx, c_result);

        rs_sha256_init_ctx(&rs_ctx);
        rs_sha256_process_bytes(input, 10, &rs_ctx);
        rs_sha256_process_bytes(input + 10, 20, &rs_ctx);
        rs_sha256_process_bytes(input + 30, len - 30, &rs_ctx);
        rs_sha256_finish_ctx(&rs_ctx, rs_result);

        assert_se(memcmp(c_result, rs_result, 32) == 0);

        /* One-shot should match incremental */
        uint8_t direct_result[32];
        sha256_direct(input, len, direct_result);
        assert_se(memcmp(c_result, direct_result, 32) == 0);
}

static void test_sha256_one_byte_at_a_time(void) {
        struct sha256_ctx c_ctx;
        struct rs_sha256_ctx rs_ctx;
        uint8_t c_result[32], rs_result[32];

        const char *input = "Hello, World!";
        size_t len = strlen(input);

        sha256_init_ctx(&c_ctx);
        rs_sha256_init_ctx(&rs_ctx);

        for (size_t i = 0; i < len; i++) {
                sha256_process_bytes(input + i, 1, &c_ctx);
                rs_sha256_process_bytes(input + i, 1, &rs_ctx);
        }

        sha256_finish_ctx(&c_ctx, c_result);
        rs_sha256_finish_ctx(&rs_ctx, rs_result);

        assert_se(memcmp(c_result, rs_result, 32) == 0);
}

static void test_sha256_block_boundary(void) {
        struct sha256_ctx c_ctx;
        struct rs_sha256_ctx rs_ctx;
        uint8_t c_result[32], rs_result[32];

        /* Feed exactly 64 bytes (one block), then one more byte */
        char buf[65];
        memset(buf, 'A', sizeof(buf));
        buf[64] = 'B';

        sha256_init_ctx(&c_ctx);
        rs_sha256_init_ctx(&rs_ctx);

        sha256_process_bytes(buf, 64, &c_ctx);
        sha256_process_bytes(buf + 64, 1, &c_ctx);
        sha256_finish_ctx(&c_ctx, c_result);

        rs_sha256_process_bytes(buf, 64, &rs_ctx);
        rs_sha256_process_bytes(buf + 64, 1, &rs_ctx);
        rs_sha256_finish_ctx(&rs_ctx, rs_result);

        assert_se(memcmp(c_result, rs_result, 32) == 0);

        /* Feed 63 bytes, then 1 byte (= one block) */
        sha256_init_ctx(&c_ctx);
        rs_sha256_init_ctx(&rs_ctx);

        sha256_process_bytes(buf, 63, &c_ctx);
        sha256_process_bytes(buf + 63, 1, &c_ctx);
        sha256_finish_ctx(&c_ctx, c_result);

        rs_sha256_process_bytes(buf, 63, &rs_ctx);
        rs_sha256_process_bytes(buf + 63, 1, &rs_ctx);
        rs_sha256_finish_ctx(&rs_ctx, rs_result);

        assert_se(memcmp(c_result, rs_result, 32) == 0);

        /* Feed 65 bytes, then 63 bytes (= two blocks) */
        sha256_init_ctx(&c_ctx);
        rs_sha256_init_ctx(&rs_ctx);

        sha256_process_bytes(buf, 65, &c_ctx);
        sha256_process_bytes(buf, 63, &c_ctx);
        sha256_finish_ctx(&c_ctx, c_result);

        rs_sha256_process_bytes(buf, 65, &rs_ctx);
        rs_sha256_process_bytes(buf, 63, &rs_ctx);
        rs_sha256_finish_ctx(&rs_ctx, rs_result);

        assert_se(memcmp(c_result, rs_result, 32) == 0);

        /* Feed 127 bytes, then 1 byte */
        sha256_init_ctx(&c_ctx);
        rs_sha256_init_ctx(&rs_ctx);

        sha256_process_bytes(buf, 65, &c_ctx);
        sha256_process_bytes(buf, 62, &c_ctx);
        sha256_finish_ctx(&c_ctx, c_result);

        rs_sha256_process_bytes(buf, 65, &rs_ctx);
        rs_sha256_process_bytes(buf, 62, &rs_ctx);
        rs_sha256_finish_ctx(&rs_ctx, rs_result);

        assert_se(memcmp(c_result, rs_result, 32) == 0);
}

static void test_sha256_hmac(void) {
        uint8_t c_result[32], rs_result[32];

        /* HMAC-SHA256 with short key */
        const char *key = "key";
        const char *msg = "The quick brown fox jumps over the lazy dog";

        hmac_sha256(key, strlen(key), msg, strlen(msg), c_result);
        rs_hmac_sha256(key, strlen(key), msg, strlen(msg), rs_result);
        assert_se(memcmp(c_result, rs_result, 32) == 0);

        /* HMAC-SHA256 with block-sized key */
        uint8_t block_key[64];
        memset(block_key, 0x0b, sizeof(block_key));
        hmac_sha256(block_key, sizeof(block_key), msg, strlen(msg), c_result);
        rs_hmac_sha256(block_key, sizeof(block_key), msg, strlen(msg), rs_result);
        assert_se(memcmp(c_result, rs_result, 32) == 0);

        /* HMAC-SHA256 with long key (> block size, gets hashed) */
        uint8_t long_key[100];
        memset(long_key, 0xaa, sizeof(long_key));
        hmac_sha256(long_key, sizeof(long_key), "test input", 10, c_result);
        rs_hmac_sha256(long_key, sizeof(long_key), "test input", 10, rs_result);
        assert_se(memcmp(c_result, rs_result, 32) == 0);

        /* HMAC-SHA256 with empty message */
        hmac_sha256(key, strlen(key), "", 0, c_result);
        rs_hmac_sha256(key, strlen(key), "", 0, rs_result);
        assert_se(memcmp(c_result, rs_result, 32) == 0);

        /* Deterministic: same inputs produce same output */
        uint8_t rs_result2[32], rs_result3[32];
        rs_hmac_sha256(key, strlen(key), msg, strlen(msg), rs_result2);
        rs_hmac_sha256(key, strlen(key), msg, strlen(msg), rs_result3);
        assert_se(memcmp(rs_result2, rs_result3, 32) == 0);

        /* RFC 4231 Test Case 2: Key="Jefe", Data="what do ya want for nothing?" */
        const char *rfc_key = "Jefe";
        const char *rfc_input = "what do ya want for nothing?";
        rs_hmac_sha256(rfc_key, strlen(rfc_key), rfc_input, strlen(rfc_input), rs_result);
        assert_se(rs_result[0] == 0x5b && rs_result[1] == 0xdc && rs_result[2] == 0xc1 && rs_result[3] == 0x46);

        /* RFC 4231 Test Case 6: Key > block size (131 bytes) */
        uint8_t rfc_long_key[131];
        memset(rfc_long_key, 0xaa, sizeof(rfc_long_key));
        rs_hmac_sha256(rfc_long_key, sizeof(rfc_long_key),
                       "Test Using Larger Than Block-Size Key - Hash Key First",
                       54, rs_result);
        assert_se(rs_result[0] == 0x60 && rs_result[1] == 0xe4 && rs_result[2] == 0x31 && rs_result[3] == 0x59);
}

static void test_sha256_validation(void) {
        assert_se(rs_sha256_is_valid("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
        assert_se(rs_sha256_is_valid("E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"));
        assert_se(!rs_sha256_is_valid(NULL));
        assert_se(!rs_sha256_is_valid(""));
        assert_se(!rs_sha256_is_valid("short"));
        assert_se(!rs_sha256_is_valid("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85500"));

        uint8_t buf[32];
        assert_se(rs_parse_sha256("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", buf) == 0);
        assert_se(buf[0] == 0xe3 && buf[1] == 0xb0);
        assert_se(rs_parse_sha256(NULL, buf) < 0);
        assert_se(rs_parse_sha256("invalid", buf) < 0);
}

int main(int argc, char **argv) {
        test_sha256_direct();
        test_sha256_incremental();
        test_sha256_one_byte_at_a_time();
        test_sha256_block_boundary();
        test_sha256_hmac();
        test_sha256_validation();
        return 0;
}
