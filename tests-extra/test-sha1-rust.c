/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <assert.h>
#include <string.h>

#include "tests.h"

/* C SHA-1 is in src/fundamental/ and available through libshared */
#include "sha1.h"
#include "rust/sha1.h"

/* Known test vectors from FIPS 180-1 */

static void test_sha1_empty(void) {
        /* SHA-1("") = da39a3ee5e6b4b0d3255bfef95601890afd80709 */
        const uint8_t expected[20] = {
                0xda, 0x39, 0xa3, 0xee, 0x5e, 0x6b, 0x4b, 0x0d,
                0x32, 0x55, 0xbf, 0xef, 0x95, 0x60, 0x18, 0x90,
                0xaf, 0xd8, 0x07, 0x09,
        };

        struct sha1_ctx c_ctx;
        uint8_t c_result[20];
        sha1_init_ctx(&c_ctx);
        sha1_finish_ctx(&c_ctx, c_result);
        assert_se(memcmp(c_result, expected, 20) == 0);

        struct rs_sha1_ctx r_ctx;
        uint8_t r_result[20];
        rs_sha1_init_ctx(&r_ctx);
        rs_sha1_finish_ctx(&r_ctx, r_result);
        assert_se(memcmp(r_result, expected, 20) == 0);

        assert_se(memcmp(c_result, r_result, 20) == 0);
}

static void test_sha1_abc(void) {
        /* SHA-1("abc") = a9993e364706816aba3e25717850c26c9cd0d89d */
        const uint8_t expected[20] = {
                0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a,
                0xba, 0x3e, 0x25, 0x71, 0x78, 0x50, 0xc2, 0x6c,
                0x9c, 0xd0, 0xd8, 0x9d,
        };
        const char *input = "abc";

        struct sha1_ctx c_ctx;
        uint8_t c_result[20];
        sha1_init_ctx(&c_ctx);
        sha1_process_bytes(input, strlen(input), &c_ctx);
        sha1_finish_ctx(&c_ctx, c_result);
        assert_se(memcmp(c_result, expected, 20) == 0);

        struct rs_sha1_ctx r_ctx;
        uint8_t r_result[20];
        rs_sha1_init_ctx(&r_ctx);
        rs_sha1_process_bytes(input, strlen(input), &r_ctx);
        rs_sha1_finish_ctx(&r_ctx, r_result);
        assert_se(memcmp(r_result, expected, 20) == 0);

        assert_se(memcmp(c_result, r_result, 20) == 0);
}

static void test_sha1_long(void) {
        /* SHA-1("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")
         * = 84983e441c3bd26ebaae4aa1f95129e5e54670f1 */
        const uint8_t expected[20] = {
                0x84, 0x98, 0x3e, 0x44, 0x1c, 0x3b, 0xd2, 0x6e,
                0xba, 0xae, 0x4a, 0xa1, 0xf9, 0x51, 0x29, 0xe5,
                0xe5, 0x46, 0x70, 0xf1,
        };
        const char *input = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";

        struct sha1_ctx c_ctx;
        uint8_t c_result[20];
        sha1_init_ctx(&c_ctx);
        sha1_process_bytes(input, strlen(input), &c_ctx);
        sha1_finish_ctx(&c_ctx, c_result);

        struct rs_sha1_ctx r_ctx;
        uint8_t r_result[20];
        rs_sha1_init_ctx(&r_ctx);
        rs_sha1_process_bytes(input, strlen(input), &r_ctx);
        rs_sha1_finish_ctx(&r_ctx, r_result);

        assert_se(memcmp(c_result, expected, 20) == 0);
        assert_se(memcmp(c_result, r_result, 20) == 0);
}

static void test_sha1_multi_chunk(void) {
        /* Feed data in multiple chunks to test buffering */
        const char *input = "The quick brown fox jumps over the lazy dog";
        const uint8_t expected[20] = {
                0x2f, 0xd4, 0xe1, 0xc6, 0x7a, 0x2d, 0x28, 0xfc,
                0xed, 0x84, 0x9e, 0xe1, 0xbb, 0x76, 0xe7, 0x39,
                0x1b, 0x93, 0xeb, 0x12,
        };

        struct sha1_ctx c_ctx;
        uint8_t c_result[20];
        sha1_init_ctx(&c_ctx);
        /* Feed 10 bytes at a time */
        for (size_t i = 0; i < strlen(input); i += 10) {
                size_t chunk = strlen(input) - i;
                if (chunk > 10) chunk = 10;
                sha1_process_bytes(input + i, chunk, &c_ctx);
        }
        sha1_finish_ctx(&c_ctx, c_result);
        assert_se(memcmp(c_result, expected, 20) == 0);

        struct rs_sha1_ctx r_ctx;
        uint8_t r_result[20];
        rs_sha1_init_ctx(&r_ctx);
        for (size_t i = 0; i < strlen(input); i += 10) {
                size_t chunk = strlen(input) - i;
                if (chunk > 10) chunk = 10;
                rs_sha1_process_bytes(input + i, chunk, &r_ctx);
        }
        rs_sha1_finish_ctx(&r_ctx, r_result);
        assert_se(memcmp(r_result, expected, 20) == 0);

        assert_se(memcmp(c_result, r_result, 20) == 0);
}

static void test_sha1_single_byte(void) {
        /* Feed one byte at a time */
        const char *input = "Hello, World!";
        size_t len = strlen(input);

        struct sha1_ctx c_ctx;
        uint8_t c_result[20];
        sha1_init_ctx(&c_ctx);
        for (size_t i = 0; i < len; i++)
                sha1_process_bytes(input + i, 1, &c_ctx);
        sha1_finish_ctx(&c_ctx, c_result);

        struct rs_sha1_ctx r_ctx;
        uint8_t r_result[20];
        rs_sha1_init_ctx(&r_ctx);
        for (size_t i = 0; i < len; i++)
                rs_sha1_process_bytes(input + i, 1, &r_ctx);
        rs_sha1_finish_ctx(&r_ctx, r_result);

        assert_se(memcmp(c_result, r_result, 20) == 0);
}

static void test_sha1_block_boundary(void) {
        /* Test exactly at 64-byte block boundary */
        char input[64];
        memset(input, 'A', sizeof(input));

        struct sha1_ctx c_ctx;
        uint8_t c_result[20];
        sha1_init_ctx(&c_ctx);
        sha1_process_bytes(input, 64, &c_ctx);
        sha1_finish_ctx(&c_ctx, c_result);

        struct rs_sha1_ctx r_ctx;
        uint8_t r_result[20];
        rs_sha1_init_ctx(&r_ctx);
        rs_sha1_process_bytes(input, 64, &r_ctx);
        rs_sha1_finish_ctx(&r_ctx, r_result);

        assert_se(memcmp(c_result, r_result, 20) == 0);
}

static void test_sha1_block_plus_one(void) {
        /* Test 65 bytes (just over one block) */
        char input[65];
        memset(input, 'B', sizeof(input));

        struct sha1_ctx c_ctx;
        uint8_t c_result[20];
        sha1_init_ctx(&c_ctx);
        sha1_process_bytes(input, 65, &c_ctx);
        sha1_finish_ctx(&c_ctx, c_result);

        struct rs_sha1_ctx r_ctx;
        uint8_t r_result[20];
        rs_sha1_init_ctx(&r_ctx);
        rs_sha1_process_bytes(input, 65, &r_ctx);
        rs_sha1_finish_ctx(&r_ctx, r_result);

        assert_se(memcmp(c_result, r_result, 20) == 0);
}

int main(int argc, char *argv[]) {
        test_sha1_empty();
        test_sha1_abc();
        test_sha1_long();
        test_sha1_multi_chunk();
        test_sha1_single_byte();
        test_sha1_block_boundary();
        test_sha1_block_plus_one();

        return 0;
}
