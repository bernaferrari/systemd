/* SPDX-License-Identifier: LicenseRef-murmurhash2-public-domain */

#include <inttypes.h>
#include <string.h>

#include "MurmurHash2.h"
#include "tests.h"

/* Rust FFI */
#include "rust/murmurhash2.h"

/* RUST-CONTRACT: murmurhash2-byte-hash */
/* ── Known-answer tests ────────────────────────────────────────────────── */

TEST(murmurhash2_empty) {
        uint32_t cr = MurmurHash2("", 0, 0);
        uint32_t rr = rs_MurmurHash2("", 0, 0);
        assert_se(cr == rr);
}

TEST(murmurhash2_empty_with_seed) {
        uint32_t cr = MurmurHash2("", 0, 42);
        uint32_t rr = rs_MurmurHash2("", 0, 42);
        assert_se(cr == rr);
}

TEST(murmurhash2_null_zero_length) {
        uint32_t cr = MurmurHash2(NULL, 0, 42);
        uint32_t rr = rs_MurmurHash2(NULL, 0, 42);
        assert_se(cr == rr);
}

TEST(murmurhash2_negative_length) {
        uint32_t cr = MurmurHash2(NULL, -1, 42);
        uint32_t rr = rs_MurmurHash2(NULL, -1, 42);
        assert_se(cr == rr);
}

TEST(murmurhash2_hello) {
        uint32_t cr = MurmurHash2("hello", 5, 0);
        uint32_t rr = rs_MurmurHash2("hello", 5, 0);
        assert_se(cr == rr);
}

TEST(murmurhash2_hello_seed) {
        uint32_t cr = MurmurHash2("hello", 5, 0x12345678);
        uint32_t rr = rs_MurmurHash2("hello", 5, 0x12345678);
        assert_se(cr == rr);
}

TEST(murmurhash2_four_bytes) {
        uint32_t cr = MurmurHash2("abcd", 4, 0);
        uint32_t rr = rs_MurmurHash2("abcd", 4, 0);
        assert_se(cr == rr);
}

TEST(murmurhash2_three_bytes) {
        uint32_t cr = MurmurHash2("abc", 3, 0);
        uint32_t rr = rs_MurmurHash2("abc", 3, 0);
        assert_se(cr == rr);
}

TEST(murmurhash2_two_bytes) {
        uint32_t cr = MurmurHash2("ab", 2, 0);
        uint32_t rr = rs_MurmurHash2("ab", 2, 0);
        assert_se(cr == rr);
}

TEST(murmurhash2_one_byte) {
        uint32_t cr = MurmurHash2("a", 1, 0);
        uint32_t rr = rs_MurmurHash2("a", 1, 0);
        assert_se(cr == rr);
}

TEST(murmurhash2_longer) {
        const char *msg = "The quick brown fox jumps over the lazy dog";
        uint32_t cr = MurmurHash2(msg, strlen(msg), 0);
        uint32_t rr = rs_MurmurHash2(msg, strlen(msg), 0);
        assert_se(cr == rr);
}

TEST(murmurhash2_binary) {
        uint8_t data[8] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
        uint32_t cr = MurmurHash2(data, 8, 0);
        uint32_t rr = rs_MurmurHash2(data, 8, 0);
        assert_se(cr == rr);
}

TEST(murmurhash2_seven_bytes) {
        uint8_t data[7] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
        uint32_t cr = MurmurHash2(data, 7, 0);
        uint32_t rr = rs_MurmurHash2(data, 7, 0);
        assert_se(cr == rr);
}

TEST(murmurhash2_five_bytes) {
        uint8_t data[5] = { 0xde, 0xad, 0xbe, 0xef, 0x42 };
        uint32_t cr = MurmurHash2(data, 5, 0);
        uint32_t rr = rs_MurmurHash2(data, 5, 0);
        assert_se(cr == rr);
}

TEST(murmurhash2_deterministic) {
        /* Same input must always produce same output */
        uint32_t a = rs_MurmurHash2("test", 4, 0);
        uint32_t b = rs_MurmurHash2("test", 4, 0);
        assert_se(a == b);
}

TEST(murmurhash2_different_seeds_differ) {
        uint32_t a = rs_MurmurHash2("test", 4, 0);
        uint32_t b = rs_MurmurHash2("test", 4, 1);
        /* With high probability these should differ */
        assert_se(a != b);
}

/* ── main ────────────────────────────────────────────────────────────────── */

DEFINE_TEST_MAIN(LOG_INFO);
