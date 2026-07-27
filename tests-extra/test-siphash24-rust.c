/* SPDX-License-Identifier: CC0-1.0 */

#include <inttypes.h>
#include <string.h>

#include "siphash24.h"
#include "tests.h"

/* Rust FFI */
#include "rust/siphash24.h"

/* ── Known-answer test vectors ─────────────────────────────────────────── */

/* Key of 16 zero bytes */
static const uint8_t zero_key[16] = {};

/* Key: 0x0102030405060708090a0b0c0d0e0f10 */
static const uint8_t seq_key[16] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
};

TEST(siphash24_empty) {
        uint64_t cr = siphash24("", 0, zero_key);
        uint64_t rr = rs_siphash24("", 0, zero_key);
        assert_se(cr == rr);
}

TEST(siphash24_empty_seq_key) {
        uint64_t cr = siphash24("", 0, seq_key);
        uint64_t rr = rs_siphash24("", 0, seq_key);
        assert_se(cr == rr);
}

TEST(siphash24_hello) {
        uint64_t cr = siphash24("hello", 5, zero_key);
        uint64_t rr = rs_siphash24("hello", 5, zero_key);
        assert_se(cr == rr);
}

TEST(siphash24_hello_seq_key) {
        uint64_t cr = siphash24("hello", 5, seq_key);
        uint64_t rr = rs_siphash24("hello", 5, seq_key);
        assert_se(cr == rr);
}

TEST(siphash24_longer) {
        const char *msg = "The quick brown fox jumps over the lazy dog";
        uint64_t cr = siphash24(msg, strlen(msg), zero_key);
        uint64_t rr = rs_siphash24(msg, strlen(msg), zero_key);
        assert_se(cr == rr);
}

TEST(siphash24_binary) {
        uint8_t data[8] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
        uint64_t cr = siphash24(data, 8, zero_key);
        uint64_t rr = rs_siphash24(data, 8, zero_key);
        assert_se(cr == rr);
}

TEST(siphash24_seven_bytes) {
        uint8_t data[7] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
        uint64_t cr = siphash24(data, 7, zero_key);
        uint64_t rr = rs_siphash24(data, 7, zero_key);
        assert_se(cr == rr);
}

TEST(siphash24_one_byte) {
        uint8_t data[1] = { 0x42 };
        uint64_t cr = siphash24(data, 1, zero_key);
        uint64_t rr = rs_siphash24(data, 1, zero_key);
        assert_se(cr == rr);
}

/* ── siphash24_string ──────────────────────────────────────────────────── */

TEST(siphash24_string_hello) {
        uint64_t cr = siphash24_string("hello", zero_key);
        uint64_t rr = rs_siphash24_string("hello", zero_key);
        assert_se(cr == rr);
        /* siphash24_string includes NUL in the hash */
        assert_se(cr != siphash24("hello", 5, zero_key));
}

TEST(siphash24_string_empty) {
        uint64_t cr = siphash24_string("", zero_key);
        uint64_t rr = rs_siphash24_string("", zero_key);
        assert_se(cr == rr);
}

/* ── Incremental API (init/compress/finalize) ───────────────────────────── */

TEST(siphash24_incremental) {
        struct siphash cs;
        struct rs_siphash rs;

        siphash24_init(&cs, seq_key);
        rs_siphash24_init(&rs, seq_key);

        /* Compress in two chunks */
        siphash24_compress("hello", 5, &cs);
        rs_siphash24_compress("hello", 5, &rs);

        siphash24_compress(" world", 6, &cs);
        rs_siphash24_compress(" world", 6, &rs);

        uint64_t cr = siphash24_finalize(&cs);
        uint64_t rr = rs_siphash24_finalize(&rs);
        assert_se(cr == rr);

        /* Compare with one-shot */
        uint64_t c_one = siphash24("hello world", 11, seq_key);
        uint64_t r_one = rs_siphash24("hello world", 11, seq_key);
        assert_se(cr == c_one);
        assert_se(rr == r_one);
}

TEST(siphash24_compress_string) {
        struct siphash cs;
        struct rs_siphash rs;

        siphash24_init(&cs, zero_key);
        rs_siphash24_init(&rs, zero_key);

        siphash24_compress_string("hello", &cs);
        rs_siphash24_compress_string("hello", &rs);

        uint64_t cr = siphash24_finalize(&cs);
        uint64_t rr = rs_siphash24_finalize(&rs);
        assert_se(cr == rr);

        /* compress_string does NOT include NUL, unlike siphash24_string */
        uint64_t cs2 = siphash24("hello", 5, zero_key);
        uint64_t rs2 = rs_siphash24("hello", 5, zero_key);
        assert_se(cr == cs2);
        assert_se(rr == rs2);

        /* Verify they differ from siphash24_string (which includes NUL) */
        uint64_t cs3 = siphash24_string("hello", zero_key);
        uint64_t rs3 = rs_siphash24_string("hello", zero_key);
        assert_se(cr != cs3);
        assert_se(rr != rs3);
}

/* ── main ────────────────────────────────────────────────────────────────── */

DEFINE_TEST_MAIN(LOG_INFO);
