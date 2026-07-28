/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <string.h>

#include "format-util.h"
#include "tests.h"

/* Rust FFI */
#include "rust/format_util.h"

#define BUF_SIZE 32

/* RUST-CONTRACT: format-bytes-full */
TEST(format_bytes_zero) {
        char cb[BUF_SIZE], rb[BUF_SIZE];
        char *cr = format_bytes(cb, BUF_SIZE, 0);
        char *rr = rs_format_bytes_full(rb, BUF_SIZE, 0, FORMAT_BYTES_USE_IEC | FORMAT_BYTES_BELOW_POINT | FORMAT_BYTES_TRAILING_B);
        assert_se(cr != NULL);
        assert_se(rr != NULL);
        assert_se(streq(cr, rr));
}

TEST(format_bytes_small) {
        char cb[BUF_SIZE], rb[BUF_SIZE];
        char *cr = format_bytes(cb, BUF_SIZE, 512);
        char *rr = rs_format_bytes_full(rb, BUF_SIZE, 512, FORMAT_BYTES_USE_IEC | FORMAT_BYTES_BELOW_POINT | FORMAT_BYTES_TRAILING_B);
        assert_se(cr != NULL);
        assert_se(rr != NULL);
        assert_se(streq(cr, rr));
}

TEST(format_bytes_one_kib) {
        char cb[BUF_SIZE], rb[BUF_SIZE];
        char *cr = format_bytes(cb, BUF_SIZE, 1024);
        char *rr = rs_format_bytes_full(rb, BUF_SIZE, 1024, FORMAT_BYTES_USE_IEC | FORMAT_BYTES_BELOW_POINT | FORMAT_BYTES_TRAILING_B);
        assert_se(cr != NULL);
        assert_se(rr != NULL);
        assert_se(streq(cr, rr));
}

TEST(format_bytes_mib) {
        char cb[BUF_SIZE], rb[BUF_SIZE];
        char *cr = format_bytes(cb, BUF_SIZE, 1024 * 1024);
        char *rr = rs_format_bytes_full(rb, BUF_SIZE, 1024 * 1024, FORMAT_BYTES_USE_IEC | FORMAT_BYTES_BELOW_POINT | FORMAT_BYTES_TRAILING_B);
        assert_se(cr != NULL);
        assert_se(rr != NULL);
        assert_se(streq(cr, rr));
}

TEST(format_bytes_gib) {
        char cb[BUF_SIZE], rb[BUF_SIZE];
        char *cr = format_bytes(cb, BUF_SIZE, 1024ULL * 1024 * 1024 * 1024);
        char *rr = rs_format_bytes_full(rb, BUF_SIZE, 1024ULL * 1024 * 1024 * 1024, FORMAT_BYTES_USE_IEC | FORMAT_BYTES_BELOW_POINT | FORMAT_BYTES_TRAILING_B);
        assert_se(cr != NULL);
        assert_se(rr != NULL);
        assert_se(streq(cr, rr));
}

TEST(format_bytes_max) {
        char cb[BUF_SIZE], rb[BUF_SIZE];
        char *cr = format_bytes(cb, BUF_SIZE, UINT64_MAX);
        char *rr = rs_format_bytes_full(rb, BUF_SIZE, UINT64_MAX, FORMAT_BYTES_USE_IEC | FORMAT_BYTES_BELOW_POINT | FORMAT_BYTES_TRAILING_B);
        assert_se(cr == NULL);
        assert_se(rr == NULL);
}

TEST(format_bytes_wrapping_final_bucket) {
        char cb[BUF_SIZE], rb[BUF_SIZE];
        char *cr = format_bytes_full(cb, BUF_SIZE, UINT64_MAX - 1, FORMAT_BYTES_USE_IEC | FORMAT_BYTES_BELOW_POINT | FORMAT_BYTES_TRAILING_B);
        char *rr = rs_format_bytes_full(rb, BUF_SIZE, UINT64_MAX - 1, FORMAT_BYTES_USE_IEC | FORMAT_BYTES_BELOW_POINT | FORMAT_BYTES_TRAILING_B);
        assert_se(cr != NULL);
        assert_se(rr != NULL);
        assert_se(streq(cr, rr));
}

TEST(format_bytes_no_trailing_b) {
        char cb[BUF_SIZE], rb[BUF_SIZE];
        char *cr = format_bytes_full(cb, BUF_SIZE, 1500, FORMAT_BYTES_USE_IEC | FORMAT_BYTES_BELOW_POINT);
        char *rr = rs_format_bytes_full(rb, BUF_SIZE, 1500, FORMAT_BYTES_USE_IEC | FORMAT_BYTES_BELOW_POINT);
        assert_se(cr != NULL);
        assert_se(rr != NULL);
        assert_se(streq(cr, rr));
}

TEST(format_bytes_si) {
        char cb[BUF_SIZE], rb[BUF_SIZE];
        char *cr = format_bytes_full(cb, BUF_SIZE, 1500, FORMAT_BYTES_BELOW_POINT | FORMAT_BYTES_TRAILING_B);
        char *rr = rs_format_bytes_full(rb, BUF_SIZE, 1500, FORMAT_BYTES_BELOW_POINT | FORMAT_BYTES_TRAILING_B);
        assert_se(cr != NULL);
        assert_se(rr != NULL);
        assert_se(streq(cr, rr));
}

TEST(format_bytes_always_point) {
        char cb[BUF_SIZE], rb[BUF_SIZE];
        char *cr = format_bytes_full(cb, BUF_SIZE, 1024, FORMAT_BYTES_USE_IEC | FORMAT_BYTES_ALWAYS_POINT | FORMAT_BYTES_TRAILING_B);
        char *rr = rs_format_bytes_full(rb, BUF_SIZE, 1024, FORMAT_BYTES_USE_IEC | FORMAT_BYTES_ALWAYS_POINT | FORMAT_BYTES_TRAILING_B);
        assert_se(cr != NULL);
        assert_se(rr != NULL);
        assert_se(streq(cr, rr));
}

TEST(format_bytes_single_byte_buffer) {
        char cb[1], rb[1];
        char *cr = format_bytes_full(cb, sizeof(cb), 1536, FORMAT_BYTES_USE_IEC | FORMAT_BYTES_BELOW_POINT);
        char *rr = rs_format_bytes_full(rb, sizeof(rb), 1536, FORMAT_BYTES_USE_IEC | FORMAT_BYTES_BELOW_POINT);
        assert_se(cr == cb);
        assert_se(rr == rb);
        assert_se(cb[0] == 0);
        assert_se(rb[0] == 0);
}

TEST(format_bytes_tib) {
        char cb[BUF_SIZE], rb[BUF_SIZE];
        char *cr = format_bytes(cb, BUF_SIZE, 1024ULL * 1024 * 1024 * 1024 * 1024);
        char *rr = rs_format_bytes_full(rb, BUF_SIZE, 1024ULL * 1024 * 1024 * 1024 * 1024, FORMAT_BYTES_USE_IEC | FORMAT_BYTES_BELOW_POINT | FORMAT_BYTES_TRAILING_B);
        assert_se(cr != NULL);
        assert_se(rr != NULL);
        assert_se(streq(cr, rr));
}

/* ── main ────────────────────────────────────────────────────────────────── */

DEFINE_TEST_MAIN(LOG_INFO);
