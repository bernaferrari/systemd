/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Shadow test: memory-util.h / ratelimit.h / gpt.h / condition.h inline wrappers vs Rust */

#include <string.h>
#include <stdlib.h>
#include "tests.h"
#include "memory-util.h"
#include "ratelimit.h"
#include "gpt.h"
#include "condition.h"

/* Rust FFI */
#include "rust/memory_util.h"
#include "rust/ratelimit.h"
#include "rust/gpt_util.h"

/* ── memcpy_safe ──────────────────────────────────────────────────────── */

TEST(memcpy_safe_basic) {
        char src[] = "hello";
        char dst_c[6] = {}, dst_r[6] = {};
        assert_se(memcpy_safe(dst_c, src, 6) == dst_c);
        assert_se(rs_memcpy_safe(dst_r, src, 6) == dst_r);
        assert_se(memcmp(dst_c, dst_r, 6) == 0);
        assert_se(streq(dst_c, "hello"));
}

TEST(memcpy_safe_zero) {
        unsigned char dst_c[1], dst_r[1];
        memset(dst_c, 0xFF, sizeof(dst_c));
        memset(dst_r, 0xFF, sizeof(dst_r));
        assert_se(memcpy_safe(dst_c, NULL, 0) == dst_c);
        assert_se(rs_memcpy_safe(dst_r, NULL, 0) == dst_r);
        assert_se(dst_c[0] == 0xFF);
        assert_se(dst_r[0] == 0xFF);
}

/* ── mempcpy_safe ─────────────────────────────────────────────────────── */

TEST(mempcpy_safe_basic) {
        char src[] = "hello";
        char buf_c[10] = {}, buf_r[10] = {};
        void *ret_c = mempcpy_safe(buf_c, src, 6);
        void *ret_r = rs_mempcpy_safe(buf_r, src, 6);
        assert_se(ret_c == buf_c + 6);
        assert_se(ret_r == buf_r + 6);
        assert_se(memcmp(buf_c, buf_r, 10) == 0);
}

/* ── memcmp_safe ──────────────────────────────────────────────────────── */

TEST(memcmp_safe_basic) {
        assert_se(memcmp_safe("abc", "abc", 3) == rs_memcmp_safe("abc", "abc", 3));
        assert_se(memcmp_safe("abc", "abd", 3) == rs_memcmp_safe("abc", "abd", 3));
        assert_se(memcmp_safe("abc", "abd", 3) < 0);
        assert_se(memcmp_safe("abd", "abc", 3) == rs_memcmp_safe("abd", "abc", 3));
}

TEST(memcmp_safe_zero) {
        assert_se(memcmp_safe(NULL, NULL, 0) == 0);
        assert_se(rs_memcmp_safe(NULL, NULL, 0) == 0);
}

/* ── memcmp_nn ────────────────────────────────────────────────────────── */

TEST(memcmp_nn_equal) {
        assert_se(memcmp_nn("hello", 5, "hello", 5) == 0);
        assert_se(rs_memcmp_nn("hello", 5, "hello", 5) == 0);
}

TEST(memcmp_nn_prefix) {
        assert_se(memcmp_nn("hello", 3, "helicopter", 3) == 0);
        assert_se(rs_memcmp_nn("hello", 3, "helicopter", 3) == 0);
}

TEST(memcmp_nn_shorter) {
        assert_se(memcmp_nn("hel", 3, "help", 4) == rs_memcmp_nn("hel", 3, "help", 4));
        assert_se(memcmp_nn("hel", 3, "help", 4) < 0);
}

TEST(memcmp_nn_longer) {
        assert_se(memcmp_nn("help", 4, "hel", 3) == rs_memcmp_nn("help", 4, "hel", 3));
        assert_se(memcmp_nn("help", 4, "hel", 3) > 0);
}

TEST(memcmp_nn_diff) {
        assert_se(memcmp_nn("abc", 3, "abd", 3) == rs_memcmp_nn("abc", 3, "abd", 3));
        assert_se(memcmp_nn("abc", 3, "abd", 3) < 0);
}

TEST(memcmp_nn_empty) {
        assert_se(memcmp_nn("", 0, "", 0) == 0);
        assert_se(rs_memcmp_nn("", 0, "", 0) == 0);
}

/* ── mempset ──────────────────────────────────────────────────────────── */

TEST(mempset_basic) {
        char buf_c[10] = {}, buf_r[10] = {};
        void *ret_c = mempset(buf_c, 'X', 5);
        void *ret_r = rs_mempset(buf_r, 'X', 5);
        assert_se(ret_c == buf_c + 5);
        assert_se(ret_r == buf_r + 5);
        assert_se(memcmp(buf_c, buf_r, 10) == 0);
        assert_se(buf_c[0] == 'X' && buf_c[4] == 'X');
}

/* ── memmem_safe ──────────────────────────────────────────────────────── */

TEST(memmem_safe_found) {
        const char *hay = "hello world";
        void *cv = memmem_safe(hay, 11, "world", 5);
        void *rv = rs_memmem_safe(hay, 11, "world", 5);
        assert_se(cv != NULL);
        assert_se(rv != NULL);
        assert_se(cv == rv);
}

TEST(memmem_safe_not_found) {
        const char *hay = "hello world";
        void *cv = memmem_safe(hay, 11, "xyz", 3);
        void *rv = rs_memmem_safe(hay, 11, "xyz", 3);
        assert_se(cv == NULL);
        assert_se(rv == NULL);
}

TEST(memmem_safe_empty_needle) {
        const char *hay = "hello";
        void *cv = memmem_safe(hay, 5, "", 0);
        void *rv = rs_memmem_safe(hay, 5, "", 0);
        assert_se(cv == hay);
        assert_se(rv == hay);
}

TEST(memmem_safe_haystack_too_short) {
        const char *hay = "hi";
        void *cv = memmem_safe(hay, 2, "hello", 5);
        void *rv = rs_memmem_safe(hay, 2, "hello", 5);
        assert_se(cv == NULL);
        assert_se(rv == NULL);
}

/* ── mempmem_safe ─────────────────────────────────────────────────────── */

TEST(mempmem_safe_found) {
        const char *hay = "hello world";
        void *cv = mempmem_safe(hay, 11, "world", 5);
        void *rv = rs_mempmem_safe(hay, 11, "world", 5);
        assert_se(cv != NULL);
        assert_se(rv != NULL);
        assert_se(cv == rv);
        /* Returns pointer past "world" = NUL terminator */
        assert_se(streq((char*)cv, ""));
}

TEST(mempmem_safe_not_found) {
        const char *hay = "hello world";
        void *cv = mempmem_safe(hay, 11, "xyz", 3);
        void *rv = rs_mempmem_safe(hay, 11, "xyz", 3);
        assert_se(cv == NULL);
        assert_se(rv == NULL);
}

/* ── ratelimit_reset / configured ─────────────────────────────────────── */

TEST(ratelimit_reset) {
        RateLimit rc = { .interval = 1000, .burst = 5, .num = 3, .begin = 42 };
        RateLimit rr = { .interval = 1000, .burst = 5, .num = 3, .begin = 42 };
        ratelimit_reset(&rc);
        rs_ratelimit_reset(&rr);
        assert_se(rc.num == 0 && rc.begin == 0);
        assert_se(rr.num == 0 && rr.begin == 0);
}

TEST(ratelimit_configured) {
        RateLimit rl = { .interval = 1000, .burst = 5 };
        assert_se(ratelimit_configured(&rl) == rs_ratelimit_configured(&rl));
        assert_se(ratelimit_configured(&rl) == true);

        RateLimit rl2 = { .interval = 0, .burst = 5 };
        assert_se(ratelimit_configured(&rl2) == rs_ratelimit_configured(&rl2));
        assert_se(ratelimit_configured(&rl2) == false);

        RateLimit rl3 = { .interval = 1000, .burst = 0 };
        assert_se(ratelimit_configured(&rl3) == rs_ratelimit_configured(&rl3));
        assert_se(ratelimit_configured(&rl3) == false);

        /* C version has no null guard — only test Rust null safety */
        assert_se(!rs_ratelimit_configured(NULL));
}

/* RUST-CONTRACT: gpt-verity-predicates */
/* ── partition_designator_is_verity_* ─────────────────────────────────── */

TEST(partition_designator_is_verity_hash) {
        assert_se(partition_designator_is_verity_hash(PARTITION_ROOT_VERITY) == rs_partition_designator_is_verity_hash(PARTITION_ROOT_VERITY));
        assert_se(partition_designator_is_verity_hash(PARTITION_ROOT) == rs_partition_designator_is_verity_hash(PARTITION_ROOT));
        assert_se(partition_designator_is_verity_hash(PARTITION_ROOT_VERITY) == true);
        assert_se(partition_designator_is_verity_hash(PARTITION_ROOT) == false);
}

TEST(partition_designator_is_verity_sig) {
        assert_se(partition_designator_is_verity_sig(PARTITION_ROOT_VERITY_SIG) == rs_partition_designator_is_verity_sig(PARTITION_ROOT_VERITY_SIG));
        assert_se(partition_designator_is_verity_sig(PARTITION_ROOT) == rs_partition_designator_is_verity_sig(PARTITION_ROOT));
}

TEST(partition_designator_is_verity) {
        assert_se(partition_designator_is_verity(PARTITION_ROOT_VERITY) == rs_partition_designator_is_verity(PARTITION_ROOT_VERITY));
        assert_se(partition_designator_is_verity(PARTITION_ROOT) == rs_partition_designator_is_verity(PARTITION_ROOT));
}

DEFINE_TEST_MAIN(LOG_INFO);
