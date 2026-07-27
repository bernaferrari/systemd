/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <string.h>

#include "tests.h"
#include "uid-range.h"
#include "rust/user_util.h"
#include "user-util.h"

/* Rust FFI */
#include "rust/uid_range.h"

/* Helper: create a UIDRange via C */
static UIDRange *make_range_c(uid_t start, uid_t nr) {
        _cleanup_(uid_range_freep) UIDRange *r = NULL;
        assert_se(uid_range_add(&r, start, nr) >= 0);
        return TAKE_PTR(r);
}

/* Helper: create a UIDRange via Rust */
static UIDRange *make_range_rust(uid_t start, uid_t nr) {
        UIDRange *r = NULL;
        assert_se(rs_uid_range_add_internal(&r, start, nr, true) >= 0);
        return r;
}

/* Helper: free Rust range */
static void free_rust(UIDRange *r) {
        rs_uid_range_free(r);
}

/* ── uid_range_covers / uid_range_contains ─────────────────────────────── */

TEST(uid_range_covers_basic) {
        UIDRange *cr = make_range_c(1000, 10);
        UIDRange *rr = make_range_rust(1000, 10);

        assert_se(uid_range_covers(cr, 1005, 1) == rs_uid_range_covers(rr, 1005, 1));
        assert_se(uid_range_covers(cr, 1005, 5) == rs_uid_range_covers(rr, 1005, 5));
        assert_se(uid_range_covers(cr, 1000, 10) == rs_uid_range_covers(rr, 1000, 10));
        assert_se(uid_range_covers(cr, 995, 1) == rs_uid_range_covers(rr, 995, 1));
        assert_se(uid_range_covers(cr, 1010, 1) == rs_uid_range_covers(rr, 1010, 1));

        uid_range_free(cr);
        free_rust(rr);
}

TEST(uid_range_covers_empty) {
        UIDRange *cr = make_range_c(1000, 10);
        UIDRange *rr = make_range_rust(1000, 10);

        assert_se(uid_range_covers(cr, 1005, 0) == rs_uid_range_covers(rr, 1005, 0));

        uid_range_free(cr);
        free_rust(rr);
}

TEST(uid_range_contains) {
        UIDRange *cr = make_range_c(1000, 10);
        UIDRange *rr = make_range_rust(1000, 10);

        assert_se(uid_range_contains(cr, 1005) == rs_uid_range_contains(rr, 1005));
        assert_se(uid_range_contains(cr, 999) == rs_uid_range_contains(rr, 999));
        assert_se(uid_range_contains(cr, 1010) == rs_uid_range_contains(rr, 1010));

        uid_range_free(cr);
        free_rust(rr);
}

TEST(uid_range_covers_null) {
        assert_se(uid_range_covers(NULL, 5, 1) == rs_uid_range_covers(NULL, 5, 1));
}

/* ── uid_range_overlaps ────────────────────────────────────────────────── */

TEST(uid_range_overlaps_basic) {
        UIDRange *cr = make_range_c(1000, 10);
        UIDRange *rr = make_range_rust(1000, 10);

        assert_se(uid_range_overlaps(cr, 1005, 5) == rs_uid_range_overlaps(rr, 1005, 5));
        assert_se(uid_range_overlaps(cr, 995, 10) == rs_uid_range_overlaps(rr, 995, 10));
        assert_se(uid_range_overlaps(cr, 1010, 5) == rs_uid_range_overlaps(rr, 1010, 5));
        assert_se(uid_range_overlaps(cr, 900, 50) == rs_uid_range_overlaps(rr, 900, 50));
        assert_se(uid_range_overlaps(cr, 2000, 10) == rs_uid_range_overlaps(rr, 2000, 10));

        uid_range_free(cr);
        free_rust(rr);
}

/* ── uid_range_size / uid_range_is_empty ───────────────────────────────── */

TEST(uid_range_size_basic) {
        UIDRange *cr = make_range_c(1000, 10);
        UIDRange *rr = make_range_rust(1000, 10);

        assert_se(uid_range_size(cr) == rs_uid_range_size(rr));

        uid_range_free(cr);
        free_rust(rr);
}

TEST(uid_range_is_empty_basic) {
        UIDRange *cr = make_range_c(1000, 10);
        UIDRange *rr = make_range_rust(1000, 10);

        assert_se(uid_range_is_empty(cr) == rs_uid_range_is_empty(rr));
        assert_se(uid_range_is_empty(NULL) == rs_uid_range_is_empty(NULL));

        uid_range_free(cr);
        free_rust(rr);
}

/* ── uid_range_equal ───────────────────────────────────────────────────── */

TEST(uid_range_equal_basic) {
        UIDRange *c1 = make_range_c(1000, 10);
        UIDRange *r1 = make_range_rust(1000, 10);
        UIDRange *c2 = make_range_c(2000, 5);
        UIDRange *r2 = make_range_rust(2000, 5);

        assert_se(uid_range_equal(c1, c1) == rs_uid_range_equal(r1, r1));
        assert_se(uid_range_equal(c1, c2) == rs_uid_range_equal(r1, r2));
        assert_se(uid_range_equal(c1, NULL) == rs_uid_range_equal(r1, NULL));

        uid_range_free(c1);
        free_rust(r1);
        uid_range_free(c2);
        free_rust(r2);
}

/* ── uid_range_base ────────────────────────────────────────────────────── */

TEST(uid_range_base_basic) {
        UIDRange *cr = make_range_c(1000, 10);
        UIDRange *rr = make_range_rust(1000, 10);

        assert_se(uid_range_base(cr) == rs_uid_range_base(rr));
        assert_se(uid_range_base(cr) == 1000);

        uid_range_free(cr);
        free_rust(rr);
}

TEST(uid_range_base_empty) {
        assert_se(uid_range_base(NULL) == rs_uid_range_base(NULL));
}

/* ── uid_range_next_lower ──────────────────────────────────────────────── */

TEST(uid_range_next_lower_inside) {
        UIDRange *cr = make_range_c(1000, 10);
        UIDRange *rr = make_range_rust(1000, 10);

        uid_t cu = 1005, ru = 1005;
        int cr_ret = uid_range_next_lower(cr, &cu);
        int rr_ret = rs_uid_range_next_lower(rr, &ru);
        assert_se(cr_ret == rr_ret);
        assert_se(cu == ru);

        uid_range_free(cr);
        free_rust(rr);
}

TEST(uid_range_next_lower_outside) {
        UIDRange *cr = make_range_c(1000, 10);
        UIDRange *rr = make_range_rust(1000, 10);

        uid_t cu = 500, ru = 500;
        int cr_ret = uid_range_next_lower(cr, &cu);
        int rr_ret = rs_uid_range_next_lower(rr, &ru);
        assert_se(cr_ret == rr_ret);
        assert_se(cu == ru);

        uid_range_free(cr);
        free_rust(rr);
}

/* ── uid_range_add coalescing ───────────────────────────────────────────── */

TEST(uid_range_add_coalesce) {
        UIDRange *cr = NULL, *rr = NULL;

        assert_se(uid_range_add(&cr, 1000, 10) >= 0);
        assert_se(uid_range_add(&cr, 1005, 10) >= 0);
        assert_se(rs_uid_range_add_internal(&rr, 1000, 10, true) >= 0);
        assert_se(rs_uid_range_add_internal(&rr, 1005, 10, true) >= 0);

        assert_se(uid_range_size(cr) == rs_uid_range_size(rr));
        assert_se(uid_range_equal(cr, rr));

        uid_range_free(cr);
        free_rust(rr);
}

/* ── uid_range_clip ────────────────────────────────────────────────────── */

TEST(uid_range_clip_basic) {
        UIDRange *cr = make_range_c(1000, 20);
        UIDRange *rr = make_range_rust(1000, 20);

        assert_se(uid_range_clip(cr, 1005, 1015) >= 0);
        assert_se(rs_uid_range_clip(rr, 1005, 1015) >= 0);

        assert_se(uid_range_equal(cr, rr));
        assert_se(uid_range_size(cr) == 11);

        uid_range_free(cr);
        free_rust(rr);
}

/* ── uid_range_copy ────────────────────────────────────────────────────── */

TEST(uid_range_copy_basic) {
        UIDRange *cr = make_range_c(1000, 10);
        UIDRange *rr = make_range_rust(1000, 10);

        UIDRange *cc = NULL, *rc = NULL;

        assert_se(uid_range_copy(cr, &cc) >= 0);
        assert_se(rs_uid_range_copy(rr, &rc) >= 0);

        assert_se(uid_range_equal(cr, cc));
        assert_se(rs_uid_range_equal(rr, rc));
        assert_se(uid_range_equal(cc, rc));

        uid_range_free(cr);
        free_rust(rr);
        uid_range_free(cc);
        free_rust(rc);
}

TEST(uid_range_copy_null) {
        UIDRange *cc = NULL, *rc = NULL;

        assert_se(uid_range_copy(NULL, &cc) >= 0);
        assert_se(rs_uid_range_copy(NULL, &rc) >= 0);
        assert_se(cc == NULL);
        assert_se(rc == NULL);
}

/* ── uid_range_remove ──────────────────────────────────────────────────── */

TEST(uid_range_remove_middle) {
        UIDRange *cr = make_range_c(1000, 20);
        UIDRange *rr = make_range_rust(1000, 20);

        assert_se(uid_range_remove(cr, 1005, 5) >= 0);
        assert_se(rs_uid_range_remove(rr, 1005, 5) >= 0);

        assert_se(uid_range_equal(cr, rr));
        assert_se(uid_range_size(cr) == 15);

        uid_range_free(cr);
        free_rust(rr);
}

TEST(uid_range_remove_split) {
        UIDRange *cr = make_range_c(1000, 20);
        UIDRange *rr = make_range_rust(1000, 20);

        assert_se(uid_range_remove(cr, 1005, 5) >= 0);
        assert_se(rs_uid_range_remove(rr, 1005, 5) >= 0);

        assert_se(!uid_range_contains(cr, 1007));
        assert_se(uid_range_contains(cr, 1002));
        assert_se(uid_range_contains(cr, 1015));

        uid_range_free(cr);
        free_rust(rr);
}

/* ── uid_range_translate ───────────────────────────────────────────────── */

TEST(uid_range_translate_basic) {
        UIDRange *co = NULL, *ci = NULL;
        UIDRange *ro = NULL, *ri = NULL;

        assert_se(uid_range_add(&co, 1000, 10) >= 0);
        assert_se(uid_range_add(&ci, 0, 10) >= 0);
        assert_se(rs_uid_range_add_internal(&ro, 1000, 10, true) >= 0);
        assert_se(rs_uid_range_add_internal(&ri, 0, 10, true) >= 0);

        uid_t ct, rt;
        assert_se(uid_range_translate(co, ci, 1005, &ct) >= 0);
        assert_se(rs_uid_range_translate(ro, ri, 1005, &rt) >= 0);
        assert_se(ct == rt);
        assert_se(ct == 5);

        assert_se(uid_range_translate(ci, co, 5, &ct) >= 0);
        assert_se(rs_uid_range_translate(ri, ro, 5, &rt) >= 0);
        assert_se(ct == rt);
        assert_se(ct == 1005);

        uid_range_free(co);
        uid_range_free(ci);
        free_rust(ro);
        free_rust(ri);
}

/* ── uid_range_partition ─────────────────────────────────────────────────── */

TEST(uid_range_partition_exact) {
        /* Entry exactly matches bucket size */
        UIDRange *cr = make_range_c(1000, 10);
        UIDRange *rr = make_range_rust(1000, 10);

        assert_se(uid_range_partition(cr, 10) >= 0);
        assert_se(rs_uid_range_partition(rr, 10) >= 0);

        assert_se(uid_range_equal(cr, rr));
        assert_se(uid_range_size(cr) == 10);
        assert_se(uid_range_entries(cr) == 1);

        uid_range_free(cr);
        free_rust(rr);
}

TEST(uid_range_partition_multiple) {
        /* Entry 20 UIDs partitioned into buckets of 5 → 4 entries */
        UIDRange *cr = make_range_c(1000, 20);
        UIDRange *rr = make_range_rust(1000, 20);

        assert_se(uid_range_partition(cr, 5) >= 0);
        assert_se(rs_uid_range_partition(rr, 5) >= 0);

        assert_se(uid_range_equal(cr, rr));
        assert_se(uid_range_size(cr) == 20);
        assert_se(uid_range_entries(cr) == 4);

        uid_range_free(cr);
        free_rust(rr);
}

TEST(uid_range_partition_with_remainder) {
        /* Entry 13 UIDs partitioned into buckets of 5 → 2 entries (10 UIDs), 3 leftover dropped */
        UIDRange *cr = make_range_c(1000, 13);
        UIDRange *rr = make_range_rust(1000, 13);

        assert_se(uid_range_partition(cr, 5) >= 0);
        assert_se(rs_uid_range_partition(rr, 5) >= 0);

        assert_se(uid_range_equal(cr, rr));
        assert_se(uid_range_size(cr) == 10);
        assert_se(uid_range_entries(cr) == 2);

        uid_range_free(cr);
        free_rust(rr);
}

TEST(uid_range_partition_too_small) {
        /* Entry smaller than bucket size → dropped entirely */
        UIDRange *cr = make_range_c(1000, 3);
        UIDRange *rr = make_range_rust(1000, 3);

        assert_se(uid_range_partition(cr, 5) >= 0);
        assert_se(rs_uid_range_partition(rr, 5) >= 0);

        assert_se(uid_range_equal(cr, rr));
        assert_se(uid_range_is_empty(cr));

        uid_range_free(cr);
        free_rust(rr);
}

TEST(uid_range_partition_multiple_entries) {
        /* Two entries: 1000-1019 and 2000-2009, partitioned into buckets of 5 */
        UIDRange *cr = NULL, *rr = NULL;

        assert_se(uid_range_add(&cr, 1000, 20) >= 0);
        assert_se(uid_range_add(&cr, 2000, 10) >= 0);
        assert_se(rs_uid_range_add_internal(&rr, 1000, 20, true) >= 0);
        assert_se(rs_uid_range_add_internal(&rr, 2000, 10, true) >= 0);

        assert_se(uid_range_partition(cr, 5) >= 0);
        assert_se(rs_uid_range_partition(rr, 5) >= 0);

        assert_se(uid_range_equal(cr, rr));
        assert_se(uid_range_size(cr) == 30);
        assert_se(uid_range_entries(cr) == 6);

        uid_range_free(cr);
        free_rust(rr);
}

TEST(uid_range_partition_bucket_size_1) {
        /* Each UID becomes its own entry */
        UIDRange *cr = make_range_c(1000, 5);
        UIDRange *rr = make_range_rust(1000, 5);

        assert_se(uid_range_partition(cr, 1) >= 0);
        assert_se(rs_uid_range_partition(rr, 1) >= 0);

        assert_se(uid_range_equal(cr, rr));
        assert_se(uid_range_size(cr) == 5);
        assert_se(uid_range_entries(cr) == 5);

        uid_range_free(cr);
        free_rust(rr);
}

/* ── parse_uid_range ─────────────────────────────────────────────────────── */

TEST(parse_uid_range_single) {
        uid_t cl, cu, rl, ru;
        int cr, rr;

        cr = parse_uid_range("1000", &cl, &cu);
        rr = rs_parse_uid_range("1000", &rl, &ru);
        assert_se(cr == rr);
        assert_se(cr == 0);
        assert_se(cl == rl && cl == 1000);
        assert_se(cu == ru && cu == 1000);
}

TEST(parse_uid_range_dash) {
        uid_t cl, cu, rl, ru;
        int cr, rr;

        cr = parse_uid_range("1000-2000", &cl, &cu);
        rr = rs_parse_uid_range("1000-2000", &rl, &ru);
        assert_se(cr == rr);
        assert_se(cr == 0);
        assert_se(cl == rl && cl == 1000);
        assert_se(cu == ru && cu == 2000);
}

TEST(parse_uid_range_trailing_dash) {
        uid_t cl, cu, rl, ru;
        int cr, rr;

        cr = parse_uid_range("1000-", &cl, &cu);
        rr = rs_parse_uid_range("1000-", &rl, &ru);
        assert_se(cr == rr);
        assert_se(cr == -EINVAL);
}

TEST(parse_uid_range_inverted) {
        uid_t cl, cu, rl, ru;
        int cr, rr;

        cr = parse_uid_range("2000-1000", &cl, &cu);
        rr = rs_parse_uid_range("2000-1000", &rl, &ru);
        assert_se(cr == rr);
        assert_se(cr == -EINVAL);
}

TEST(parse_uid_range_invalid) {
        uid_t cl, cu, rl, ru;
        int cr, rr;

        cr = parse_uid_range("abc", &cl, &cu);
        rr = rs_parse_uid_range("abc", &rl, &ru);
        assert_se(cr == rr);
        assert_se(cr < 0);

        cr = parse_uid_range("", &cl, &cu);
        rr = rs_parse_uid_range("", &rl, &ru);
        assert_se(cr == rr);
        assert_se(cr < 0);
}

TEST(parse_uid_range_zero) {
        uid_t cl, cu, rl, ru;
        int cr, rr;

        cr = parse_uid_range("0", &cl, &cu);
        rr = rs_parse_uid_range("0", &rl, &ru);
        assert_se(cr == rr);
        assert_se(cr == 0);
        assert_se(cl == 0);
}

TEST(parse_uid_range_max_valid) {
        uid_t cl, cu, rl, ru;
        int cr, rr;

        /* 65534 is valid (not -1) */
        cr = parse_uid_range("65534-65534", &cl, &cu);
        rr = rs_parse_uid_range("65534-65534", &rl, &ru);
        assert_se(cr == rr);
        assert_se(cr == 0);
        assert_se(cl == 65534);
}

TEST(parse_uid_range_invalid_uid_ffff) {
        uid_t cl, cu, rl, ru;
        int cr, rr;

        /* 65535 is invalid UID */
        cr = parse_uid_range("65535", &cl, &cu);
        rr = rs_parse_uid_range("65535", &rl, &ru);
        assert_se(cr == rr);
        assert_se(cr < 0);
}

/* ── uid_range_add_str_full ─────────────────────────────────────────────── */

TEST(uid_range_add_str_single) {
        _cleanup_(uid_range_freep) UIDRange *cr = NULL;
        UIDRange *rr = NULL;

        assert_se(uid_range_add_str(&cr, "1000") >= 0);
        assert_se(rs_uid_range_add_str_full(&rr, "1000", true) >= 0);

        assert_se(uid_range_equal(cr, rr));
        assert_se(uid_range_size(cr) == 1);
        assert_se(uid_range_contains(cr, 1000));

        rs_uid_range_free(rr);
}

TEST(uid_range_add_str_range) {
        _cleanup_(uid_range_freep) UIDRange *cr = NULL;
        UIDRange *rr = NULL;

        assert_se(uid_range_add_str(&cr, "1000-1010") >= 0);
        assert_se(rs_uid_range_add_str_full(&rr, "1000-1010", true) >= 0);

        assert_se(uid_range_equal(cr, rr));
        assert_se(uid_range_size(cr) == 11);
        assert_se(uid_range_contains(cr, 1005));
        assert_se(!uid_range_contains(cr, 999));
        assert_se(!uid_range_contains(cr, 1011));

        rs_uid_range_free(rr);
}

TEST(uid_range_add_str_coalesce) {
        _cleanup_(uid_range_freep) UIDRange *cr = NULL;
        UIDRange *rr = NULL;

        assert_se(uid_range_add_str(&cr, "1000-1010") >= 0);
        assert_se(uid_range_add_str(&cr, "1005-1020") >= 0);
        assert_se(rs_uid_range_add_str_full(&rr, "1000-1010", true) >= 0);
        assert_se(rs_uid_range_add_str_full(&rr, "1005-1020", true) >= 0);

        assert_se(uid_range_equal(cr, rr));

        rs_uid_range_free(rr);
}

TEST(uid_range_add_str_no_coalesce) {
        _cleanup_(uid_range_freep) UIDRange *cr = NULL;
        UIDRange *rr = NULL;

        assert_se(uid_range_add_str_full(&cr, "1000-1010", false) >= 0);
        assert_se(uid_range_add_str_full(&cr, "1005-1020", false) >= 0);
        assert_se(rs_uid_range_add_str_full(&rr, "1000-1010", false) >= 0);
        assert_se(rs_uid_range_add_str_full(&rr, "1005-1020", false) >= 0);

        assert_se(uid_range_equal(cr, rr));

        rs_uid_range_free(rr);
}

TEST(uid_range_add_str_invalid) {
        _cleanup_(uid_range_freep) UIDRange *cr = NULL;
        UIDRange *rr = NULL;

        int cr_ret = uid_range_add_str(&cr, "abc");
        int rr_ret = rs_uid_range_add_str_full(&rr, "abc", true);
        assert_se(cr_ret == rr_ret);
        assert_se(cr_ret < 0);

        rs_uid_range_free(rr);
}

/* ── main ────────────────────────────────────────────────────────────────── */

DEFINE_TEST_MAIN(LOG_INFO);
