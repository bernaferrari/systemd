/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Shadow test: C image-policy vs Rust rs_image_policy_* */
/* RUST-CONTRACT: image-policy-free */
/* RUST-CONTRACT: image-policy-lookup */
/* RUST-CONTRACT: image-policy-equal */
/* RUST-CONTRACT: image-policy-equivalent */
/* RUST-CONTRACT: image-policy-special-equivalence */
/* RUST-CONTRACT: image-policy-parse */
/* RUST-CONTRACT: image-policy-format */
/* RUST-CONTRACT: image-policy-set-operations */
/* RUST-CONTRACT: image-policy-fstype */

#include <stdlib.h>
#include <string.h>

#include "tests.h"
#include "image-policy.h"
#include "rust/image_policy_util.h"

/* ── partition_policy_flags_extend ─────────────────────────────────────── */
/* RUST-CONTRACT: image-policy-flags-extend */

TEST(partition_policy_flags_extend_zero) {
        int cr, rr;
        cr = partition_policy_flags_extend(0);
        rr = rs_partition_policy_flags_extend(0);
        assert_se(cr == rr);
        assert_se(cr != 0);
}

TEST(partition_policy_flags_extend_full) {
        int flags = PARTITION_POLICY_OPEN | PARTITION_POLICY_READ_ONLY_ON | PARTITION_POLICY_GROWFS_ON;
        assert_se(partition_policy_flags_extend(flags) == rs_partition_policy_flags_extend(flags));
}

TEST(partition_policy_flags_extend_partial) {
        int cr, rr;
        cr = partition_policy_flags_extend(PARTITION_POLICY_ENCRYPTED);
        rr = rs_partition_policy_flags_extend(PARTITION_POLICY_ENCRYPTED);
        assert_se(cr == rr);
        assert_se((cr & _PARTITION_POLICY_READ_ONLY_MASK) == _PARTITION_POLICY_READ_ONLY_MASK);
        assert_se((cr & _PARTITION_POLICY_GROWFS_MASK) == _PARTITION_POLICY_GROWFS_MASK);
}

TEST(partition_policy_flags_extend_negative) {
        int cr = partition_policy_flags_extend(-EINVAL);
        int rr = rs_partition_policy_flags_extend(-EINVAL);
        assert_se(cr == rr);
}

/* ── partition_policy_flags_reduce ─────────────────────────────────────── */
/* RUST-CONTRACT: image-policy-flags-reduce */

TEST(partition_policy_flags_reduce_zero) {
        assert_se(partition_policy_flags_reduce(0) == rs_partition_policy_flags_reduce(0));
}

TEST(partition_policy_flags_reduce_full) {
        assert_se(partition_policy_flags_reduce(PARTITION_POLICY_OPEN) == rs_partition_policy_flags_reduce(PARTITION_POLICY_OPEN));
        assert_se(partition_policy_flags_reduce(PARTITION_POLICY_OPEN) == 0);
}

TEST(partition_policy_flags_reduce_partial) {
        int cr = partition_policy_flags_reduce(PARTITION_POLICY_ENCRYPTED);
        int rr = rs_partition_policy_flags_reduce(PARTITION_POLICY_ENCRYPTED);
        assert_se(cr == rr);
        assert_se(cr == PARTITION_POLICY_ENCRYPTED);
}

/* ── partition_policy_flags_from_string ────────────────────────────────── */
/* RUST-CONTRACT: image-policy-flags-from-string */

TEST(flags_from_string_single) {
        int cr = partition_policy_flags_from_string("verity", false);
        int rr = rs_partition_policy_flags_from_string("verity", false);
        assert_se(cr == rr);
        assert_se(cr == PARTITION_POLICY_VERITY);
}

TEST(flags_from_string_multiple) {
        int cr = partition_policy_flags_from_string("verity+signed+encrypted", false);
        int rr = rs_partition_policy_flags_from_string("verity+signed+encrypted", false);
        assert_se(cr == rr);
}

TEST(flags_from_string_open_alias) {
        int cr = partition_policy_flags_from_string("open", false);
        int rr = rs_partition_policy_flags_from_string("open", false);
        assert_se(cr == rr);
        assert_se(cr == PARTITION_POLICY_OPEN);
}

TEST(flags_from_string_fstype) {
        int cr = partition_policy_flags_from_string("btrfs+encrypted", false);
        int rr = rs_partition_policy_flags_from_string("btrfs+encrypted", false);
        assert_se(cr == rr);
}

TEST(flags_from_string_readonly_growfs) {
        int cr = partition_policy_flags_from_string("read-only-on+growfs-off", false);
        int rr = rs_partition_policy_flags_from_string("read-only-on+growfs-off", false);
        assert_se(cr == rr);
}

TEST(flags_from_string_invalid) {
        int cr = partition_policy_flags_from_string("notarealflag", false);
        int rr = rs_partition_policy_flags_from_string("notarealflag", false);
        assert_se(cr == rr);
        assert_se(cr == -EBADRQC);
}

TEST(flags_from_string_graceful) {
        int cr = partition_policy_flags_from_string("verity+notarealflag", true);
        int rr = rs_partition_policy_flags_from_string("verity+notarealflag", true);
        assert_se(cr == rr);
        assert_se(cr == PARTITION_POLICY_VERITY);
}

TEST(flags_from_string_dash) {
        int cr = partition_policy_flags_from_string("-", false);
        int rr = rs_partition_policy_flags_from_string("-", false);
        assert_se(cr == rr);
        assert_se(cr == 0);
}

TEST(flags_from_string_empty) {
        int cr = partition_policy_flags_from_string("", false);
        int rr = rs_partition_policy_flags_from_string("", false);
        assert_se(cr == rr);
        assert_se(cr == 0);
}

TEST(flags_from_string_empty_segment) {
        int cr = partition_policy_flags_from_string("verity++signed", false);
        int rr = rs_partition_policy_flags_from_string("verity++signed", false);
        assert_se(cr == rr);
        assert_se(cr == -EBADRQC);

        cr = partition_policy_flags_from_string("verity++signed", true);
        rr = rs_partition_policy_flags_from_string("verity++signed", true);
        assert_se(cr == rr);
        assert_se(cr == (PARTITION_POLICY_VERITY | PARTITION_POLICY_SIGNED));
}

/* ── partition_policy_flags_to_string ──────────────────────────────────── */
/* RUST-CONTRACT: image-policy-flags-to-string */

TEST(flags_to_string_basic) {
        _cleanup_free_ char *cp = NULL, *rp = NULL;
        int cr, rr;

        cr = partition_policy_flags_to_string(PARTITION_POLICY_ENCRYPTED, false, &cp);
        rr = rs_partition_policy_flags_to_string(PARTITION_POLICY_ENCRYPTED, false, &rp);
        assert_se(cr == rr);
        assert_se(cr == 1);
        assert_se(streq(cp, rp));
        assert_se(streq(cp, "encrypted"));
}

TEST(flags_to_string_multiple) {
        _cleanup_free_ char *cp = NULL, *rp = NULL;
        int cr, rr;

        int flags = PARTITION_POLICY_VERITY | PARTITION_POLICY_SIGNED | PARTITION_POLICY_ENCRYPTED;
        cr = partition_policy_flags_to_string(flags, false, &cp);
        rr = rs_partition_policy_flags_to_string(flags, false, &rp);
        assert_se(cr == rr);
        assert_se(cr == 3);
        assert_se(streq(cp, rp));
}

TEST(flags_to_string_zero_simplify) {
        _cleanup_free_ char *cp = NULL, *rp = NULL;
        int cr, rr;

        cr = partition_policy_flags_to_string(0, true, &cp);
        rr = rs_partition_policy_flags_to_string(0, true, &rp);
        assert_se(cr == rr);
        assert_se(streq(cp, rp));
}

TEST(flags_to_string_invalid_flags) {
        char *cp = NULL, *rp = NULL;
        int cr, rr;

        cr = partition_policy_flags_to_string(-EINVAL, false, &cp);
        rr = rs_partition_policy_flags_to_string(-EINVAL, false, &rp);
        assert_se(cr == rr);
        assert_se(cr == -EINVAL);
}

TEST(flags_to_string_fstype) {
        _cleanup_free_ char *cp = NULL, *rp = NULL;
        int cr, rr;

        int flags = PARTITION_POLICY_ENCRYPTED | PARTITION_POLICY_EXT4;
        cr = partition_policy_flags_to_string(flags, false, &cp);
        rr = rs_partition_policy_flags_to_string(flags, false, &rp);
        assert_se(cr == rr);
        assert_se(streq(cp, rp));
}

/* ── image_policy_get ──────────────────────────────────────────────────── */

TEST(image_policy_get_null_policy) {
        /* NULL policy → open for all designators */
        for (int d = 0; d < _PARTITION_DESIGNATOR_MAX; d++) {
                int cr = image_policy_get(NULL, d);
                int rr = rs_image_policy_get(NULL, d);
                assert_se(cr == rr);
                assert_se(cr >= 0);
        }
}

TEST(image_policy_lookup_out_of_range_designator) {
        const int invalid = _PARTITION_DESIGNATOR_MAX;

        assert_se(image_policy_get(NULL, invalid) == rs_image_policy_get(NULL, invalid));
        assert_se(image_policy_get_exhaustively(NULL, invalid) ==
                  rs_image_policy_get_exhaustively(NULL, invalid));
}

TEST(image_policy_get_explicit) {
        _cleanup_(image_policy_freep) ImagePolicy *p = NULL;

        assert_se(image_policy_from_string("root=encrypted:usr=verity+signed:=absent", false, &p) >= 0);

        int cr = image_policy_get(p, PARTITION_ROOT);
        int rr = rs_image_policy_get(p, PARTITION_ROOT);
        assert_se(cr == rr);

        cr = image_policy_get(p, PARTITION_USR);
        rr = rs_image_policy_get(p, PARTITION_USR);
        assert_se(cr == rr);

        /* home → default (absent) */
        cr = image_policy_get(p, PARTITION_HOME);
        rr = rs_image_policy_get(p, PARTITION_HOME);
        assert_se(cr == rr);
}

/* ── image_policy_get_exhaustively ─────────────────────────────────────── */

TEST(image_policy_get_exhaustively_null) {
        for (int d = 0; d < _PARTITION_DESIGNATOR_MAX; d++) {
                int cr = image_policy_get_exhaustively(NULL, d);
                int rr = rs_image_policy_get_exhaustively(NULL, d);
                assert_se(cr == rr);
                assert_se(cr >= 0);
        }
}

/* ── image_policy_equal ────────────────────────────────────────────────── */

TEST(image_policy_equal_same) {
        _cleanup_(image_policy_freep) ImagePolicy *a = NULL, *b = NULL;

        assert_se(image_policy_from_string("root=encrypted:=absent", false, &a) >= 0);
        assert_se(image_policy_from_string("root=encrypted:=absent", false, &b) >= 0);

        assert_se(image_policy_equal(a, b));
        assert_se(rs_image_policy_equal(a, b));
}

TEST(image_policy_equal_null) {
        assert_se(image_policy_equal(NULL, NULL));
        assert_se(rs_image_policy_equal(NULL, NULL));
}

TEST(image_policy_equal_different) {
        _cleanup_(image_policy_freep) ImagePolicy *a = NULL, *b = NULL;

        assert_se(image_policy_from_string("root=encrypted", false, &a) >= 0);
        assert_se(image_policy_from_string("root=verity", false, &b) >= 0);

        assert_se(!image_policy_equal(a, b));
        assert_se(!rs_image_policy_equal(a, b));
}

TEST(image_policy_free_c_allocation) {
        ImagePolicy *p = NULL;

        assert_se(image_policy_from_string("root=encrypted:=absent", false, &p) >= 0);
        assert_se(p);
        assert_se(rs_image_policy_free(p) == NULL);
}

/* ── image_policy_equiv_* ──────────────────────────────────────────────── */

TEST(image_policy_equiv_null) {
        /* NULL policy = allow */
        assert_se(image_policy_equiv_allow(NULL) == rs_image_policy_equiv_allow(NULL));
        assert_se(image_policy_equiv_allow(NULL));
        assert_se(!image_policy_equiv_ignore(NULL));
        assert_se(!image_policy_equiv_deny(NULL));
}

TEST(image_policy_equiv_after_parse) {
        _cleanup_(image_policy_freep) ImagePolicy *p = NULL;

        assert_se(image_policy_from_string("root=verity+signed+encrypted:usr=verity+signed+encrypted:home=unprotected+unused+absent:esp=unprotected+unused+absent:xbootldr=unprotected+unused+absent:swap=unprotected+unused+absent:tmp=unprotected+unused+absent:var=unprotected+unused+absent:=unprotected+unused+absent", false, &p) >= 0);

        assert_se(image_policy_equiv_allow(p) == rs_image_policy_equiv_allow(p));
        assert_se(image_policy_equiv_ignore(p) == rs_image_policy_equiv_ignore(p));
        assert_se(image_policy_equiv_deny(p) == rs_image_policy_equiv_deny(p));
}

/* ── image_policy_equivalent ───────────────────────────────────────────── */

TEST(image_policy_equivalent_same) {
        _cleanup_(image_policy_freep) ImagePolicy *a = NULL, *b = NULL;

        assert_se(image_policy_from_string("root=encrypted", false, &a) >= 0);
        assert_se(image_policy_from_string("root=encrypted", false, &b) >= 0);

        assert_se(image_policy_equivalent(a, b) == 1);
        assert_se(rs_image_policy_equivalent(a, b) == 1);
}

TEST(image_policy_equivalent_null) {
        assert_se(image_policy_equivalent(NULL, NULL) == 1);
        assert_se(rs_image_policy_equivalent(NULL, NULL) == 1);
}

/* ── image_policy_free ─────────────────────────────────────────────────── */

TEST(image_policy_free_null) {
        assert_se(image_policy_free(NULL) == NULL);
        assert_se(rs_image_policy_free(NULL) == NULL);
}

/* ── image_policy_from_string / image_policy_to_string ─────────────────── */

TEST(image_policy_parse_and_format) {
        _cleanup_(image_policy_freep) ImagePolicy *cp = NULL, *rp = NULL;
        _cleanup_free_ char *cs = NULL, *rs = NULL;
        const char *input = "root=encrypted+ext4:usr=verity+signed:=unprotected";
        int cr, rr;

        cr = image_policy_from_string(input, false, &cp);
        rr = rs_image_policy_from_string(input, false, &rp);
        assert_se(cr == rr);
        assert_se(cr == 0);
        assert_se(image_policy_equal(cp, rp));

        cr = image_policy_to_string(cp, true, &cs);
        rr = rs_image_policy_to_string(rp, true, &rs);
        assert_se(cr == rr);
        assert_se(streq(cs, rs));
}

TEST(image_policy_parse_validation_only_and_strict_separators) {
        const char *invalid[] = { " ", "root=encrypted::usr=signed", "root=encrypted:" };

        assert_se(image_policy_from_string("root=encrypted", false, NULL) ==
                  rs_image_policy_from_string("root=encrypted", false, NULL));
        assert_se(image_policy_from_string("root=encrypted\\+signed", false, NULL) ==
                  rs_image_policy_from_string("root=encrypted\\+signed", false, NULL));

        FOREACH_ARRAY(s, invalid, ELEMENTSOF(invalid))
                assert_se(image_policy_from_string(*s, false, NULL) ==
                          rs_image_policy_from_string(*s, false, NULL));
}

/* ── image_policy_intersect / image_policy_union ───────────────────────── */

TEST(image_policy_set_operations) {
        _cleanup_(image_policy_freep) ImagePolicy *a = NULL, *b = NULL, *ci = NULL, *ri = NULL, *cu = NULL, *ru = NULL;
        int cr, rr;

        assert_se(image_policy_from_string("root=encrypted+ext4:usr=signed", false, &a) == 0);
        assert_se(image_policy_from_string("root=encrypted+xfs:usr=signed", false, &b) == 0);

        cr = image_policy_intersect(a, b, &ci);
        rr = rs_image_policy_intersect(a, b, &ri);
        assert_se(cr == rr);
        assert_se(cr == 0);
        assert_se(image_policy_equal(ci, ri));

        cr = image_policy_union(a, b, &cu);
        rr = rs_image_policy_union(a, b, &ru);
        assert_se(cr == rr);
        assert_se(cr == 0);
        assert_se(image_policy_equal(cu, ru));

        assert_se(image_policy_union(a, b, NULL) == rs_image_policy_union(a, b, NULL));
}

/* ── partition_policy_determine_fstype ─────────────────────────────────── */

TEST(image_policy_fstype) {
        _cleanup_(image_policy_freep) ImagePolicy *p = NULL;
        _cleanup_free_ char *cfstype = NULL, *rfstype = NULL;
        bool cencrypted, rencrypted;
        int cr, rr;

        assert_se(image_policy_from_string("root=encrypted+ext4", false, &p) == 0);
        cr = partition_policy_determine_fstype(p, PARTITION_ROOT, &cencrypted, &cfstype);
        rr = rs_partition_policy_determine_fstype(p, PARTITION_ROOT, &rencrypted, &rfstype);
        assert_se(cr == rr);
        assert_se(cr == 1);
        assert_se(cencrypted == rencrypted);
        assert_se(streq(cfstype, rfstype));

        free(cfstype);
        free(rfstype);
        cfstype = rfstype = NULL;
        p = image_policy_free(p);
        assert_se(image_policy_from_string("root=ext4+xfs", false, &p) == 0);
        cr = partition_policy_determine_fstype(p, PARTITION_ROOT, &cencrypted, &cfstype);
        rr = rs_partition_policy_determine_fstype(p, PARTITION_ROOT, &rencrypted, &rfstype);
        assert_se(cr == rr);
        assert_se(cr == 0);
        assert_se(cfstype == NULL && rfstype == NULL);
        assert_se(cencrypted == rencrypted);
}

/* ── main ──────────────────────────────────────────────────────────────── */

DEFINE_TEST_MAIN(LOG_INFO);
