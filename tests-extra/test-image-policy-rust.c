/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Shadow test: C image-policy vs Rust rs_image_policy_* */

#include <stdlib.h>
#include <string.h>

#include "tests.h"
#include "image-policy.h"
#include "rust/image_policy_util.h"

/* ── partition_policy_flags_extend ─────────────────────────────────────── */

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

/* ── partition_policy_flags_to_string ──────────────────────────────────── */

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

/* ── image_policy_from_string (symbolic) ───────────────────────────────── */

TEST(image_policy_from_string_ignore) {
        _cleanup_(image_policy_freep) ImagePolicy *cp = NULL;
        _cleanup_(image_policy_freep) ImagePolicy *rp = NULL;
        int cr, rr;

        cr = image_policy_from_string("-", false, &cp);
        rr = rs_image_policy_from_string("-", false, &rp);
        assert_se(cr == rr);
        assert_se(cr == 0);
        assert_se(image_policy_equiv_ignore(cp));
        assert_se(rs_image_policy_equiv_ignore(rp));
        assert_se(image_policy_equal(cp, rp));
}

TEST(image_policy_from_string_allow) {
        _cleanup_(image_policy_freep) ImagePolicy *cp = NULL;
        _cleanup_(image_policy_freep) ImagePolicy *rp = NULL;
        int cr, rr;

        cr = image_policy_from_string("*", false, &cp);
        rr = rs_image_policy_from_string("*", false, &rp);
        assert_se(cr == rr);
        assert_se(cr == 0);
        assert_se(image_policy_equiv_allow(cp));
        assert_se(rs_image_policy_equiv_allow(rp));
        assert_se(image_policy_equal(cp, rp));
}

TEST(image_policy_from_string_deny) {
        _cleanup_(image_policy_freep) ImagePolicy *cp = NULL;
        _cleanup_(image_policy_freep) ImagePolicy *rp = NULL;
        int cr, rr;

        cr = image_policy_from_string("~", false, &cp);
        rr = rs_image_policy_from_string("~", false, &rp);
        assert_se(cr == rr);
        assert_se(image_policy_equiv_deny(cp));
        assert_se(rs_image_policy_equiv_deny(rp));
        assert_se(image_policy_equal(cp, rp));
}

TEST(image_policy_from_string_empty) {
        _cleanup_(image_policy_freep) ImagePolicy *cp = NULL;
        _cleanup_(image_policy_freep) ImagePolicy *rp = NULL;
        int cr, rr;

        cr = image_policy_from_string("", false, &cp);
        rr = rs_image_policy_from_string("", false, &rp);
        assert_se(cr == rr);
        assert_se(cr == 0);
        assert_se(image_policy_equal(cp, rp));
}

/* ── image_policy_from_string (complex) ────────────────────────────────── */

TEST(image_policy_from_string_complex) {
        _cleanup_(image_policy_freep) ImagePolicy *cp = NULL;
        _cleanup_(image_policy_freep) ImagePolicy *rp = NULL;
        int cr, rr;

        cr = image_policy_from_string("root=verity+signed+encrypted:usr=verity+signed:=absent", false, &cp);
        rr = rs_image_policy_from_string("root=verity+signed+encrypted:usr=verity+signed:=absent", false, &rp);
        assert_se(cr == rr);
        assert_se(cr == 0);
        assert_se(image_policy_equal(cp, rp));
        assert_se(image_policy_equivalent(cp, rp) == 1);
        assert_se(rs_image_policy_equivalent(cp, rp) == 1);
}

TEST(image_policy_from_string_default_only) {
        _cleanup_(image_policy_freep) ImagePolicy *cp = NULL;
        _cleanup_(image_policy_freep) ImagePolicy *rp = NULL;
        int cr, rr;

        cr = image_policy_from_string("=verity+encrypted", false, &cp);
        rr = rs_image_policy_from_string("=verity+encrypted", false, &rp);
        assert_se(cr == rr);
        assert_se(cr == 0);
        assert_se(image_policy_equal(cp, rp));
}

TEST(image_policy_from_string_readonly_growfs) {
        _cleanup_(image_policy_freep) ImagePolicy *cp = NULL;
        _cleanup_(image_policy_freep) ImagePolicy *rp = NULL;
        int cr, rr;

        cr = image_policy_from_string("root=encrypted+read-only-on+growfs-off:=ignore", false, &cp);
        rr = rs_image_policy_from_string("root=encrypted+read-only-on+growfs-off:=ignore", false, &rp);
        assert_se(cr == rr);
        assert_se(cr == 0);
        assert_se(image_policy_equal(cp, rp));
}

TEST(image_policy_from_string_fstype) {
        _cleanup_(image_policy_freep) ImagePolicy *cp = NULL;
        _cleanup_(image_policy_freep) ImagePolicy *rp = NULL;
        int cr, rr;

        cr = image_policy_from_string("root=encrypted+ext4:usr=verity+signed+btrfs", false, &cp);
        rr = rs_image_policy_from_string("root=encrypted+ext4:usr=verity+signed+btrfs", false, &rp);
        assert_se(cr == rr);
        assert_se(cr == 0);
        assert_se(image_policy_equal(cp, rp));
}

TEST(image_policy_from_string_duplicate_designator) {
        _cleanup_(image_policy_freep) ImagePolicy *cp = NULL;
        _cleanup_(image_policy_freep) ImagePolicy *rp = NULL;
        int cr, rr;

        cr = image_policy_from_string("root=encrypted:root=verity", false, &cp);
        rr = rs_image_policy_from_string("root=encrypted:root=verity", false, &rp);
        assert_se(cr == rr);
        assert_se(cr == -ENOTUNIQ);
}

TEST(image_policy_from_string_unknown_designator) {
        _cleanup_(image_policy_freep) ImagePolicy *cp = NULL;
        _cleanup_(image_policy_freep) ImagePolicy *rp = NULL;
        int cr, rr;

        cr = image_policy_from_string("nonsense=encrypted", false, &cp);
        rr = rs_image_policy_from_string("nonsense=encrypted", false, &rp);
        assert_se(cr == rr);
        assert_se(cr == -EBADSLT);
}

TEST(image_policy_from_string_unknown_designator_graceful) {
        _cleanup_(image_policy_freep) ImagePolicy *cp = NULL;
        _cleanup_(image_policy_freep) ImagePolicy *rp = NULL;
        int cr, rr;

        cr = image_policy_from_string("root=encrypted:nonsense=verity", true, &cp);
        rr = rs_image_policy_from_string("root=encrypted:nonsense=verity", true, &rp);
        assert_se(cr == rr);
        assert_se(cr == 0);
        assert_se(image_policy_equal(cp, rp));
}

TEST(image_policy_from_string_duplicate_default) {
        _cleanup_(image_policy_freep) ImagePolicy *cp = NULL;
        _cleanup_(image_policy_freep) ImagePolicy *rp = NULL;
        int cr, rr;

        cr = image_policy_from_string("=encrypted:=verity", false, &cp);
        rr = rs_image_policy_from_string("=encrypted:=verity", false, &rp);
        assert_se(cr == rr);
        assert_se(cr == -ENOTUNIQ);
}

TEST(image_policy_from_string_ret_null) {
        int cr = image_policy_from_string("*", false, NULL);
        int rr = rs_image_policy_from_string("*", false, NULL);
        assert_se(cr == rr);
        assert_se(cr == 0);
}

/* ── image_policy_to_string ────────────────────────────────────────────── */

TEST(image_policy_to_string_ignore) {
        _cleanup_(image_policy_freep) ImagePolicy *p = NULL;
        _cleanup_free_ char *cs = NULL, *rs = NULL;
        int cr, rr;

        assert_se(image_policy_from_string("-", false, &p) >= 0);
        cr = image_policy_to_string(p, true, &cs);
        rr = rs_image_policy_to_string(p, true, &rs);
        assert_se(cr == rr);
        assert_se(streq(cs, rs));
        assert_se(streq(cs, "-"));
}

TEST(image_policy_to_string_allow) {
        _cleanup_(image_policy_freep) ImagePolicy *p = NULL;
        _cleanup_free_ char *cs = NULL, *rs = NULL;
        int cr, rr;

        assert_se(image_policy_from_string("*", false, &p) >= 0);
        cr = image_policy_to_string(p, true, &cs);
        rr = rs_image_policy_to_string(p, true, &rs);
        assert_se(cr == rr);
        assert_se(streq(cs, rs));
        assert_se(streq(cs, "*"));
}

TEST(image_policy_to_string_complex) {
        _cleanup_(image_policy_freep) ImagePolicy *p = NULL;
        _cleanup_free_ char *cs = NULL, *rs = NULL;
        int cr, rr;

        assert_se(image_policy_from_string("root=verity+signed+encrypted:=absent", false, &p) >= 0);
        cr = image_policy_to_string(p, false, &cs);
        rr = rs_image_policy_to_string(p, false, &rs);
        assert_se(cr == rr);
        assert_se(streq(cs, rs));
}

TEST(image_policy_to_string_null_ret) {
        _cleanup_(image_policy_freep) ImagePolicy *p = NULL;
        int rr;

        assert_se(rs_image_policy_from_string("*", false, &p) >= 0);
        /* C version has assert_se(ret) so can't call with NULL; test Rust only */
        rr = rs_image_policy_to_string(p, false, NULL);
        assert_se(rr == -EINVAL);
}

/* ── image_policy_to_string roundtrip ──────────────────────────────────── */

TEST(image_policy_to_string_roundtrip) {
        const char *input = "root=verity+signed+encrypted+read-only-on+ext4:home=absent:=ignore";
        _cleanup_(image_policy_freep) ImagePolicy *cp = NULL, *cp2 = NULL;
        _cleanup_free_ char *cs = NULL;
        int cr;

        cr = image_policy_from_string(input, false, &cp);
        assert_se(cr == 0);

        cr = image_policy_to_string(cp, false, &cs);
        assert_se(cr >= 0);

        cr = image_policy_from_string(cs, false, &cp2);
        assert_se(cr == 0);

        assert_se(image_policy_equivalent(cp, cp2) > 0);
}

TEST(rs_image_policy_to_string_roundtrip) {
        const char *input = "root=verity+signed+encrypted+read-only-on+ext4:home=absent:=ignore";
        _cleanup_(image_policy_freep) ImagePolicy *rp = NULL, *rp2 = NULL;
        _cleanup_free_ char *rs = NULL;
        int rr;

        rr = rs_image_policy_from_string(input, false, &rp);
        assert_se(rr == 0);

        rr = rs_image_policy_to_string(rp, false, &rs);
        assert_se(rr >= 0);

        rr = rs_image_policy_from_string(rs, false, &rp2);
        assert_se(rr == 0);

        assert_se(rs_image_policy_equivalent(rp, rp2) == 1);
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
        _cleanup_(image_policy_freep) ImagePolicy *cp = NULL, *rp = NULL;

        assert_se(image_policy_from_string("root=encrypted:=absent", false, &cp) >= 0);
        assert_se(rs_image_policy_from_string("root=encrypted:=absent", false, &rp) >= 0);

        assert_se(image_policy_equal(cp, rp));
        assert_se(rs_image_policy_equal(cp, rp));
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

/* ── image_policy_intersect / union ────────────────────────────────────── */

TEST(image_policy_intersect_allow_allow) {
        _cleanup_(image_policy_freep) ImagePolicy *a = NULL, *b = NULL;
        _cleanup_(image_policy_freep) ImagePolicy *cp = NULL, *rp = NULL;
        int cr, rr;

        assert_se(image_policy_from_string("*", false, &a) >= 0);
        assert_se(image_policy_from_string("*", false, &b) >= 0);

        cr = image_policy_intersect(a, b, &cp);
        rr = rs_image_policy_intersect(a, b, &rp);
        assert_se(cr == rr);
        assert_se(cr == 0);
        assert_se(image_policy_equal(cp, rp));
}

TEST(image_policy_union_allow_deny) {
        _cleanup_(image_policy_freep) ImagePolicy *a = NULL, *b = NULL;
        _cleanup_(image_policy_freep) ImagePolicy *cp = NULL, *rp = NULL;
        int cr, rr;

        assert_se(image_policy_from_string("*", false, &a) >= 0);
        assert_se(image_policy_from_string("~", false, &b) >= 0);

        cr = image_policy_union(a, b, &cp);
        rr = rs_image_policy_union(a, b, &rp);
        assert_se(cr == rr);
        assert_se(cr == 0);
        assert_se(image_policy_equal(cp, rp));
}

TEST(image_policy_intersect_conflict) {
        _cleanup_(image_policy_freep) ImagePolicy *a = NULL, *b = NULL;
        _cleanup_(image_policy_freep) ImagePolicy *cp = NULL, *rp = NULL;
        int cr, rr;

        assert_se(image_policy_from_string("root=absent", false, &a) >= 0);
        assert_se(image_policy_from_string("root=encrypted", false, &b) >= 0);

        cr = image_policy_intersect(a, b, &cp);
        rr = rs_image_policy_intersect(a, b, &rp);
        assert_se(cr == rr);
        assert_se(cr == -ENAVAIL);
}

/* ── image_policy_free ─────────────────────────────────────────────────── */

TEST(image_policy_free_null) {
        assert_se(image_policy_free(NULL) == NULL);
        assert_se(rs_image_policy_free(NULL) == NULL);
}

/* ── partition_policy_determine_fstype ─────────────────────────────────── */

TEST(determine_fstype_single) {
        _cleanup_(image_policy_freep) ImagePolicy *p = NULL;
        _cleanup_free_ char *cf = NULL, *rf = NULL;
        bool ce = false, re = false;
        int cr, rr;

        assert_se(image_policy_from_string("root=encrypted+ext4", false, &p) >= 0);

        cr = partition_policy_determine_fstype(p, PARTITION_ROOT, &ce, &cf);
        rr = rs_partition_policy_determine_fstype(p, PARTITION_ROOT, &re, &rf);
        assert_se(cr == rr);
        assert_se(cr == 1);
        assert_se(streq(cf, rf));
        assert_se(streq(cf, "ext4"));
        assert_se(ce == re);
}

TEST(determine_fstype_none) {
        _cleanup_(image_policy_freep) ImagePolicy *p = NULL;
        char *cf = NULL, *rf = NULL;
        bool ce = false, re = false;
        int cr, rr;

        assert_se(image_policy_from_string("root=encrypted", false, &p) >= 0);

        cr = partition_policy_determine_fstype(p, PARTITION_ROOT, &ce, &cf);
        rr = rs_partition_policy_determine_fstype(p, PARTITION_ROOT, &re, &rf);
        assert_se(cr == rr);
        assert_se(cr == 0);
        assert_se(cf == NULL);
        assert_se(rf == NULL);
}

/* ── main ──────────────────────────────────────────────────────────────── */

DEFINE_TEST_MAIN(LOG_INFO);
