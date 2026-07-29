/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* RUST-CONTRACT: id128-string-rendering */
/* RUST-CONTRACT: id128-string-parsing */
/* RUST-CONTRACT: id128-nonzero-parsing */
/* RUST-CONTRACT: id128-string-equality */
/* RUST-CONTRACT: id128-v4-uuid */
/* RUST-CONTRACT: id128-comparison-and-predicates */
/* RUST-CONTRACT: id128-digest */
/* Shadow test: C sd-id128 functions vs Rust */

#include "tests.h"
#include "sd-id128.h"
#include "id128-util.h"

/* Rust FFI */
#include "rust/id128_util.h"

/* ── sd_id128_to_string / sd_id128_to_uuid_string ────────────────────────── */

TEST(sd_id128_to_string_basic) {
        sd_id128_t id = SD_ID128_MAKE(f9,7d,15,8c,50,d4,4e,ba,a4,96,7a,35,e1,d4,07,5c);
        char cs[SD_ID128_STRING_MAX];
        char rs[SD_ID128_STRING_MAX];

        assert_se(sd_id128_to_string(id, cs) == cs);
        assert_se(rs_sd_id128_to_string(id, rs) == rs);
        assert_se(streq(cs, "f97d158c50d44ebaa4967a35e1d4075c"));
        assert_se(streq(cs, rs));
}

TEST(sd_id128_to_string_all_zeros) {
        sd_id128_t id = SD_ID128_NULL;
        char cs[SD_ID128_STRING_MAX];
        char rs[SD_ID128_STRING_MAX];

        assert_se(sd_id128_to_string(id, cs) == cs);
        assert_se(rs_sd_id128_to_string(id, rs) == rs);
        assert_se(streq(cs, "00000000000000000000000000000000"));
        assert_se(streq(cs, rs));
}

TEST(sd_id128_to_string_all_ff) {
        sd_id128_t id = SD_ID128_ALLF;
        char cs[SD_ID128_STRING_MAX];
        char rs[SD_ID128_STRING_MAX];

        assert_se(sd_id128_to_string(id, cs) == cs);
        assert_se(rs_sd_id128_to_string(id, rs) == rs);
        assert_se(streq(cs, "ffffffffffffffffffffffffffffffff"));
        assert_se(streq(cs, rs));
}

TEST(sd_id128_to_string_preserves_caller_boundary) {
        sd_id128_t id = SD_ID128_MAKE(f9,7d,15,8c,50,d4,4e,ba,a4,96,7a,35,e1,d4,07,5c);
        char cs[SD_ID128_STRING_MAX + 1] = {};
        char rs[SD_ID128_STRING_MAX + 1] = {};

        cs[SD_ID128_STRING_MAX] = '#';
        rs[SD_ID128_STRING_MAX] = '#';
        assert_se(sd_id128_to_string(id, cs) == cs);
        assert_se(rs_sd_id128_to_string(id, rs) == rs);
        assert_se(streq(cs, rs));
        assert_se(cs[SD_ID128_STRING_MAX] == '#');
        assert_se(rs[SD_ID128_STRING_MAX] == '#');
}

TEST(sd_id128_to_uuid_string_basic) {
        sd_id128_t id = SD_ID128_MAKE(f9,7d,15,8c,50,d4,4e,ba,a4,96,7a,35,e1,d4,07,5c);
        char cs[SD_ID128_UUID_STRING_MAX];
        char rs[SD_ID128_UUID_STRING_MAX];

        assert_se(sd_id128_to_uuid_string(id, cs) == cs);
        assert_se(rs_sd_id128_to_uuid_string(id, rs) == rs);
        assert_se(streq(cs, "f97d158c-50d4-4eba-a496-7a35e1d4075c"));
        assert_se(streq(cs, rs));
}

TEST(sd_id128_to_uuid_string_null) {
        sd_id128_t id = SD_ID128_NULL;
        char cs[SD_ID128_UUID_STRING_MAX];
        char rs[SD_ID128_UUID_STRING_MAX];

        assert_se(sd_id128_to_uuid_string(id, cs) == cs);
        assert_se(rs_sd_id128_to_uuid_string(id, rs) == rs);
        assert_se(streq(cs, "00000000-0000-0000-0000-000000000000"));
        assert_se(streq(cs, rs));
}

/* ── sd_id128_from_string ────────────────────────────────────────────────── */

TEST(sd_id128_from_string_plain) {
        sd_id128_t id = SD_ID128_MAKE(f9,7d,15,8c,50,d4,4e,ba,a4,96,7a,35,e1,d4,07,5c);
        sd_id128_t cr, rr;
        int rc, rr2;

        rc = sd_id128_from_string("f97d158c50d44ebaa4967a35e1d4075c", &cr);
        rr2 = rs_sd_id128_from_string("f97d158c50d44ebaa4967a35e1d4075c", &rr);
        assert_se(rc == 0);
        assert_se(rr2 == 0);
        assert_se(sd_id128_equal(cr, id));
        assert_se(sd_id128_equal(rr, id));
        assert_se(sd_id128_equal(cr, rr));
}

TEST(sd_id128_from_string_uuid) {
        sd_id128_t id = SD_ID128_MAKE(f9,7d,15,8c,50,d4,4e,ba,a4,96,7a,35,e1,d4,07,5c);
        sd_id128_t cr, rr;
        int rc, rr2;

        rc = sd_id128_from_string("f97d158c-50d4-4eba-a496-7a35e1d4075c", &cr);
        rr2 = rs_sd_id128_from_string("f97d158c-50d4-4eba-a496-7a35e1d4075c", &rr);
        assert_se(rc == 0);
        assert_se(rr2 == 0);
        assert_se(sd_id128_equal(cr, id));
        assert_se(sd_id128_equal(rr, id));
        assert_se(sd_id128_equal(cr, rr));
}

TEST(sd_id128_from_string_null_ret) {
        int rc, rr2;

        /* ret=NULL is valid — just validates */
        rc = sd_id128_from_string("f97d158c50d44ebaa4967a35e1d4075c", NULL);
        rr2 = rs_sd_id128_from_string("f97d158c50d44ebaa4967a35e1d4075c", NULL);
        assert_se(rc == 0);
        assert_se(rr2 == 0);
}

TEST(sd_id128_from_string_errors) {
        sd_id128_t dummy;
        int rc, rr2;

        /* Too short */
        rc = sd_id128_from_string("f97d158c", &dummy);
        rr2 = rs_sd_id128_from_string("f97d158c", &dummy);
        assert_se(rc == -EINVAL);
        assert_se(rr2 == rc);

        /* Too long (trailing garbage) */
        rc = sd_id128_from_string("f97d158c50d44ebaa4967a35e1d4075cXX", &dummy);
        rr2 = rs_sd_id128_from_string("f97d158c50d44ebaa4967a35e1d4075cXX", &dummy);
        assert_se(rc == -EINVAL);
        assert_se(rr2 == rc);

        /* Invalid hex char */
        rc = sd_id128_from_string("g97d158c50d44ebaa4967a35e1d4075c", &dummy);
        rr2 = rs_sd_id128_from_string("g97d158c50d44ebaa4967a35e1d4075c", &dummy);
        assert_se(rc == -EINVAL);
        assert_se(rr2 == rc);

        /* Dash in wrong position */
        rc = sd_id128_from_string("f97d15-8c50d44ebaa4967a35e1d4075c", &dummy);
        rr2 = rs_sd_id128_from_string("f97d15-8c50d44ebaa4967a35e1d4075c", &dummy);
        assert_se(rc == -EINVAL);
        assert_se(rr2 == rc);

        /* Dash without GUID context (no dash at position 8 first) */
        rc = sd_id128_from_string("f97d158c50d44eba-a4967a35e1d4075c", &dummy);
        rr2 = rs_sd_id128_from_string("f97d158c50d44eba-a4967a35e1d4075c", &dummy);
        assert_se(rc == -EINVAL);
        assert_se(rr2 == rc);
}

TEST(sd_id128_from_string_preserves_output_on_error) {
        sd_id128_t initial = SD_ID128_MAKE(aa,bb,cc,dd,ee,ff,01,23,45,67,89,ab,cd,ef,10,20);
        sd_id128_t cr = initial, rr = initial;
        int rc, rr2;

        rc = sd_id128_from_string("not-an-id", &cr);
        rr2 = rs_sd_id128_from_string("not-an-id", &rr);
        assert_se(rc == -EINVAL);
        assert_se(rr2 == rc);
        assert_se(sd_id128_equal(cr, initial));
        assert_se(sd_id128_equal(rr, initial));
}

TEST(sd_id128_from_string_is_byte_oriented) {
        char invalid[] = { (char) 0xff, 0 };
        sd_id128_t cr = SD_ID128_ALLF, rr = SD_ID128_ALLF;
        int rc, rr2;

        rc = sd_id128_from_string(invalid, &cr);
        rr2 = rs_sd_id128_from_string(invalid, &rr);
        assert_se(rc == -EINVAL);
        assert_se(rr2 == rc);
        assert_se(sd_id128_equal(cr, SD_ID128_ALLF));
        assert_se(sd_id128_equal(rr, SD_ID128_ALLF));
}

TEST(sd_id128_from_string_uppercase) {
        sd_id128_t id = SD_ID128_MAKE(ab,cd,ef,01,23,45,67,89,fe,dc,ba,98,76,54,32,10);
        sd_id128_t cr, rr;

        assert_se(sd_id128_from_string("ABCDEF0123456789FEDCBA9876543210", &cr) == 0);
        assert_se(rs_sd_id128_from_string("ABCDEF0123456789FEDCBA9876543210", &rr) == 0);
        assert_se(sd_id128_equal(cr, id));
        assert_se(sd_id128_equal(rr, id));
}

/* ── sd_id128_string_equal ───────────────────────────────────────────────── */

TEST(sd_id128_string_equal_matching) {
        sd_id128_t id = SD_ID128_MAKE(f9,7d,15,8c,50,d4,4e,ba,a4,96,7a,35,e1,d4,07,5c);
        int cr, rr;

        cr = sd_id128_string_equal("f97d158c50d44ebaa4967a35e1d4075c", id);
        rr = rs_sd_id128_string_equal("f97d158c50d44ebaa4967a35e1d4075c", id);
        assert_se(cr == 1);
        assert_se(rr == cr);

        /* Also match UUID format */
        cr = sd_id128_string_equal("f97d158c-50d4-4eba-a496-7a35e1d4075c", id);
        rr = rs_sd_id128_string_equal("f97d158c-50d4-4eba-a496-7a35e1d4075c", id);
        assert_se(cr == 1);
        assert_se(rr == cr);
}

TEST(sd_id128_string_equal_not_matching) {
        sd_id128_t id = SD_ID128_MAKE(f9,7d,15,8c,50,d4,4e,ba,a4,96,7a,35,e1,d4,07,5c);
        int cr, rr;

        cr = sd_id128_string_equal("aabbccdd50d44ebaa4967a35e1d4075c", id);
        rr = rs_sd_id128_string_equal("aabbccdd50d44ebaa4967a35e1d4075c", id);
        assert_se(cr == 0);
        assert_se(rr == cr);
}

TEST(sd_id128_string_equal_null) {
        sd_id128_t id = SD_ID128_MAKE(f9,7d,15,8c,50,d4,4e,ba,a4,96,7a,35,e1,d4,07,5c);
        int cr, rr;

        cr = sd_id128_string_equal(NULL, id);
        rr = rs_sd_id128_string_equal(NULL, id);
        assert_se(cr == 0);
        assert_se(rr == cr);
}

TEST(sd_id128_string_equal_invalid) {
        sd_id128_t id = SD_ID128_MAKE(f9,7d,15,8c,50,d4,4e,ba,a4,96,7a,35,e1,d4,07,5c);
        int cr, rr;

        cr = sd_id128_string_equal("invalid", id);
        rr = rs_sd_id128_string_equal("invalid", id);
        assert_se(cr < 0);
        assert_se(rr == cr);
}

/* ── id128_from_string_nonzero ───────────────────────────────────────────── */

TEST(id128_from_string_nonzero_valid) {
        sd_id128_t id = SD_ID128_MAKE(f9,7d,15,8c,50,d4,4e,ba,a4,96,7a,35,e1,d4,07,5c);
        sd_id128_t cr, rr;
        int rc, rr2;

        rc = id128_from_string_nonzero("f97d158c50d44ebaa4967a35e1d4075c", &cr);
        rr2 = rs_id128_from_string_nonzero("f97d158c50d44ebaa4967a35e1d4075c", &rr);
        assert_se(rc == 0);
        assert_se(rr2 == 0);
        assert_se(sd_id128_equal(cr, id));
        assert_se(sd_id128_equal(rr, id));
}

TEST(id128_from_string_nonzero_null_id) {
        sd_id128_t cr, rr;
        int rc, rr2;

        rc = id128_from_string_nonzero("00000000000000000000000000000000", &cr);
        rr2 = rs_id128_from_string_nonzero("00000000000000000000000000000000", &rr);
        assert_se(rc == -ENXIO);
        assert_se(rr2 == rc);
}

TEST(id128_from_string_nonzero_preserves_output_on_error) {
        sd_id128_t initial = SD_ID128_MAKE(aa,bb,cc,dd,ee,ff,01,23,45,67,89,ab,cd,ef,10,20);
        sd_id128_t cr = initial, rr = initial;
        int rc, rr2;

        rc = id128_from_string_nonzero("00000000000000000000000000000000", &cr);
        rr2 = rs_id128_from_string_nonzero("00000000000000000000000000000000", &rr);
        assert_se(rc == -ENXIO);
        assert_se(rr2 == rc);
        assert_se(sd_id128_equal(cr, initial));
        assert_se(sd_id128_equal(rr, initial));
}

TEST(id128_from_string_nonzero_null_args) {
        int rr2;

        /* NULL ret (C version uses ASSERT_PTR which aborts, so only test Rust) */
        rr2 = rs_id128_from_string_nonzero("f97d158c50d44ebaa4967a35e1d4075c", NULL);
        assert_se(rr2 < 0);
}

/* ── id128_make_v4_uuid ──────────────────────────────────────────────────── */

TEST(id128_make_v4_uuid) {
        /* Start with all zeros */
        sd_id128_t zero = SD_ID128_NULL;
        sd_id128_t cr, rr;

        cr = id128_make_v4_uuid(zero);
        rr = rs_id128_make_v4_uuid(zero);
        assert_se(sd_id128_equal(cr, rr));

        /* Check version 4 bits: byte[6] should be 0x40 */
        assert_se(cr.bytes[6] == 0x40);
        assert_se(rr.bytes[6] == 0x40);

        /* Check DCE variant bits: byte[8] should have 0x80 set */
        assert_se((cr.bytes[8] & 0xC0) == 0x80);
        assert_se((rr.bytes[8] & 0xC0) == 0x80);

        /* Lower 6 bits of byte[6] preserved */
        assert_se((cr.bytes[6] & 0x0F) == 0x00);

        /* Lower 6 bits of byte[8] preserved */
        assert_se((cr.bytes[8] & 0x3F) == 0x00);
}

TEST(id128_make_v4_uuid_preserves_bits) {
        sd_id128_t id = SD_ID128_MAKE(ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff);
        sd_id128_t cr, rr;

        cr = id128_make_v4_uuid(id);
        rr = rs_id128_make_v4_uuid(id);
        assert_se(sd_id128_equal(cr, rr));

        /* byte[6]: upper nibble forced to 4, lower nibble preserved (0xF) */
        assert_se(cr.bytes[6] == 0x4F);

        /* byte[8]: upper two bits forced to 10, lower 6 bits preserved (0x3F) */
        assert_se(cr.bytes[8] == 0xBF);

        /* All other bytes unchanged */
        for (int i = 0; i < 16; i++) {
                if (i != 6 && i != 8) {
                        assert_se(cr.bytes[i] == 0xFF);
                        assert_se(rr.bytes[i] == 0xFF);
                }
        }
}

TEST(id128_make_v4_uuid_specific) {
        sd_id128_t id = SD_ID128_MAKE(01,23,45,67,89,ab,cd,ef,fe,dc,ba,98,76,54,32,10);
        sd_id128_t cr, rr;

        cr = id128_make_v4_uuid(id);
        rr = rs_id128_make_v4_uuid(id);
        assert_se(sd_id128_equal(cr, rr));

        /* byte[6] = (0xCD & 0x0F) | 0x40 = 0x0D | 0x40 = 0x4D */
        assert_se(cr.bytes[6] == 0x4D);
        /* byte[8] = (0xFE & 0x3F) | 0x80 = 0x3E | 0x80 = 0xBE */
        assert_se(cr.bytes[8] == 0xBE);
}

/* ── id128_compare_func ──────────────────────────────────────────────────── */

TEST(id128_compare_func_equal) {
        sd_id128_t a = SD_ID128_MAKE(f9,7d,15,8c,50,d4,4e,ba,a4,96,7a,35,e1,d4,07,5c);
        sd_id128_t b = SD_ID128_MAKE(f9,7d,15,8c,50,d4,4e,ba,a4,96,7a,35,e1,d4,07,5c);

        assert_se(id128_compare_func(&a, &b) == rs_id128_compare_func(&a, &b));
        assert_se(id128_compare_func(&a, &b) == 0);
}

TEST(id128_compare_func_less) {
        sd_id128_t a = SD_ID128_MAKE(00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,01);
        sd_id128_t b = SD_ID128_MAKE(00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,02);

        assert_se(id128_compare_func(&a, &b) == rs_id128_compare_func(&a, &b));
        assert_se(id128_compare_func(&a, &b) < 0);
}

TEST(id128_compare_func_greater) {
        sd_id128_t a = SD_ID128_MAKE(00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,02);
        sd_id128_t b = SD_ID128_MAKE(00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,01);

        assert_se(id128_compare_func(&a, &b) == rs_id128_compare_func(&a, &b));
        assert_se(id128_compare_func(&a, &b) > 0);
}

TEST(id128_compare_func_null_vs_nonnull) {
        sd_id128_t a = SD_ID128_NULL;
        sd_id128_t b = SD_ID128_MAKE(00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,01);

        assert_se(id128_compare_func(&a, &b) == rs_id128_compare_func(&a, &b));
        assert_se(id128_compare_func(&a, &b) < 0);
}

TEST(id128_compare_func_preserves_memcmp_result) {
        sd_id128_t a = SD_ID128_MAKE(00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,ff);
        sd_id128_t b = SD_ID128_MAKE(00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,01);

        assert_se(id128_compare_func(&a, &b) == rs_id128_compare_func(&a, &b));
}

/* ── sd_id128_equal / sd_id128_is_null ───────────────────────────────────── */

TEST(sd_id128_equal_matching) {
        sd_id128_t a = SD_ID128_MAKE(f9,7d,15,8c,50,d4,4e,ba,a4,96,7a,35,e1,d4,07,5c);
        sd_id128_t b = SD_ID128_MAKE(f9,7d,15,8c,50,d4,4e,ba,a4,96,7a,35,e1,d4,07,5c);

        assert_se(sd_id128_equal(a, b) == rs_sd_id128_equal(a, b));
        assert_se(sd_id128_equal(a, b) == 1);
}

TEST(sd_id128_equal_not_matching) {
        sd_id128_t a = SD_ID128_MAKE(f9,7d,15,8c,50,d4,4e,ba,a4,96,7a,35,e1,d4,07,5c);
        sd_id128_t b = SD_ID128_MAKE(00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00);

        assert_se(sd_id128_equal(a, b) == rs_sd_id128_equal(a, b));
        assert_se(sd_id128_equal(a, b) == 0);
}

TEST(sd_id128_equal_nulls) {
        sd_id128_t a = SD_ID128_NULL;
        sd_id128_t b = SD_ID128_NULL;

        assert_se(sd_id128_equal(a, b) == rs_sd_id128_equal(a, b));
        assert_se(sd_id128_equal(a, b) == 1);
}

TEST(sd_id128_is_null_true) {
        sd_id128_t a = SD_ID128_NULL;
        assert_se(sd_id128_is_null(a) == rs_sd_id128_is_null(a));
        assert_se(sd_id128_is_null(a) == 1);
}

TEST(sd_id128_is_null_false) {
        sd_id128_t a = SD_ID128_MAKE(00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,01);
        assert_se(sd_id128_is_null(a) == rs_sd_id128_is_null(a));
        assert_se(sd_id128_is_null(a) == 0);
}

TEST(sd_id128_is_null_allf) {
        sd_id128_t a = SD_ID128_ALLF;
        assert_se(sd_id128_is_null(a) == rs_sd_id128_is_null(a));
        assert_se(sd_id128_is_null(a) == 0);
}

/* ── roundtrip: to_string → from_string ──────────────────────────────────── */

TEST(sd_id128_roundtrip_plain) {
        sd_id128_t id = SD_ID128_MAKE(f9,7d,15,8c,50,d4,4e,ba,a4,96,7a,35,e1,d4,07,5c);
        char cs[SD_ID128_STRING_MAX];
        sd_id128_t parsed;

        sd_id128_to_string(id, cs);
        assert_se(sd_id128_from_string(cs, &parsed) == 0);
        assert_se(sd_id128_equal(id, parsed));

        /* Same with Rust */
        char rs[SD_ID128_STRING_MAX];
        sd_id128_t r_parsed;
        rs_sd_id128_to_string(id, rs);
        assert_se(rs_sd_id128_from_string(rs, &r_parsed) == 0);
        assert_se(sd_id128_equal(id, r_parsed));
        assert_se(streq(cs, rs));
}

TEST(sd_id128_roundtrip_uuid) {
        sd_id128_t id = SD_ID128_MAKE(f9,7d,15,8c,50,d4,4e,ba,a4,96,7a,35,e1,d4,07,5c);
        char cs[SD_ID128_UUID_STRING_MAX];
        sd_id128_t parsed;

        sd_id128_to_uuid_string(id, cs);
        assert_se(sd_id128_from_string(cs, &parsed) == 0);
        assert_se(sd_id128_equal(id, parsed));

        /* Same with Rust */
        char rs[SD_ID128_UUID_STRING_MAX];
        sd_id128_t r_parsed;
        rs_sd_id128_to_uuid_string(id, rs);
        assert_se(rs_sd_id128_from_string(rs, &r_parsed) == 0);
        assert_se(sd_id128_equal(id, r_parsed));
        assert_se(streq(cs, rs));
}

/* ── id128_digest ─────────────────────────────────────────────────────────── */

TEST(id128_digest_deterministic) {
        const char *data = "hello world";
        sd_id128_t cr, rr;

        cr = id128_digest(data, strlen(data));
        rr = rs_id128_digest(data, strlen(data));
        assert_se(sd_id128_equal(cr, rr));

        /* Same input must produce same output */
        rr = rs_id128_digest(data, strlen(data));
        assert_se(sd_id128_equal(cr, rr));
}

TEST(id128_digest_different_inputs) {
        const char *data1 = "hello world";
        const char *data2 = "hello earth";
        sd_id128_t r1, r2;

        r1 = rs_id128_digest(data1, strlen(data1));
        r2 = rs_id128_digest(data2, strlen(data2));
        assert_se(!sd_id128_equal(r1, r2));
}

TEST(id128_digest_is_v4_uuid) {
        const char *data = "test data for digest";
        sd_id128_t result = rs_id128_digest(data, strlen(data));

        /* byte[6] should have version 4 bits: (byte & 0xF0) == 0x40 */
        assert_se((result.bytes[6] & 0xF0) == 0x40);
        /* byte[8] should have DCE variant bits: (byte & 0xC0) == 0x80 */
        assert_se((result.bytes[8] & 0xC0) == 0x80);
}

TEST(id128_digest_empty) {
        sd_id128_t cr, rr;

        /* Empty input (size=0, data can be anything) */
        cr = id128_digest("", 0);
        rr = rs_id128_digest("", 0);
        assert_se(sd_id128_equal(cr, rr));
}

TEST(id128_digest_binary_input) {
        const uint8_t data[] = { 0, 0xff, 0, 0x80, 0x7f };
        sd_id128_t cr, rr;

        cr = id128_digest(data, sizeof(data));
        rr = rs_id128_digest(data, sizeof(data));
        assert_se(sd_id128_equal(cr, rr));
}

TEST(id128_digest_size_max_uses_c_string_length) {
        const char *data = "digest text";
        sd_id128_t cr, rr;

        cr = id128_digest(data, SIZE_MAX);
        rr = rs_id128_digest(data, SIZE_MAX);
        assert_se(sd_id128_equal(cr, rr));
}

DEFINE_TEST_MAIN(LOG_INFO);
