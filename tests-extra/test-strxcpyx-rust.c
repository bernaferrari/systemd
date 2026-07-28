/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* RUST-CONTRACT: strxcpyx-n-pointer */
/* RUST-CONTRACT: strxcpyx-c-string-pointer */
/* RUST-CONTRACT: strxcpyx-n-static */
/* RUST-CONTRACT: strxcpyx-c-string-static */

#include <string.h>

#include "strxcpyx.h"
#include "tests.h"

/* Rust FFI */
#include "rust/strxcpyx.h"

/* ── strnpcpy_full ──────────────────────────────────────────────────────── */

TEST(strnpcpy_full_basic) {
        char cb[32], rb[32];
        char *cp = cb, *rp = rb;
        bool ct = false, rt = false;

        size_t cr = strnpcpy_full(&cp, sizeof(cb), "hello", 5, &ct);
        size_t rr = rs_strnpcpy_full(&rp, sizeof(rb), "hello", 5, &rt);
        assert_se(cr == rr);
        assert_se(ct == rt);
        assert_se(streq(cb, rb));
}

TEST(strnpcpy_full_truncated) {
        char cb[4], rb[4];
        char *cp = cb, *rp = rb;
        bool ct = false, rt = false;

        size_t cr = strnpcpy_full(&cp, sizeof(cb), "hello", 5, &ct);
        size_t rr = rs_strnpcpy_full(&rp, sizeof(rb), "hello", 5, &rt);
        assert_se(cr == rr);
        assert_se(ct == rt);
        assert_se(ct == true);
        assert_se(streq(cb, rb));
}

TEST(strnpcpy_full_empty) {
        char cb[32], rb[32];
        char *cp = cb, *rp = rb;
        bool ct = false, rt = false;

        size_t cr = strnpcpy_full(&cp, sizeof(cb), "hello", 0, &ct);
        size_t rr = rs_strnpcpy_full(&rp, sizeof(rb), "hello", 0, &rt);
        assert_se(cr == rr);
        assert_se(ct == rt);
        assert_se(streq(cb, rb));
}

TEST(strnpcpy_full_zero_size) {
        char cb[32] = "C sentinel", rb[32] = "Rust sentinel";
        char *cp = cb, *rp = rb;
        bool ct = false, rt = false;

        size_t cr = strnpcpy_full(&cp, 0, "hello", 5, &ct);
        size_t rr = rs_strnpcpy_full(&rp, 0, "hello", 5, &rt);
        assert_se(cr == rr);
        assert_se(cr == 0);
        assert_se(ct == rt);
        assert_se(ct);
        assert_se(cp == cb);
        assert_se(rp == rb);
        assert_se(streq(cb, "C sentinel"));
        assert_se(streq(rb, "Rust sentinel"));
}

TEST(strnpcpy_full_raw_bytes_and_pointer_advance) {
        static const char source[] = { 'a', '\0', 'b' };
        char cb[8] = { 0 }, rb[8] = { 0 };
        char *cp = cb + 1, *rp = rb + 1;
        bool ct = false, rt = false;

        size_t cr = strnpcpy_full(&cp, 6, source, sizeof(source), &ct);
        size_t rr = rs_strnpcpy_full(&rp, 6, source, sizeof(source), &rt);

        assert_se(cr == rr);
        assert_se(cr == 3);
        assert_se(ct == rt);
        assert_se(!ct);
        assert_se(cp - cb == rp - rb);
        assert_se(cp == cb + 4);
        assert_se(rp == rb + 4);
        assert_se(memcmp(cb, rb, sizeof(cb)) == 0);
        assert_se(memcmp(cb + 1, source, sizeof(source)) == 0);
        assert_se(cb[4] == '\0');
}

TEST(strnpcpy_full_null_truncation_output) {
        char cb[4] = { 0 }, rb[4] = { 0 };
        char *cp = cb, *rp = rb;

        size_t cr = strnpcpy_full(&cp, sizeof(cb), "hello", 5, NULL);
        size_t rr = rs_strnpcpy_full(&rp, sizeof(rb), "hello", 5, NULL);

        assert_se(cr == rr);
        assert_se(cr == 0);
        assert_se(cp - cb == rp - rb);
        assert_se(cp == cb + 3);
        assert_se(rp == rb + 3);
        assert_se(memcmp(cb, rb, sizeof(cb)) == 0);
}

/* ── strpcpy_full ───────────────────────────────────────────────────────── */

TEST(strpcpy_full_basic) {
        char cb[32], rb[32];
        char *cp = cb, *rp = rb;
        bool ct = false, rt = false;

        size_t cr = strpcpy_full(&cp, sizeof(cb), "world", &ct);
        size_t rr = rs_strpcpy_full(&rp, sizeof(rb), "world", &rt);
        assert_se(cr == rr);
        assert_se(ct == rt);
        assert_se(streq(cb, rb));
}

TEST(strpcpy_full_truncated) {
        char cb[4], rb[4];
        char *cp = cb, *rp = rb;
        bool ct = false, rt = false;

        size_t cr = strpcpy_full(&cp, sizeof(cb), "world", &ct);
        size_t rr = rs_strpcpy_full(&rp, sizeof(rb), "world", &rt);
        assert_se(cr == rr);
        assert_se(ct == true);
        assert_se(streq(cb, rb));
}

TEST(strpcpy_full_stops_at_first_nul) {
        static const char source[] = { 'a', '\0', 'b', '\0' };
        char cb[8] = { 0 }, rb[8] = { 0 };
        char *cp = cb, *rp = rb;
        bool ct = true, rt = true;

        size_t cr = strpcpy_full(&cp, sizeof(cb), source, &ct);
        size_t rr = rs_strpcpy_full(&rp, sizeof(rb), source, &rt);

        assert_se(cr == rr);
        assert_se(cr == 7);
        assert_se(ct == rt);
        assert_se(!ct);
        assert_se(cp - cb == rp - rb);
        assert_se(cp == cb + 1);
        assert_se(rp == rb + 1);
        assert_se(memcmp(cb, rb, sizeof(cb)) == 0);
        assert_se(cb[0] == 'a');
        assert_se(cb[1] == '\0');
}

/* ── strnscpy_full ──────────────────────────────────────────────────────── */

TEST(strnscpy_full_basic) {
        char cb[32], rb[32];
        bool ct = false, rt = false;

        size_t cr = strnscpy_full(cb, sizeof(cb), "hello", 5, &ct);
        size_t rr = rs_strnscpy_full(rb, sizeof(rb), "hello", 5, &rt);
        assert_se(cr == rr);
        assert_se(ct == rt);
        assert_se(streq(cb, rb));
}

TEST(strnscpy_full_truncated) {
        char cb[4], rb[4];
        bool ct = false, rt = false;

        size_t cr = strnscpy_full(cb, sizeof(cb), "hello", 5, &ct);
        size_t rr = rs_strnscpy_full(rb, sizeof(rb), "hello", 5, &rt);
        assert_se(cr == rr);
        assert_se(ct == true);
        assert_se(streq(cb, rb));
}

TEST(strnscpy_full_zero_size_preserves_destination) {
        char cb[] = { 'C', '!', '\0' }, rb[] = { 'R', '!', '\0' };
        bool ct = false, rt = false;

        size_t cr = strnscpy_full(cb, 0, "hello", 5, &ct);
        size_t rr = rs_strnscpy_full(rb, 0, "hello", 5, &rt);

        assert_se(cr == rr);
        assert_se(cr == 0);
        assert_se(ct == rt);
        assert_se(ct);
        assert_se(memcmp(cb, "C!", sizeof(cb)) == 0);
        assert_se(memcmp(rb, "R!", sizeof(rb)) == 0);
}

/* ── strscpy_full ───────────────────────────────────────────────────────── */

TEST(strscpy_full_basic) {
        char cb[32], rb[32];
        bool ct = false, rt = false;

        size_t cr = strscpy_full(cb, sizeof(cb), "test", &ct);
        size_t rr = rs_strscpy_full(rb, sizeof(rb), "test", &rt);
        assert_se(cr == rr);
        assert_se(ct == rt);
        assert_se(streq(cb, rb));
}

TEST(strscpy_full_truncated) {
        char cb[4], rb[4];
        bool ct = false, rt = false;

        size_t cr = strscpy_full(cb, sizeof(cb), "testing", &ct);
        size_t rr = rs_strscpy_full(rb, sizeof(rb), "testing", &rt);
        assert_se(cr == rr);
        assert_se(ct == true);
        assert_se(streq(cb, rb));
}

TEST(strscpy_full_empty_string) {
        char cb[32], rb[32];
        bool ct = false, rt = false;

        size_t cr = strscpy_full(cb, sizeof(cb), "", &ct);
        size_t rr = rs_strscpy_full(rb, sizeof(rb), "", &rt);
        assert_se(cr == rr);
        assert_se(streq(cb, rb));
}

TEST(strpcpy_full_sequential) {
        /* Copy two strings sequentially into the same buffer */
        char cb[32], rb[32];
        char *cp = cb, *rp = rb;

        size_t cr = strpcpy(&cp, sizeof(cb), "hello ");
        size_t rr = rs_strpcpy_full(&rp, sizeof(rb), "hello ", NULL);
        assert_se(cr == rr);

        cr = strpcpy(&cp, cr, "world");
        rr = rs_strpcpy_full(&rp, rr, "world", NULL);
        assert_se(cr == rr);
        assert_se(streq(cb, "hello world"));
        assert_se(streq(rb, "hello world"));
}

/* ── main ────────────────────────────────────────────────────────────────── */

DEFINE_TEST_MAIN(LOG_INFO);
