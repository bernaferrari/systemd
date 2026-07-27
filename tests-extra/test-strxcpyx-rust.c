/* SPDX-License-Identifier: LGPL-2.1-or-later */

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
        char cb[32], rb[32];
        char *cp = cb, *rp = rb;
        bool ct = false, rt = false;

        size_t cr = strnpcpy_full(&cp, 0, "hello", 5, &ct);
        size_t rr = rs_strnpcpy_full(&rp, 0, "hello", 5, &rt);
        assert_se(cr == rr);
        assert_se(cr == 0);
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
