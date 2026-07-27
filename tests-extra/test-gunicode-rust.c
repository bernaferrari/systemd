/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Shadow test: C gunicode vs Rust rs_gunicode */

#include <string.h>

#include "gunicode.h"
#include "rust/gunicode.h"

/* ── utf8_skip_data ────────────────────────────────────────────────────── */

static void test_utf8_skip_data(void) {
        /* ASCII bytes (0x00-0x7F) → skip 1 */
        for (int i = 0; i < 0x80; i++)
                assert_se(utf8_skip_data[i] == rs_utf8_skip_data[i]);

        /* 2-byte lead (0xC0-0xDF) → skip 2 */
        for (int i = 0xC0; i <= 0xDF; i++)
                assert_se(utf8_skip_data[i] == 2 && rs_utf8_skip_data[i] == 2);

        /* 3-byte lead (0xE0-0xEF) → skip 3 */
        for (int i = 0xE0; i <= 0xEF; i++)
                assert_se(utf8_skip_data[i] == 3 && rs_utf8_skip_data[i] == 3);

        /* 4-byte lead (0xF0-0xF7) → skip 4 */
        for (int i = 0xF0; i <= 0xF7; i++)
                assert_se(utf8_skip_data[i] == 4 && rs_utf8_skip_data[i] == 4);

        /* 5-byte lead (0xF8-0xFB) → skip 5 */
        for (int i = 0xF8; i <= 0xFB; i++)
                assert_se(utf8_skip_data[i] == 5 && rs_utf8_skip_data[i] == 5);

        /* 6-byte lead (0xFC-0xFD) → skip 6 */
        for (int i = 0xFC; i <= 0xFD; i++)
                assert_se(utf8_skip_data[i] == 6 && rs_utf8_skip_data[i] == 6);

        /* Continuation bytes (0x80-0xBF) → skip 1 */
        for (int i = 0x80; i <= 0xBF; i++)
                assert_se(utf8_skip_data[i] == 1 && rs_utf8_skip_data[i] == 1);
}

/* ── utf8_prev_char ──────────────────────────────────────────────────────── */

static void test_utf8_prev_char(void) {
        /* "abc" — prev from 'c' should point to 'b' */
        const char *s = "abc";
        const char *p = s + 2; /* points to 'c' */
        char *c_ret = utf8_prev_char(p);
        char *r_ret = rs_utf8_prev_char(p);
        assert_se(c_ret == s + 1);
        assert_se(r_ret == s + 1);
        assert_se(c_ret == r_ret);
        assert_se(*c_ret == 'b');

        /* 2-byte UTF-8: é = 0xC3 0xA9 — prev from after should point to 0xC3 */
        char two[] = { 0xC3, 0xA9, 'x', 0 };
        p = two + 2; /* points to 'x' */
        c_ret = utf8_prev_char(p);
        r_ret = rs_utf8_prev_char(p);
        assert_se(c_ret == two);
        assert_se(r_ret == two);
        assert_se((unsigned char)*c_ret == 0xC3); /* lead byte of the é character */

        /* Actually prev_char returns the start of the char, which is the
         * continuation byte first, then the lead byte. Let me verify:
         * p points to 'x' (index 2). p-- → 0xA9 (continuation, skip). p-- → 0xC3 (lead).
         * So prev_char returns pointer to 0xC3 which is two[0]. Correct. */

        /* 3-byte UTF-8: 中 = 0xE4 0xB8 0xAD */
        char three[] = { 0xE4, 0xB8, 0xAD, 'y', 0 };
        p = three + 3; /* points to 'y' */
        c_ret = utf8_prev_char(p);
        r_ret = rs_utf8_prev_char(p);
        assert_se(c_ret == three);
        assert_se(r_ret == three);
}

/* ── unichar_iswide ─────────────────────────────────────────────────────── */

static void test_unichar_iswide_ascii(void) {
        /* ASCII should never be wide */
        for (uint32_t c = 0; c < 0x80; c++) {
                assert_se(unichar_iswide(c) == rs_unichar_iswide(c));
                assert_se(!unichar_iswide(c));
        }
}

static void test_unichar_iswide_hangul(void) {
        /* Hangul syllables (AC00-D7A3) are wide */
        assert_se(unichar_iswide(0xAC00) == rs_unichar_iswide(0xAC00));
        assert_se(unichar_iswide(0xAC00));
        assert_se(unichar_iswide(0xD7A3) == rs_unichar_iswide(0xD7A3));
        assert_se(unichar_iswide(0xD7A3));
        assert_se(!unichar_iswide(0xD7A4)); /* just past */
        assert_se(unichar_iswide(0xD7A4) == rs_unichar_iswide(0xD7A4));
}

static void test_unichar_iswide_cjk(void) {
        /* CJK Unified Ideographs (4E00-A48C) are wide */
        assert_se(unichar_iswide(0x4E00) == rs_unichar_iswide(0x4E00));
        assert_se(unichar_iswide(0x4E00));
        assert_se(unichar_iswide(0xA48C) == rs_unichar_iswide(0xA48C));
        assert_se(unichar_iswide(0xA48C));
        assert_se(!unichar_iswide(0xA48D));
        assert_se(unichar_iswide(0xA48D) == rs_unichar_iswide(0xA48D));
}

static void test_unichar_iswide_katakana(void) {
        /* Katakana (30A1-30FF) are wide */
        assert_se(unichar_iswide(0x30A1) == rs_unichar_iswide(0x30A1));
        assert_se(unichar_iswide(0x30A1));
        assert_se(unichar_iswide(0x30FF) == rs_unichar_iswide(0x30FF));
}

static void test_unichar_iswide_fullwidth(void) {
        /* Fullwidth forms (FF01-FF60) are wide */
        assert_se(unichar_iswide(0xFF01) == rs_unichar_iswide(0xFF01));
        assert_se(unichar_iswide(0xFF01));
        assert_se(unichar_iswide(0xFF60) == rs_unichar_iswide(0xFF60));
}

static void test_unichar_iswide_not_wide(void) {
        /* Some code points that should NOT be wide */
        assert_se(!unichar_iswide(0x0041)); /* 'A' */
        assert_se(!unichar_iswide(0x007E)); /* '~' */
        assert_se(!unichar_iswide(0x00A0)); /* NBSP */
        assert_se(!unichar_iswide(0x2000)); /* EN QUAD */
        assert_se(!unichar_iswide(0x20AC)); /* Euro sign */
        assert_se(!unichar_iswide(0x0000));
        assert_se(!unichar_iswide(0xFFFF));
        assert_se(!unichar_iswide(0x10FFFF));

        /* Verify C and Rust agree on non-wide chars too */
        uint32_t non_wide[] = { 0x0041, 0x007E, 0x00A0, 0x2000, 0x20AC, 0x0000, 0xFFFF };
        for (int i = 0; i < (int)(sizeof(non_wide)/sizeof(non_wide[0])); i++) {
                assert_se(unichar_iswide(non_wide[i]) == rs_unichar_iswide(non_wide[i]));
                assert_se(!unichar_iswide(non_wide[i]));
        }
}

static void test_unichar_iswide_supplementary(void) {
        /* Supplementary planes (20000-2FFFD) are wide */
        assert_se(unichar_iswide(0x20000) == rs_unichar_iswide(0x20000));
        assert_se(unichar_iswide(0x20000));
        assert_se(unichar_iswide(0x2FFFD) == rs_unichar_iswide(0x2FFFD));
}

/* ── Main ───────────────────────────────────────────────────────────────── */

int main(int argc, char **argv) {
        test_utf8_skip_data();
        test_utf8_prev_char();
        test_unichar_iswide_ascii();
        test_unichar_iswide_hangul();
        test_unichar_iswide_cjk();
        test_unichar_iswide_katakana();
        test_unichar_iswide_fullwidth();
        test_unichar_iswide_not_wide();
        test_unichar_iswide_supplementary();

        return 0;
}
