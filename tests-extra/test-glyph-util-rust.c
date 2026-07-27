/* SPDX-License-Identifier: LGPL-2.1-or-later */

/*
 * Shadow test: verify Rust glyph-util port matches C behavior exactly.
 * This test links against both the C (via libshared) and Rust (via
 * libsystemd_basic_rs.a) implementations and compares outputs for
 * every ported function.
 */

#include "glyph-util.h"
#include "rust/glyph_util.h"
#include "tests.h"

/* ── glyph_full with force_utf=false ──────────────────────────────────── */

TEST(glyph_full_ascii_c_vs_rs) {
        /* Test every non-emoji glyph with force_utf=false (ASCII mode) */
        for (int i = 0; i < _GLYPH_FIRST_EMOJI; i++) {
                const char *c_str = glyph_full(i, false);
                const char *rs_str = rs_glyph_full(i, false);

                if (c_str)
                        ASSERT_NOT_NULL(rs_str);
                else
                        ASSERT_NULL(rs_str);

                if (c_str && rs_str)
                        ASSERT_STREQ(c_str, rs_str);
        }
}

/* ── glyph_full with force_utf=true ───────────────────────────────────── */

TEST(glyph_full_utf8_c_vs_rs) {
        /* Test every glyph with force_utf=true (forced UTF-8 mode) */
        for (int i = 0; i < _GLYPH_MAX; i++) {
                const char *c_str = glyph_full(i, true);
                const char *rs_str = rs_glyph_full(i, true);

                if (c_str)
                        ASSERT_NOT_NULL(rs_str);
                else
                        ASSERT_NULL(rs_str);

                if (c_str && rs_str)
                        ASSERT_STREQ(c_str, rs_str);
        }
}

/* ── Specific glyph spot checks ───────────────────────────────────────── */

TEST(glyph_full_specific_ascii_c_vs_rs) {
        /* Tree drawing */
        ASSERT_STREQ(glyph_full(GLYPH_TREE_VERTICAL, false),
                     rs_glyph_full(GLYPH_TREE_VERTICAL, false));
        ASSERT_STREQ(glyph_full(GLYPH_TREE_BRANCH, false),
                     rs_glyph_full(GLYPH_TREE_BRANCH, false));
        ASSERT_STREQ(glyph_full(GLYPH_TREE_RIGHT, false),
                     rs_glyph_full(GLYPH_TREE_RIGHT, false));

        /* Arrows */
        ASSERT_STREQ(glyph_full(GLYPH_ARROW_UP, false),
                     rs_glyph_full(GLYPH_ARROW_UP, false));
        ASSERT_STREQ(glyph_full(GLYPH_ARROW_DOWN, false),
                     rs_glyph_full(GLYPH_ARROW_DOWN, false));
        ASSERT_STREQ(glyph_full(GLYPH_ARROW_LEFT, false),
                     rs_glyph_full(GLYPH_ARROW_LEFT, false));
        ASSERT_STREQ(glyph_full(GLYPH_ARROW_RIGHT, false),
                     rs_glyph_full(GLYPH_ARROW_RIGHT, false));

        /* Check/cross marks */
        ASSERT_STREQ(glyph_full(GLYPH_CHECK_MARK, false),
                     rs_glyph_full(GLYPH_CHECK_MARK, false));
        ASSERT_STREQ(glyph_full(GLYPH_CROSS_MARK, false),
                     rs_glyph_full(GLYPH_CROSS_MARK, false));

        /* Shades */
        ASSERT_STREQ(glyph_full(GLYPH_LIGHT_SHADE, false),
                     rs_glyph_full(GLYPH_LIGHT_SHADE, false));
        ASSERT_STREQ(glyph_full(GLYPH_DARK_SHADE, false),
                     rs_glyph_full(GLYPH_DARK_SHADE, false));
        ASSERT_STREQ(glyph_full(GLYPH_FULL_BLOCK, false),
                     rs_glyph_full(GLYPH_FULL_BLOCK, false));
}

TEST(glyph_full_specific_utf8_c_vs_rs) {
        /* Tree drawing */
        ASSERT_STREQ(glyph_full(GLYPH_TREE_VERTICAL, true),
                     rs_glyph_full(GLYPH_TREE_VERTICAL, true));
        ASSERT_STREQ(glyph_full(GLYPH_TREE_BRANCH, true),
                     rs_glyph_full(GLYPH_TREE_BRANCH, true));
        ASSERT_STREQ(glyph_full(GLYPH_TREE_RIGHT, true),
                     rs_glyph_full(GLYPH_TREE_RIGHT, true));

        /* Check marks */
        ASSERT_STREQ(glyph_full(GLYPH_CHECK_MARK, true),
                     rs_glyph_full(GLYPH_CHECK_MARK, true));
        ASSERT_STREQ(glyph_full(GLYPH_CROSS_MARK, true),
                     rs_glyph_full(GLYPH_CROSS_MARK, true));
}

/* ── Invalid code ─────────────────────────────────────────────────────── */

TEST(glyph_full_invalid_c_vs_rs) {
        /* _GLYPH_INVALID = -EINVAL, both should return NULL */
        ASSERT_NULL(glyph_full(-EINVAL, false));
        ASSERT_NULL(rs_glyph_full(-EINVAL, false));
        ASSERT_NULL(glyph_full(-1, false));
        ASSERT_NULL(rs_glyph_full(-1, false));
}

DEFINE_TEST_MAIN(LOG_INFO);
