/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdlib.h>

#include "glyph-util.h"
#include "tests.h"

TEST(glyph_full_non_null) {
        /* All valid glyph codes should return non-NULL */
        for (int i = 0; i < _GLYPH_MAX; i++) {
                const char *g = glyph_full(i, false);
                ASSERT_NOT_NULL(g);
        }
}

TEST(glyph_full_invalid) {
        ASSERT_NULL(glyph_full(_GLYPH_INVALID, false));
        ASSERT_NULL(glyph_full(_GLYPH_INVALID, true));
}

TEST(glyph_full_emoji_force_utf) {
        /* Emoji glyphs should return UTF-8 when force_utf=true */
        const char *g = glyph_full(GLYPH_ECSTATIC_SMILEY, true);
        ASSERT_NOT_NULL(g);
        /* Emoji should be multi-byte UTF-8 */
        ASSERT_TRUE(strlen(g) > 1);
}

TEST(glyph_full_space) {
        /* Space is the same regardless of mode */
        ASSERT_STREQ(glyph_full(GLYPH_SPACE, false), " ");
        ASSERT_STREQ(glyph_full(GLYPH_SPACE, true), " ");
}

TEST(glyph_full_deterministic) {
        /* Same glyph should always return the same string */
        const char *g1 = glyph_full(GLYPH_BLACK_CIRCLE, false);
        const char *g2 = glyph_full(GLYPH_BLACK_CIRCLE, false);
        ASSERT_STREQ(g1, g2);

        g1 = glyph_full(GLYPH_CHECK_MARK, true);
        g2 = glyph_full(GLYPH_CHECK_MARK, true);
        ASSERT_STREQ(g1, g2);
}

TEST(glyph_shortcuts) {
        /* glyph() is equivalent to glyph_full(code, false) */
        ASSERT_STREQ(glyph(GLYPH_SPACE), glyph_full(GLYPH_SPACE, false));

        /* glyph_check_mark */
        ASSERT_STREQ(glyph_check_mark(true), glyph_full(GLYPH_CHECK_MARK, false));
        ASSERT_STREQ(glyph_check_mark(false), glyph_full(GLYPH_CROSS_MARK, false));

        /* glyph_check_mark_space */
        ASSERT_STREQ(glyph_check_mark_space(true), glyph_full(GLYPH_CHECK_MARK, false));
        ASSERT_STREQ(glyph_check_mark_space(false), " ");
}

DEFINE_TEST_MAIN(LOG_DEBUG);
