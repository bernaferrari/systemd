/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "glyph-util.h"
#include "string-util.h"
#include "tests.h"

TEST(glyph_basic) {
        const char *s = glyph(GLYPH_SPACE);
        assert_se(s);

        s = glyph(GLYPH_TREE_RIGHT);
        assert_se(s);

        s = glyph(GLYPH_ARROW_RIGHT);
        assert_se(s);
        log_debug("glyph(ARROW_RIGHT): %s", s);
}

TEST(glyph_full_basic) {
        const char *s = glyph_full(GLYPH_SPACE, true);
        assert_se(s);
        log_debug("glyph_full(SPACE, true): '%s'", s);

        s = glyph_full(GLYPH_TREE_RIGHT, false);
        assert_se(s);
        log_debug("glyph_full(TREE_RIGHT, false): '%s'", s);
}

TEST(emoji_enabled_basic) {
        (void) emoji_enabled();
}

TEST(optional_glyph_basic) {
        const char *s = optional_glyph(GLYPH_ECSTATIC_SMILEY);
        assert_se(s);
        log_debug("optional_glyph(ECSTATIC_SMILEY): '%s'", s);
}

TEST(glyph_check_mark_basic) {
        const char *s = glyph_check_mark(true);
        assert_se(s);
        log_debug("glyph_check_mark(true): '%s'", s);

        s = glyph_check_mark(false);
        assert_se(s);
        log_debug("glyph_check_mark(false): '%s'", s);
}

TEST(glyph_check_mark_space_basic) {
        const char *s = glyph_check_mark_space(true);
        assert_se(s);

        s = glyph_check_mark_space(false);
        assert_se(streq(s, " "));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
