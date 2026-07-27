/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdlib.h>
#include <string.h>

#include "ansi-color.h"
#include "tests.h"

/* Rust FFI */
#include "rust/ansi_color.h"

/* ── looks_like_ansi_color_code ─────────────────────────────────────────── */

TEST(looks_like_ansi_color_code_simple) {
        /* Valid SGR parameters */
        assert_se(looks_like_ansi_color_code("0") == rs_looks_like_ansi_color_code("0"));
        assert_se(looks_like_ansi_color_code("1") == rs_looks_like_ansi_color_code("1"));
        assert_se(looks_like_ansi_color_code("38") == rs_looks_like_ansi_color_code("38"));
        assert_se(looks_like_ansi_color_code("255") == rs_looks_like_ansi_color_code("255"));
}

TEST(looks_like_ansi_color_code_multi) {
        /* Multiple parameters separated by semicolons */
        assert_se(looks_like_ansi_color_code("0;1") == rs_looks_like_ansi_color_code("0;1"));
        assert_se(looks_like_ansi_color_code("38;5;245") == rs_looks_like_ansi_color_code("38;5;245"));
        assert_se(looks_like_ansi_color_code("1;2;3;4") == rs_looks_like_ansi_color_code("1;2;3;4"));
}

TEST(looks_like_ansi_color_code_invalid) {
        /* Various invalid inputs */
        const char *invalid[] = {
                "",
                ";",
                "0;",
                ";1",
                "abc",
                "1;abc",
                "1;2;",
                "a1",
                "1a",
                NULL,
        };

        for (int i = 0; invalid[i] != NULL; i++) {
                assert_se(looks_like_ansi_color_code(invalid[i]) == rs_looks_like_ansi_color_code(invalid[i]));
        }
}

TEST(looks_like_ansi_color_code_complex) {
        /* More complex valid patterns */
        assert_se(looks_like_ansi_color_code("38;2;255;128;0") == rs_looks_like_ansi_color_code("38;2;255;128;0"));
        assert_se(looks_like_ansi_color_code("48;5;196") == rs_looks_like_ansi_color_code("48;5;196"));
        assert_se(looks_like_ansi_color_code("1;7;38;5;220") == rs_looks_like_ansi_color_code("1;7;38;5;220"));
}

/* ── color_mode_from_string / color_mode_to_string ───────────────────────── */

TEST(color_mode_roundtrip) {
        static const ColorMode modes[] = {
                COLOR_OFF, COLOR_16, COLOR_256, COLOR_24BIT,
                COLOR_AUTO_16, COLOR_AUTO_256, COLOR_AUTO_24BIT, COLOR_TRUE,
        };

        for (size_t i = 0; i < ELEMENTSOF(modes); i++) {
                const char *c_str = color_mode_to_string(modes[i]);
                const char *rs_str = rs_color_mode_to_string(modes[i]);

                assert_se(c_str == NULL && rs_str == NULL || streq_ptr(c_str, rs_str));

                /* Roundtrip: string → mode */
                if (c_str) {
                        assert_se(color_mode_from_string(c_str) == rs_color_mode_from_string(rs_str));
                }
        }
}

TEST(color_mode_from_string_known) {
        assert_se(color_mode_from_string("off") == rs_color_mode_from_string("off"));
        assert_se(color_mode_from_string("16") == rs_color_mode_from_string("16"));
        assert_se(color_mode_from_string("256") == rs_color_mode_from_string("256"));
        assert_se(color_mode_from_string("24bit") == rs_color_mode_from_string("24bit"));
        assert_se(color_mode_from_string("auto-16") == rs_color_mode_from_string("auto-16"));
        assert_se(color_mode_from_string("auto-256") == rs_color_mode_from_string("auto-256"));
        assert_se(color_mode_from_string("auto-24bit") == rs_color_mode_from_string("auto-24bit"));
        assert_se(color_mode_from_string("true") == rs_color_mode_from_string("true"));
}

TEST(color_mode_from_string_boolean) {
        /* DEFINE_STRING_TABLE_LOOKUP_WITH_BOOLEAN accepts yes/no/true/false */
        assert_se(color_mode_from_string("yes") == rs_color_mode_from_string("yes"));
        assert_se(color_mode_from_string("no") == rs_color_mode_from_string("no"));
        assert_se(color_mode_from_string("true") == rs_color_mode_from_string("true"));
        assert_se(color_mode_from_string("false") == rs_color_mode_from_string("false"));
        assert_se(color_mode_from_string("1") == rs_color_mode_from_string("1"));
        assert_se(color_mode_from_string("0") == rs_color_mode_from_string("0"));

        /* Invalid strings */
        assert_se(color_mode_from_string("bogus") == rs_color_mode_from_string("bogus"));
        assert_se(color_mode_from_string("") == rs_color_mode_from_string(""));
}

TEST(color_mode_to_string_invalid) {
        /* Out-of-range mode */
        const char *c_str = color_mode_to_string(-1);
        const char *rs_str = rs_color_mode_to_string(-1);
        assert_se(c_str == NULL && rs_str == NULL);
}

/* ── parse_systemd_colors ────────────────────────────────────────────────── */

TEST(parse_systemd_colors_unset) {
        /* With $SYSTEMD_COLORS unset, both should return _COLOR_MODE_INVALID */
        unsetenv("SYSTEMD_COLORS");
        assert_se(parse_systemd_colors() == rs_parse_systemd_colors());
}

TEST(parse_systemd_colors_explicit) {
        /* Set $SYSTEMD_COLORS to various values */
        const char *values[] = { "off", "16", "256", "24bit", "true", NULL };

        for (int i = 0; values[i] != NULL; i++) {
                setenv("SYSTEMD_COLORS", values[i], 1);
                assert_se(parse_systemd_colors() == rs_parse_systemd_colors());
        }

        unsetenv("SYSTEMD_COLORS");
}

/* ── get_color_mode ──────────────────────────────────────────────────────── */

TEST(get_color_mode_off) {
        /* Force off via $SYSTEMD_COLORS=off */
        unsetenv("COLORTERM");
        unsetenv("NO_COLOR");
        setenv("SYSTEMD_COLORS", "off", 1);
        reset_ansi_feature_caches();
        assert_se(get_color_mode() == rs_get_color_mode());
        assert_se(get_color_mode() == COLOR_OFF);
        unsetenv("SYSTEMD_COLORS");
}

TEST(get_color_mode_no_color) {
        /* $NO_COLOR forces off when not COLOR_TRUE */
        unsetenv("SYSTEMD_COLORS");
        setenv("NO_COLOR", "1", 1);
        reset_ansi_feature_caches();
        assert_se(get_color_mode() == rs_get_color_mode());
        assert_se(get_color_mode() == COLOR_OFF);
        unsetenv("NO_COLOR");
}

TEST(get_color_mode_colorterm) {
        /* $COLORTERM=truecolor should give 24bit when no other override */
        unsetenv("SYSTEMD_COLORS");
        unsetenv("NO_COLOR");
        setenv("COLORTERM", "truecolor", 1);
        reset_ansi_feature_caches();
        assert_se(get_color_mode() == rs_get_color_mode());
        unsetenv("COLORTERM");
}

TEST(get_color_mode_colorterm_24bit) {
        /* $COLORTERM=24bit is also recognized */
        unsetenv("SYSTEMD_COLORS");
        unsetenv("NO_COLOR");
        setenv("COLORTERM", "24bit", 1);
        reset_ansi_feature_caches();
        assert_se(get_color_mode() == rs_get_color_mode());
        unsetenv("COLORTERM");
}

/* ── underline_enabled ───────────────────────────────────────────────────── */

TEST(underline_enabled_off) {
        /* Colors off → underline off */
        unsetenv("COLORTERM");
        unsetenv("NO_COLOR");
        setenv("SYSTEMD_COLORS", "off", 1);
        reset_ansi_feature_caches();
        assert_se(underline_enabled() == rs_underline_enabled());
        assert_se(underline_enabled() == false);
        unsetenv("SYSTEMD_COLORS");
}

/* ── main ────────────────────────────────────────────────────────────────── */

DEFINE_TEST_MAIN(LOG_INFO);
