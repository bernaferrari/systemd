/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdlib.h>

#include "ansi-color.h"
#include "tests.h"

TEST(looks_like_ansi_color_code_valid) {
        ASSERT_TRUE(looks_like_ansi_color_code("0"));
        ASSERT_TRUE(looks_like_ansi_color_code("1"));
        ASSERT_TRUE(looks_like_ansi_color_code("38"));
        ASSERT_TRUE(looks_like_ansi_color_code("255"));
        ASSERT_TRUE(looks_like_ansi_color_code("0;1"));
        ASSERT_TRUE(looks_like_ansi_color_code("1;31"));
        ASSERT_TRUE(looks_like_ansi_color_code("38;5;245"));
        ASSERT_TRUE(looks_like_ansi_color_code("1;4;31"));
        ASSERT_TRUE(looks_like_ansi_color_code("0;1;2;3;4"));
}

TEST(looks_like_ansi_color_code_invalid) {
        ASSERT_FALSE(looks_like_ansi_color_code(""));
        ASSERT_FALSE(looks_like_ansi_color_code("abc"));
        ASSERT_FALSE(looks_like_ansi_color_code("1a"));
        ASSERT_FALSE(looks_like_ansi_color_code(";1"));
        ASSERT_FALSE(looks_like_ansi_color_code("1;"));
        ASSERT_FALSE(looks_like_ansi_color_code("1;;2"));
        ASSERT_FALSE(looks_like_ansi_color_code("1;2;"));
        ASSERT_FALSE(looks_like_ansi_color_code(" "));
        ASSERT_FALSE(looks_like_ansi_color_code(" 1"));
        ASSERT_FALSE(looks_like_ansi_color_code("1 "));
        ASSERT_FALSE(looks_like_ansi_color_code("1; 2"));
        ASSERT_FALSE(looks_like_ansi_color_code("1;2a"));
        ASSERT_FALSE(looks_like_ansi_color_code("m"));
}

TEST(color_mode_lookup) {
        /* Fixed modes */
        ASSERT_STREQ(color_mode_to_string(COLOR_OFF), "off");
        ASSERT_STREQ(color_mode_to_string(COLOR_16), "16");
        ASSERT_STREQ(color_mode_to_string(COLOR_256), "256");
        ASSERT_STREQ(color_mode_to_string(COLOR_24BIT), "24bit");

        /* Auto modes */
        ASSERT_STREQ(color_mode_to_string(COLOR_AUTO_16), "auto-16");
        ASSERT_STREQ(color_mode_to_string(COLOR_AUTO_256), "auto-256");
        ASSERT_STREQ(color_mode_to_string(COLOR_AUTO_24BIT), "auto-24bit");
        ASSERT_STREQ(color_mode_to_string(COLOR_TRUE), "true");
}

TEST(color_mode_from_string) {
        ASSERT_EQ(color_mode_from_string("off"), COLOR_OFF);
        ASSERT_EQ(color_mode_from_string("16"), COLOR_16);
        ASSERT_EQ(color_mode_from_string("256"), COLOR_256);
        ASSERT_EQ(color_mode_from_string("24bit"), COLOR_24BIT);
        ASSERT_EQ(color_mode_from_string("auto-16"), COLOR_AUTO_16);
        ASSERT_EQ(color_mode_from_string("auto-256"), COLOR_AUTO_256);
        ASSERT_EQ(color_mode_from_string("auto-24bit"), COLOR_AUTO_24BIT);
        ASSERT_EQ(color_mode_from_string("true"), COLOR_TRUE);

        /* Boolean handling */
        ASSERT_EQ(color_mode_from_string("yes"), COLOR_TRUE);
        ASSERT_EQ(color_mode_from_string("no"), COLOR_OFF);
        ASSERT_EQ(color_mode_from_string("1"), COLOR_TRUE);
        ASSERT_EQ(color_mode_from_string("0"), COLOR_OFF);

        /* Invalid */
        ASSERT_EQ(color_mode_from_string("invalid"), _COLOR_MODE_INVALID);
        ASSERT_EQ(color_mode_from_string(NULL), _COLOR_MODE_INVALID);
}

TEST(reset_ansi_feature_caches) {
        /* Just verify it doesn't crash */
        reset_ansi_feature_caches();
        reset_ansi_feature_caches();
}

DEFINE_TEST_MAIN(LOG_DEBUG);
