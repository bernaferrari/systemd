/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "gunicode.h"
#include "tests.h"

TEST(unichar_iswide) {
        /* ASCII characters are not wide */
        ASSERT_FALSE(unichar_iswide('A'));
        ASSERT_FALSE(unichar_iswide('z'));
        ASSERT_FALSE(unichar_iswide(' '));
        ASSERT_FALSE(unichar_iswide('\n'));

        /* East Asian Wide characters */
        ASSERT_TRUE(unichar_iswide(0x1100));  /* Hangul Jamo */
        ASSERT_TRUE(unichar_iswide(0x3000));  /* CJK Symbols */
        ASSERT_TRUE(unichar_iswide(0xFF01));  /* Fullwidth Forms */
        ASSERT_TRUE(unichar_iswide(0x4E00));  /* CJK Unified Ideographs */

        /* Zero width characters */
        ASSERT_FALSE(unichar_iswide(0x200B));  /* Zero-width space */
}

DEFINE_TEST_MAIN(LOG_DEBUG);
