/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "utf8.h"
#include "tests.h"

TEST(utf8_is_valid) {
        ASSERT_TRUE(utf8_is_valid("hello"));
        ASSERT_TRUE(utf8_is_valid(""));
        ASSERT_FALSE(utf8_is_valid("\xff\xfe"));
}

TEST(unichar_is_valid) {
        ASSERT_TRUE(unichar_is_valid('a'));
        ASSERT_TRUE(unichar_is_valid(0x007F));
        ASSERT_TRUE(unichar_is_valid(0x00A9));
        ASSERT_FALSE(unichar_is_valid(0xD800));
        ASSERT_FALSE(unichar_is_valid(0xFFFFFFFF));
}

TEST(ascii_is_valid) {
        ASSERT_TRUE(ascii_is_valid("hello"));
        ASSERT_TRUE(ascii_is_valid(""));
        ASSERT_FALSE(ascii_is_valid("héllo"));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
