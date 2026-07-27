/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "utf8.h"
#include "tests.h"

TEST(unichar_is_valid) {
        /* Basic ASCII */
        ASSERT_TRUE(unichar_is_valid('A'));
        ASSERT_TRUE(unichar_is_valid(' '));
        ASSERT_TRUE(unichar_is_valid(0x7F));

        /* Latin supplement */
        ASSERT_TRUE(unichar_is_valid(0x00E9)); /* é */

        /* CJK */
        ASSERT_TRUE(unichar_is_valid(0x4E2D)); /* 中 */

        /* Emoji */
        ASSERT_TRUE(unichar_is_valid(0x1F600)); /* 😀 */

        /* Surrogates are invalid */
        ASSERT_FALSE(unichar_is_valid(0xD800));
        ASSERT_FALSE(unichar_is_valid(0xDFFF));

        /* Beyond Unicode range */
        ASSERT_FALSE(unichar_is_valid(0x110000));
        ASSERT_FALSE(unichar_is_valid(UINT32_MAX));
}

TEST(utf8_encode_unichar) {
        char buf[4];

        /* ASCII: 1 byte */
        ASSERT_EQ(utf8_encode_unichar(buf, 'A'), 1u);
        ASSERT_EQ(buf[0], 'A');

        /* 2-byte sequence: ö (U+00F6) */
        ASSERT_EQ(utf8_encode_unichar(buf, 0xF6), 2u);

        /* 3-byte sequence: 中 (U+4E2D) */
        ASSERT_EQ(utf8_encode_unichar(buf, 0x4E2D), 3u);

        /* 4-byte sequence: 😀 (U+1F600) */
        ASSERT_EQ(utf8_encode_unichar(buf, 0x1F600), 4u);
}

TEST(utf8_encoded_valid_unichar) {
        /* Valid ASCII */
        ASSERT_EQ(utf8_encoded_valid_unichar("A", 1), 1);

        /* Valid 2-byte */
        ASSERT_EQ(utf8_encoded_valid_unichar("\xC3\xA9", 2), 2); /* é */

        /* Valid 3-byte */
        ASSERT_EQ(utf8_encoded_valid_unichar("\xE4\xB8\xAD", 3), 3); /* 中 */

        /* Valid 4-byte */
        ASSERT_EQ(utf8_encoded_valid_unichar("\xF0\x9F\x98\x80", 4), 4); /* 😀 */

        /* Invalid: truncated */
        ASSERT_LT(utf8_encoded_valid_unichar("\xC3", 1), 0);

        /* Invalid: continuation byte as start */
        ASSERT_LT(utf8_encoded_valid_unichar("\x80", 1), 0);

        /* Invalid: overlong */
        ASSERT_LT(utf8_encoded_valid_unichar("\xC0\x80", 2), 0);
}

TEST(utf8_encoded_to_unichar) {
        char32_t c;

        ASSERT_OK(utf8_encoded_to_unichar("A", &c));
        ASSERT_EQ(c, (char32_t)'A');

        ASSERT_OK(utf8_encoded_to_unichar("\xC3\xA9", &c));
        ASSERT_EQ(c, (char32_t)0xE9);
}

TEST(utf8_is_valid) {
        ASSERT_NOT_NULL(utf8_is_valid("hello"));
        ASSERT_NOT_NULL(utf8_is_valid(""));
        ASSERT_NOT_NULL(utf8_is_valid("café"));
        ASSERT_NULL(utf8_is_valid("\xFF"));
        ASSERT_NULL(utf8_is_valid("\xC3"));  /* truncated */
}

TEST(ascii_is_valid) {
        ASSERT_NOT_NULL(ascii_is_valid("hello"));
        ASSERT_NOT_NULL(ascii_is_valid(""));
        ASSERT_NULL(ascii_is_valid("café")); /* é is not ASCII */
        ASSERT_NULL(ascii_is_valid("\xFF"));
}

TEST(utf8_n_codepoints) {
        ASSERT_EQ(utf8_n_codepoints(""), 0u);
        ASSERT_EQ(utf8_n_codepoints("hello"), 5u);
        ASSERT_EQ(utf8_n_codepoints("café"), 4u);
        ASSERT_EQ(utf8_n_codepoints("中文"), 2u);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
