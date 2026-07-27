/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "utf8.h"
#include "tests.h"

TEST(utf8_encode_unichar) {
        char buf[4];
        size_t len;
        /* ASCII */
        len = utf8_encode_unichar(buf, 'A');
        ASSERT_EQ(len, 1u);
        ASSERT_EQ(buf[0], 'A');
        /* 2-byte sequence (U+00E9 = é) */
        len = utf8_encode_unichar(buf, 0x00E9);
        ASSERT_EQ(len, 2u);
        /* 3-byte sequence (U+4E2D = 中) */
        len = utf8_encode_unichar(buf, 0x4E2D);
        ASSERT_EQ(len, 3u);
        /* 4-byte sequence (U+1F600 = 😀) */
        len = utf8_encode_unichar(buf, 0x1F600);
        ASSERT_EQ(len, 4u);
}

TEST(utf8_encoded_valid_unichar) {
        /* utf8_encoded_valid_unichar takes (str, length) */
        /* Valid ASCII */
        ASSERT_EQ(utf8_encoded_valid_unichar("A", 1), 1);
        /* Valid 2-byte */
        ASSERT_EQ(utf8_encoded_valid_unichar("\xC3\xA9", 2), 2);
        /* Valid 3-byte */
        ASSERT_EQ(utf8_encoded_valid_unichar("\xE4\xB8\xAD", 3), 3);
        /* Valid 4-byte */
        ASSERT_EQ(utf8_encoded_valid_unichar("\xF0\x9F\x98\x80", 4), 4);
        /* Invalid: continuation byte at start */
        ASSERT_EQ(utf8_encoded_valid_unichar("\x80", 1), -EINVAL);
        /* Invalid: overlong encoding */
        ASSERT_EQ(utf8_encoded_valid_unichar("\xC0\x80", 2), -EINVAL);
}

TEST(utf8_encoded_to_unichar) {
        char32_t c;
        ASSERT_EQ(utf8_encoded_to_unichar("A", &c), 1);
        ASSERT_EQ(c, (char32_t)'A');
        ASSERT_EQ(utf8_encoded_to_unichar("\xC3\xA9", &c), 2);
        ASSERT_EQ(c, (char32_t)0x00E9);
}

TEST(utf8_n_codepoints) {
        ASSERT_EQ(utf8_n_codepoints(""), 0u);
        ASSERT_EQ(utf8_n_codepoints("hello"), 5u);
        ASSERT_EQ(utf8_n_codepoints("é"), 1u);
        ASSERT_EQ(utf8_n_codepoints("helloé"), 6u);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
