/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "compress.h"
#include "tests.h"

TEST(compression_to_string) {
        ASSERT_STREQ(compression_to_string(COMPRESSION_NONE), "NONE");
        ASSERT_STREQ(compression_to_string(COMPRESSION_XZ), "XZ");
        ASSERT_STREQ(compression_to_string(COMPRESSION_LZ4), "LZ4");
        ASSERT_STREQ(compression_to_string(COMPRESSION_ZSTD), "ZSTD");
}

TEST(compression_from_string) {
        ASSERT_EQ(compression_from_string("NONE"), COMPRESSION_NONE);
        ASSERT_EQ(compression_from_string("XZ"), COMPRESSION_XZ);
        ASSERT_EQ(compression_from_string("LZ4"), COMPRESSION_LZ4);
        ASSERT_EQ(compression_from_string("ZSTD"), COMPRESSION_ZSTD);
        ASSERT_EQ(compression_from_string("invalid"), _COMPRESSION_INVALID);
}

TEST(compression_lowercase_to_string) {
        ASSERT_STREQ(compression_lowercase_to_string(COMPRESSION_NONE), "none");
        ASSERT_STREQ(compression_lowercase_to_string(COMPRESSION_XZ), "xz");
        ASSERT_STREQ(compression_lowercase_to_string(COMPRESSION_LZ4), "lz4");
        ASSERT_STREQ(compression_lowercase_to_string(COMPRESSION_ZSTD), "zstd");
}

TEST(compression_lowercase_from_string) {
        ASSERT_EQ(compression_lowercase_from_string("none"), COMPRESSION_NONE);
        ASSERT_EQ(compression_lowercase_from_string("xz"), COMPRESSION_XZ);
        ASSERT_EQ(compression_lowercase_from_string("lz4"), COMPRESSION_LZ4);
        ASSERT_EQ(compression_lowercase_from_string("zstd"), COMPRESSION_ZSTD);
        ASSERT_EQ(compression_lowercase_from_string("invalid"), _COMPRESSION_INVALID);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
