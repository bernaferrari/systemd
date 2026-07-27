/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "compress.h"
#include "tests.h"

TEST(compression_to_from_string) {
        assert_se(streq(compression_to_string(COMPRESSION_NONE), "NONE"));
        assert_se(streq(compression_to_string(COMPRESSION_XZ), "XZ"));
        assert_se(streq(compression_to_string(COMPRESSION_LZ4), "LZ4"));
        assert_se(streq(compression_to_string(COMPRESSION_ZSTD), "ZSTD"));

        assert_se(compression_from_string("NONE") == COMPRESSION_NONE);
        assert_se(compression_from_string("XZ") == COMPRESSION_XZ);
        assert_se(compression_from_string("LZ4") == COMPRESSION_LZ4);
        assert_se(compression_from_string("ZSTD") == COMPRESSION_ZSTD);
        assert_se(compression_from_string("invalid") < 0);
}

TEST(compression_lowercase_to_from_string) {
        assert_se(streq(compression_lowercase_to_string(COMPRESSION_NONE), "none"));
        assert_se(streq(compression_lowercase_to_string(COMPRESSION_XZ), "xz"));
        assert_se(streq(compression_lowercase_to_string(COMPRESSION_LZ4), "lz4"));
        assert_se(streq(compression_lowercase_to_string(COMPRESSION_ZSTD), "zstd"));

        assert_se(compression_lowercase_from_string("none") == COMPRESSION_NONE);
        assert_se(compression_lowercase_from_string("xz") == COMPRESSION_XZ);
        assert_se(compression_lowercase_from_string("lz4") == COMPRESSION_LZ4);
        assert_se(compression_lowercase_from_string("zstd") == COMPRESSION_ZSTD);
        assert_se(compression_lowercase_from_string("invalid") < 0);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
