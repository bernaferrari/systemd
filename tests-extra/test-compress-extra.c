/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "compress.h"
#include "string-util.h"
#include "tests.h"

TEST(compression_roundtrip) {
        /* Roundtrip for compression_to_string / compression_from_string */
        assert_se(streq(compression_to_string(COMPRESSION_NONE), "NONE"));
        assert_se(streq(compression_to_string(COMPRESSION_XZ), "XZ"));
        assert_se(streq(compression_to_string(COMPRESSION_LZ4), "LZ4"));
        assert_se(streq(compression_to_string(COMPRESSION_ZSTD), "ZSTD"));

        assert_se(compression_from_string("NONE") == COMPRESSION_NONE);
        assert_se(compression_from_string("XZ") == COMPRESSION_XZ);
        assert_se(compression_from_string("LZ4") == COMPRESSION_LZ4);
        assert_se(compression_from_string("ZSTD") == COMPRESSION_ZSTD);
        assert_se(compression_from_string("invalid") == _COMPRESSION_INVALID);
}

TEST(compression_lowercase_roundtrip) {
        assert_se(streq(compression_lowercase_to_string(COMPRESSION_NONE), "none"));
        assert_se(streq(compression_lowercase_to_string(COMPRESSION_XZ), "xz"));
        assert_se(streq(compression_lowercase_to_string(COMPRESSION_LZ4), "lz4"));
        assert_se(streq(compression_lowercase_to_string(COMPRESSION_ZSTD), "zstd"));

        assert_se(compression_lowercase_from_string("none") == COMPRESSION_NONE);
        assert_se(compression_lowercase_from_string("xz") == COMPRESSION_XZ);
        assert_se(compression_lowercase_from_string("lz4") == COMPRESSION_LZ4);
        assert_se(compression_lowercase_from_string("zstd") == COMPRESSION_ZSTD);
}

TEST(compression_supported) {
        assert_se(compression_supported(COMPRESSION_NONE));
        /* XZ, LZ4, ZSTD support depends on build config — just verify they don't crash */
        (void) compression_supported(COMPRESSION_XZ);
        (void) compression_supported(COMPRESSION_LZ4);
        (void) compression_supported(COMPRESSION_ZSTD);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
