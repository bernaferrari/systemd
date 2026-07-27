/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "compress.h"
#include "tests.h"

TEST(compression_supported_all) {
        assert_se(compression_supported(COMPRESSION_NONE));
        /* Results depend on build config */
        (void) compression_supported(COMPRESSION_XZ);
        (void) compression_supported(COMPRESSION_LZ4);
        (void) compression_supported(COMPRESSION_ZSTD);
}

TEST(dlopen_lzma_basic) {
        int r = dlopen_lzma();
        log_debug("dlopen_lzma: %d", r);
}

TEST(dlopen_lz4_basic) {
        int r = dlopen_lz4();
        log_debug("dlopen_lz4: %d", r);
}

TEST(dlopen_zstd_basic) {
        int r = dlopen_zstd();
        log_debug("dlopen_zstd: %d", r);
}

TEST(default_compression_extension_basic) {
        const char *ext = default_compression_extension();
        /* Returns NULL when no compression is enabled */
        log_debug("default_compression_extension: %s", ext ?: "(null)");
}

DEFINE_TEST_MAIN(LOG_DEBUG);
