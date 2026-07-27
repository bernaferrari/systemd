/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include "rust/compress_util.h"

/* C references */
#include "compress.h"
#include "string-util.h"

/*
 * C helper: return the compression supported mask.
 * The C code in compress.c uses a static local computed at init time.
 * We provide a definition here so the Rust staticlib can link.
 */
uint32_t rs_get_compression_supported_mask(void) {
        /* Match what C compress_supported() uses: NONE always, others depend on HAVE_* */
        uint32_t mask = 0;
        mask |= (1u << COMPRESSION_NONE);
#if HAVE_XZ
        mask |= (1u << COMPRESSION_XZ);
#endif
#if HAVE_LZ4
        mask |= (1u << COMPRESSION_LZ4);
#endif
#if HAVE_ZSTD
        mask |= (1u << COMPRESSION_ZSTD);
#endif
        return mask;
}

static void test_compression_to_string(void) {
        const char *c_ret, *r_ret;

        c_ret = compression_to_string(COMPRESSION_NONE);
        r_ret = rs_compression_to_string(COMPRESSION_NONE);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        c_ret = compression_to_string(COMPRESSION_XZ);
        r_ret = rs_compression_to_string(COMPRESSION_XZ);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        c_ret = compression_to_string(COMPRESSION_LZ4);
        r_ret = rs_compression_to_string(COMPRESSION_LZ4);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        c_ret = compression_to_string(COMPRESSION_ZSTD);
        r_ret = rs_compression_to_string(COMPRESSION_ZSTD);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        /* Invalid (out of range) — C returns NULL via string_table_lookup */
        c_ret = compression_to_string(_COMPRESSION_INVALID);
        r_ret = rs_compression_to_string(_COMPRESSION_INVALID);
        assert_se(streq_ptr(c_ret, r_ret));
}

static void test_compression_from_string(void) {
        Compression c_ret;
        int r_ret;

        c_ret = compression_from_string("NONE");
        r_ret = rs_compression_from_string("NONE");
        assert_se((int)c_ret == r_ret);
        assert_se(c_ret == COMPRESSION_NONE);

        c_ret = compression_from_string("XZ");
        r_ret = rs_compression_from_string("XZ");
        assert_se((int)c_ret == r_ret);
        assert_se(c_ret == COMPRESSION_XZ);

        c_ret = compression_from_string("LZ4");
        r_ret = rs_compression_from_string("LZ4");
        assert_se((int)c_ret == r_ret);
        assert_se(c_ret == COMPRESSION_LZ4);

        c_ret = compression_from_string("ZSTD");
        r_ret = rs_compression_from_string("ZSTD");
        assert_se((int)c_ret == r_ret);
        assert_se(c_ret == COMPRESSION_ZSTD);

        /* Invalid */
        c_ret = compression_from_string("bogus");
        r_ret = rs_compression_from_string("bogus");
        assert_se((int)c_ret == r_ret);

        c_ret = compression_from_string(NULL);
        r_ret = rs_compression_from_string(NULL);
        assert_se((int)c_ret == r_ret);
}

/*
 * C generates compression_lowercase_to_string / compression_lowercase_from_string
 * from DEFINE_STRING_TABLE_LOOKUP(compression_lowercase, Compression).
 * Rust uses rs_compression_to_string_lowercase / rs_compression_from_string_lowercase.
 */
static void test_compression_to_string_lowercase(void) {
        const char *c_ret, *r_ret;

        c_ret = compression_lowercase_to_string(COMPRESSION_NONE);
        r_ret = rs_compression_to_string_lowercase(COMPRESSION_NONE);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        c_ret = compression_lowercase_to_string(COMPRESSION_XZ);
        r_ret = rs_compression_to_string_lowercase(COMPRESSION_XZ);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        c_ret = compression_lowercase_to_string(COMPRESSION_LZ4);
        r_ret = rs_compression_to_string_lowercase(COMPRESSION_LZ4);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        c_ret = compression_lowercase_to_string(COMPRESSION_ZSTD);
        r_ret = rs_compression_to_string_lowercase(COMPRESSION_ZSTD);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        /* Invalid */
        c_ret = compression_lowercase_to_string(_COMPRESSION_INVALID);
        r_ret = rs_compression_to_string_lowercase(_COMPRESSION_INVALID);
        assert_se(streq_ptr(c_ret, r_ret));
}

static void test_compression_from_string_lowercase(void) {
        Compression c_ret;
        int r_ret;

        c_ret = compression_lowercase_from_string("none");
        r_ret = rs_compression_from_string_lowercase("none");
        assert_se((int)c_ret == r_ret);
        assert_se(c_ret == COMPRESSION_NONE);

        c_ret = compression_lowercase_from_string("xz");
        r_ret = rs_compression_from_string_lowercase("xz");
        assert_se((int)c_ret == r_ret);
        assert_se(c_ret == COMPRESSION_XZ);

        c_ret = compression_lowercase_from_string("lz4");
        r_ret = rs_compression_from_string_lowercase("lz4");
        assert_se((int)c_ret == r_ret);
        assert_se(c_ret == COMPRESSION_LZ4);

        c_ret = compression_lowercase_from_string("zstd");
        r_ret = rs_compression_from_string_lowercase("zstd");
        assert_se((int)c_ret == r_ret);
        assert_se(c_ret == COMPRESSION_ZSTD);

        /* Invalid */
        c_ret = compression_lowercase_from_string("bogus");
        r_ret = rs_compression_from_string_lowercase("bogus");
        assert_se((int)c_ret == r_ret);

        c_ret = compression_lowercase_from_string(NULL);
        r_ret = rs_compression_from_string_lowercase(NULL);
        assert_se((int)c_ret == r_ret);
}

static void test_compression_supported(void) {
        bool c_ret, r_ret;

        /* Only test valid range — C asserts c >= 0 && c < _COMPRESSION_MAX */
        c_ret = compression_supported(COMPRESSION_NONE);
        r_ret = rs_compression_supported(COMPRESSION_NONE);
        assert_se(c_ret == r_ret);
        assert_se(c_ret); /* NONE is always supported */

        c_ret = compression_supported(COMPRESSION_XZ);
        r_ret = rs_compression_supported(COMPRESSION_XZ);
        assert_se(c_ret == r_ret);

        c_ret = compression_supported(COMPRESSION_LZ4);
        r_ret = rs_compression_supported(COMPRESSION_LZ4);
        assert_se(c_ret == r_ret);

        c_ret = compression_supported(COMPRESSION_ZSTD);
        r_ret = rs_compression_supported(COMPRESSION_ZSTD);
        assert_se(c_ret == r_ret);
}

int main(int argc, char **argv) {
        test_compression_to_string();
        test_compression_from_string();
        test_compression_to_string_lowercase();
        test_compression_from_string_lowercase();
        test_compression_supported();
        return 0;
}
