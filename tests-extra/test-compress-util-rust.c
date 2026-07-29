/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <string.h>

#include "compress.h"
#include "rust/compress_util.h"
#include "string-util.h"

/* RUST-CONTRACT: compression-string-tables */
/* RUST-CONTRACT: compression-string-parsing */
/* RUST-CONTRACT: compression-supported-feature-mask */

/*
 * Linked only by this shadow test. Keep it aligned with compression_supported()
 * in compress.c, including codecs added after the original Rust port.
 */
static uint32_t c_compression_supported_mask(void) {
        uint32_t mask = 1u << COMPRESSION_NONE;

#if HAVE_XZ
        mask |= 1u << COMPRESSION_XZ;
#endif
#if HAVE_LZ4
        mask |= 1u << COMPRESSION_LZ4;
#endif
#if HAVE_ZSTD
        mask |= 1u << COMPRESSION_ZSTD;
#endif
#if HAVE_ZLIB
        mask |= 1u << COMPRESSION_GZIP;
#endif
#if HAVE_BZIP2
        mask |= 1u << COMPRESSION_BZIP2;
#endif

        return mask;
}

static const Compression compression_values[] = {
        COMPRESSION_NONE,
        COMPRESSION_XZ,
        COMPRESSION_LZ4,
        COMPRESSION_ZSTD,
        COMPRESSION_GZIP,
        COMPRESSION_BZIP2,
};

static void assert_string_lookup_matches(
                const char *(*c_to_string)(Compression),
                const char *(*rs_to_string)(int),
                Compression (*c_from_string)(const char *),
                int (*rs_from_string)(const char *),
                const char *const names[]) {

        static const char non_utf8[] = "\xff";
        static const char nul_terminated_prefix[] = "xz\0ignored";

        for (size_t i = 0; i < ELEMENTSOF(compression_values); i++) {
                Compression value = compression_values[i];
                const char *c_name, *rs_name;

                c_name = c_to_string(value);
                rs_name = rs_to_string(value);
                assert_se(c_name != NULL);
                assert_se(rs_name != NULL);
                assert_se(streq(c_name, names[i]));
                assert_se(streq(c_name, rs_name));

                /* Rust returns a borrowed pointer to process-lifetime storage. */
                assert_se(rs_name == rs_to_string(value));

                assert_se(c_from_string(names[i]) == value);
                assert_se(rs_from_string(names[i]) == value);
        }

        for (int value = -1; value <= _COMPRESSION_MAX; value++)
                if (value < 0 || value >= _COMPRESSION_MAX)
                        assert_se(streq_ptr(c_to_string(value), rs_to_string(value)));

        assert_se(streq_ptr(c_to_string(INT_MIN), rs_to_string(INT_MIN)));
        assert_se(streq_ptr(c_to_string(INT_MAX), rs_to_string(INT_MAX)));

        assert_se(c_from_string("") == rs_from_string(""));
        assert_se(c_from_string("bogus") == rs_from_string("bogus"));
        assert_se(c_from_string(non_utf8) == rs_from_string(non_utf8));
        assert_se(c_from_string(nul_terminated_prefix) == rs_from_string(nul_terminated_prefix));
        assert_se(c_from_string(NULL) == rs_from_string(NULL));
}

static void test_compression_to_string(void) {
        static const char *const names[] = {
                "uncompressed",
                "xz",
                "lz4",
                "zstd",
                "gzip",
                "bzip2",
        };

        assert_string_lookup_matches(
                        compression_to_string,
                        rs_compression_to_string,
                        compression_from_string,
                        rs_compression_from_string,
                        names);
}

static void test_compression_to_string_uppercase(void) {
        static const char *const names[] = {
                "NONE",
                "XZ",
                "LZ4",
                "ZSTD",
                "GZIP",
                "BZIP2",
        };

        assert_string_lookup_matches(
                        compression_uppercase_to_string,
                        rs_compression_uppercase_to_string,
                        compression_uppercase_from_string,
                        rs_compression_uppercase_from_string,
                        names);
}

static void test_compression_supported(void) {
        uint32_t mask = c_compression_supported_mask();

        for (size_t i = 0; i < ELEMENTSOF(compression_values); i++) {
                Compression value = compression_values[i];

                assert_se(compression_supported(value) == rs_compression_supported(value));
                assert_se(rs_compression_supported(value) == !!(mask & (1u << value)));
        }

        /* C asserts for invalid values; the Rust boundary safely rejects them. */
        assert_se(!rs_compression_supported(-1));
        assert_se(!rs_compression_supported(_COMPRESSION_MAX));
        assert_se(!rs_compression_supported(INT_MIN));
        assert_se(!rs_compression_supported(INT_MAX));
}

/* Keep all four table operations as direct C/R calls for static ABI auditing. */
static void test_compression_table_abi_direct_calls(void) {
        assert_se(streq(compression_to_string(COMPRESSION_XZ),
                        rs_compression_to_string(COMPRESSION_XZ)));
        assert_se(streq(compression_uppercase_to_string(COMPRESSION_XZ),
                        rs_compression_uppercase_to_string(COMPRESSION_XZ)));
        assert_se(compression_from_string("xz") == rs_compression_from_string("xz"));
        assert_se(compression_uppercase_from_string("XZ") ==
                  rs_compression_uppercase_from_string("XZ"));
}

int main(int argc, char **argv) {
        test_compression_to_string();
        test_compression_to_string_uppercase();
        test_compression_supported();
        test_compression_table_abi_direct_calls();
        return 0;
}
