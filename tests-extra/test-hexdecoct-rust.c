/* SPDX-License-Identifier: LGPL-2.1-or-later */

/* Shadow test for reviewed scalar and libc-allocation codec boundaries. */
/* RUST-CONTRACT: hexdecoct-scalar-encoders */
/* RUST-CONTRACT: hexdecoct-scalar-decoders */
/* RUST-CONTRACT: hexdecoct-hexmem */
/* RUST-CONTRACT: hexdecoct-base32 */
/* RUST-CONTRACT: hexdecoct-base64 */
/* RUST-CONTRACT: hexdecoct-base64-append */

#include <limits.h>
#include <stdlib.h>
#include <string.h>

#include "hexdecoct.h"
#include "rust/hexdecoct.h"
#include "tests.h"

TEST(octchar_c_vs_rs) {
        for (int i = 0; i < 8; i++)
                ASSERT_EQ(octchar(i), rs_octchar(i));

        ASSERT_EQ(octchar(8), rs_octchar(8));
        ASSERT_EQ(octchar(15), rs_octchar(15));
        ASSERT_EQ(octchar(-1), rs_octchar(-1));
        ASSERT_EQ(octchar(255), rs_octchar(255));
        ASSERT_EQ(octchar(INT_MIN), rs_octchar(INT_MIN));
        ASSERT_EQ(octchar(INT_MAX), rs_octchar(INT_MAX));
}

TEST(unoctchar_c_vs_rs) {
        for (unsigned i = 0; i <= UCHAR_MAX; i++) {
                char c = (char) i;
                ASSERT_EQ(unoctchar(c), rs_unoctchar(c));
        }
}

TEST(decchar_c_vs_rs) {
        for (int i = 0; i < 10; i++)
                ASSERT_EQ(decchar(i), rs_decchar(i));

        ASSERT_EQ(decchar(10), rs_decchar(10));
        ASSERT_EQ(decchar(-1), rs_decchar(-1));
        ASSERT_EQ(decchar(INT_MIN), rs_decchar(INT_MIN));
        ASSERT_EQ(decchar(INT_MAX), rs_decchar(INT_MAX));
}

TEST(undecchar_c_vs_rs) {
        for (unsigned i = 0; i <= UCHAR_MAX; i++) {
                char c = (char) i;
                ASSERT_EQ(undecchar(c), rs_undecchar(c));
        }
}

TEST(hexchar_c_vs_rs) {
        for (int i = 0; i < 16; i++)
                ASSERT_EQ(hexchar(i), rs_hexchar(i));

        ASSERT_EQ(hexchar(16), rs_hexchar(16));
        ASSERT_EQ(hexchar(31), rs_hexchar(31));
        ASSERT_EQ(hexchar(-1), rs_hexchar(-1));
        ASSERT_EQ(hexchar(255), rs_hexchar(255));
        ASSERT_EQ(hexchar(INT_MIN), rs_hexchar(INT_MIN));
        ASSERT_EQ(hexchar(INT_MAX), rs_hexchar(INT_MAX));
}

TEST(unhexchar_c_vs_rs) {
        for (unsigned i = 0; i <= UCHAR_MAX; i++) {
                char c = (char) i;
                ASSERT_EQ(unhexchar(c), rs_unhexchar(c));
        }
}

TEST(base32hexchar_c_vs_rs) {
        for (int i = 0; i < 32; i++)
                ASSERT_EQ(base32hexchar(i), rs_base32hexchar(i));

        ASSERT_EQ(base32hexchar(32), rs_base32hexchar(32));
        ASSERT_EQ(base32hexchar(255), rs_base32hexchar(255));
        ASSERT_EQ(base32hexchar(-1), rs_base32hexchar(-1));
        ASSERT_EQ(base32hexchar(INT_MIN), rs_base32hexchar(INT_MIN));
        ASSERT_EQ(base32hexchar(INT_MAX), rs_base32hexchar(INT_MAX));
}

TEST(unbase32hexchar_c_vs_rs) {
        for (unsigned i = 0; i <= UCHAR_MAX; i++) {
                char c = (char) i;
                ASSERT_EQ(unbase32hexchar(c), rs_unbase32hexchar(c));
        }
}

TEST(base64char_c_vs_rs) {
        for (int i = 0; i < 64; i++)
                ASSERT_EQ(base64char(i), rs_base64char(i));

        ASSERT_EQ(base64char(64), rs_base64char(64));
        ASSERT_EQ(base64char(-1), rs_base64char(-1));
        ASSERT_EQ(base64char(INT_MIN), rs_base64char(INT_MIN));
        ASSERT_EQ(base64char(INT_MAX), rs_base64char(INT_MAX));
}

TEST(urlsafe_base64char_c_vs_rs) {
        for (int i = 0; i < 64; i++)
                ASSERT_EQ(urlsafe_base64char(i), rs_urlsafe_base64char(i));

        ASSERT_EQ(urlsafe_base64char(64), rs_urlsafe_base64char(64));
        ASSERT_EQ(urlsafe_base64char(-1), rs_urlsafe_base64char(-1));
        ASSERT_EQ(urlsafe_base64char(INT_MIN), rs_urlsafe_base64char(INT_MIN));
        ASSERT_EQ(urlsafe_base64char(INT_MAX), rs_urlsafe_base64char(INT_MAX));
}

TEST(unbase64char_c_vs_rs) {
        for (unsigned i = 0; i <= UCHAR_MAX; i++) {
                char c = (char) i;
                ASSERT_EQ(unbase64char(c), rs_unbase64char(c));
        }
}

TEST(hexmem_full_c_vs_rs) {
        static const uint8_t input[] = { 0, 1, 0xfe, 0xff };
        _cleanup_free_ char *c_encoded = hexmem(input, sizeof(input));
        _cleanup_free_ char *rs_encoded = rs_hexmem(input, sizeof(input));
        _cleanup_free_ void *c_decoded = NULL;
        _cleanup_free_ void *rs_decoded = NULL;
        size_t c_size = SIZE_MAX, rs_size = SIZE_MAX;

        ASSERT_NOT_NULL(c_encoded);
        ASSERT_NOT_NULL(rs_encoded);
        ASSERT_STREQ(c_encoded, rs_encoded);

        ASSERT_EQ(unhexmem_full("00 01\nfeff", 10, true, &c_decoded, &c_size),
                  rs_unhexmem_full("00 01\nfeff", 10, true, &rs_decoded, &rs_size));
        ASSERT_EQ(c_size, rs_size);
        ASSERT_EQ(memcmp(c_decoded, rs_decoded, c_size), 0);
}

TEST(base32hexmem_c_vs_rs) {
        static const uint8_t input[] = { 'f', 'o', 'o', 0, 0xff };
        _cleanup_free_ char *c_encoded = NULL;
        _cleanup_free_ char *rs_encoded = NULL;
        _cleanup_free_ void *c_decoded = NULL;
        _cleanup_free_ void *rs_decoded = NULL;
        size_t c_size = SIZE_MAX, rs_size = SIZE_MAX;

        for (unsigned pad = 0; pad < 2; pad++) {
                bool padding = pad != 0;

                free(c_encoded);
                c_encoded = NULL;
                free(rs_encoded);
                rs_encoded = NULL;
                c_encoded = base32hexmem(input, sizeof(input), padding);
                rs_encoded = rs_base32hexmem(input, sizeof(input), padding);
                ASSERT_NOT_NULL(c_encoded);
                ASSERT_NOT_NULL(rs_encoded);
                ASSERT_STREQ(c_encoded, rs_encoded);

                free(c_decoded);
                c_decoded = NULL;
                free(rs_decoded);
                rs_decoded = NULL;
                ASSERT_EQ(unbase32hexmem(c_encoded, strlen(c_encoded), padding, &c_decoded, &c_size),
                          rs_unbase32hexmem(c_encoded, strlen(c_encoded), padding, &rs_decoded, &rs_size));
                ASSERT_EQ(c_size, rs_size);
                ASSERT_EQ(memcmp(c_decoded, rs_decoded, c_size), 0);
        }
}

TEST(base64mem_full_c_vs_rs) {
        static const uint8_t input[] = { 'a', 'b', 'c', 'd', 'e', 'f', 'g' };
        _cleanup_free_ char *c_encoded = NULL;
        _cleanup_free_ char *rs_encoded = NULL;
        _cleanup_free_ void *c_decoded = NULL;
        _cleanup_free_ void *rs_decoded = NULL;
        size_t c_size = SIZE_MAX, rs_size = SIZE_MAX;

        ASSERT_EQ(base64mem_full(input, sizeof(input), 4, &c_encoded),
                  rs_base64mem_full(input, sizeof(input), 4, &rs_encoded));
        ASSERT_NOT_NULL(c_encoded);
        ASSERT_NOT_NULL(rs_encoded);
        ASSERT_STREQ(c_encoded, rs_encoded);

        ASSERT_EQ(unbase64mem_full(c_encoded, strlen(c_encoded), true, &c_decoded, &c_size),
                  rs_unbase64mem_full(c_encoded, strlen(c_encoded), true, &rs_decoded, &rs_size));
        ASSERT_EQ(c_size, rs_size);
        ASSERT_EQ(memcmp(c_decoded, rs_decoded, c_size), 0);
}

TEST(base64_append_c_vs_rs) {
        static const uint8_t input[] = { 'a', 'b', 'c', 'd', 'e', 'f', 'g' };
        _cleanup_free_ char *c_prefix = strdup("old");
        _cleanup_free_ char *rs_prefix = strdup("old");

        ASSERT_NOT_NULL(c_prefix);
        ASSERT_NOT_NULL(rs_prefix);
        ASSERT_EQ(base64_append(&c_prefix, 3, input, sizeof(input), 2, 8),
                  rs_base64_append(&rs_prefix, 3, input, sizeof(input), 2, 8));
        ASSERT_STREQ(c_prefix, rs_prefix);
}

DEFINE_TEST_MAIN(LOG_INFO);
