/* SPDX-License-Identifier: LGPL-2.1-or-later */

/* Shadow test for the reviewed, allocation-free scalar character codecs. */
/* RUST-CONTRACT: hexdecoct-scalar-encoders */
/* RUST-CONTRACT: hexdecoct-scalar-decoders */

#include <limits.h>

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

DEFINE_TEST_MAIN(LOG_INFO);
