/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "hexdecoct.h"
#include "tests.h"

TEST(hexchar_unhexchar_roundtrip) {
        for (int i = 0; i < 16; i++) {
                char c = hexchar(i);
                assert_se(unhexchar(c) == i);
        }
        assert_se(hexchar(0) == '0');
        assert_se(hexchar(9) == '9');
        assert_se(hexchar(10) == 'a');
        assert_se(hexchar(15) == 'f');
        assert_se(unhexchar('0') == 0);
        assert_se(unhexchar('9') == 9);
        assert_se(unhexchar('a') == 10);
        assert_se(unhexchar('f') == 15);
        assert_se(unhexchar('A') == 10);
        assert_se(unhexchar('F') == 15);
        assert_se(unhexchar('x') < 0);
}

TEST(decchar_undecchar_roundtrip) {
        for (int i = 0; i < 10; i++) {
                char c = decchar(i);
                assert_se(undecchar(c) == i);
        }
        assert_se(decchar(0) == '0');
        assert_se(decchar(9) == '9');
        assert_se(undecchar('0') == 0);
        assert_se(undecchar('9') == 9);
        assert_se(undecchar('a') < 0);
}

TEST(octchar_unoctchar_roundtrip) {
        for (int i = 0; i < 8; i++) {
                char c = octchar(i);
                assert_se(unoctchar(c) == i);
        }
        assert_se(octchar(0) == '0');
        assert_se(octchar(7) == '7');
        assert_se(unoctchar('0') == 0);
        assert_se(unoctchar('7') == 7);
        assert_se(unoctchar('8') < 0);
        assert_se(unoctchar('a') < 0);
}

TEST(urlsafe_base64char) {
        assert_se(urlsafe_base64char(62) == '-');
        assert_se(urlsafe_base64char(63) == '_');
        /* standard base64 has + and / at positions 62,63 */
        assert_se(base64char(62) == '+');
        assert_se(base64char(63) == '/');
}

TEST(hexmem_unhexmem_roundtrip) {
        const char *input = "Hello, systemd!";
        size_t input_len = strlen(input);

        _cleanup_free_ char *hex = hexmem(input, input_len);
        assert_se(hex);
        assert_se(streq(hex, "48656c6c6f2c2073797374656d6421"));

        _cleanup_free_ void *bin = NULL;
        size_t bin_size = 0;
        assert_se(unhexmem(hex, &bin, &bin_size) >= 0);
        assert_se(bin_size == input_len);
        assert_se(memcmp(bin, input, input_len) == 0);
}

TEST(base64mem_unbase64mem_roundtrip) {
        const char *input = "systemd test data";
        size_t input_len = strlen(input);

        _cleanup_free_ char *b64 = NULL;
        assert_se(base64mem(input, input_len, &b64) >= 0);
        assert_se(b64);

        _cleanup_free_ void *decoded = NULL;
        size_t decoded_size = 0;
        assert_se(unbase64mem(b64, &decoded, &decoded_size) >= 0);
        assert_se(decoded_size == input_len);
        assert_se(memcmp(decoded, input, input_len) == 0);
}

TEST(hexmem_empty) {
        _cleanup_free_ char *hex = hexmem("", 0);
        assert_se(hex);
        assert_se(streq(hex, ""));

        _cleanup_free_ void *bin = NULL;
        size_t bin_size = 0;
        assert_se(unhexmem("", &bin, &bin_size) >= 0);
        assert_se(bin_size == 0);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
