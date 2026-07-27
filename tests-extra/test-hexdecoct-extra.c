/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "hexdecoct.h"
#include "tests.h"

TEST(hexchar) {
        ASSERT_EQ(hexchar(0), '0');
        ASSERT_EQ(hexchar(9), '9');
        ASSERT_EQ(hexchar(10), 'a');
        ASSERT_EQ(hexchar(15), 'f');
}

TEST(unhexchar) {
        ASSERT_EQ(unhexchar('0'), 0);
        ASSERT_EQ(unhexchar('9'), 9);
        ASSERT_EQ(unhexchar('a'), 10);
        ASSERT_EQ(unhexchar('f'), 15);
        ASSERT_EQ(unhexchar('A'), 10);
        ASSERT_EQ(unhexchar('F'), 15);
        ASSERT_EQ(unhexchar('g'), -EINVAL);
}

TEST(octchar) {
        ASSERT_EQ(octchar(0), '0');
        ASSERT_EQ(octchar(7), '7');
}

TEST(unoctchar) {
        ASSERT_EQ(unoctchar('0'), 0);
        ASSERT_EQ(unoctchar('7'), 7);
        ASSERT_EQ(unoctchar('8'), -EINVAL);
}

TEST(decchar) {
        ASSERT_EQ(decchar(0), '0');
        ASSERT_EQ(decchar(9), '9');
}

TEST(undecchar) {
        ASSERT_EQ(undecchar('0'), 0);
        ASSERT_EQ(undecchar('9'), 9);
        ASSERT_EQ(undecchar('a'), -EINVAL);
}

TEST(base64mem) {
        _cleanup_free_ char *encoded = NULL;

        ASSERT_OK(base64mem("Hello, world!", 13, &encoded));
        ASSERT_STREQ(encoded, "SGVsbG8sIHdvcmxkIQ==");

        encoded = mfree(encoded);
        ASSERT_OK(base64mem("", 0, &encoded));
        ASSERT_STREQ(encoded, "");
}

TEST(unbase64mem) {
        _cleanup_free_ void *decoded = NULL;
        size_t len = 0;

        ASSERT_OK(unbase64mem("SGVsbG8sIHdvcmxkIQ==", &decoded, &len));
        ASSERT_EQ(len, 13);
        ASSERT_STREQ((char*)decoded, "Hello, world!");
}

TEST(hexmem) {
        _cleanup_free_ char *h = NULL;

        h = hexmem("AB", 2);
        ASSERT_NOT_NULL(h);
        ASSERT_STREQ(h, "4142");

        h = mfree(h);
        h = hexmem("", 0);
        ASSERT_NOT_NULL(h);
        ASSERT_STREQ(h, "");
}

TEST(unhexmem) {
        _cleanup_free_ void *buf = NULL;
        size_t len = 0;

        ASSERT_OK(unhexmem("4142", &buf, &len));
        ASSERT_EQ(len, 2);
        ASSERT_EQ(((char*)buf)[0], 'A');
        ASSERT_EQ(((char*)buf)[1], 'B');
}

DEFINE_TEST_MAIN(LOG_DEBUG);
