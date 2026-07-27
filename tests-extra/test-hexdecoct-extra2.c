/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "hexdecoct.h"
#include "tests.h"

TEST(base32hexchar) {
        ASSERT_EQ(base32hexchar(0), '0');
        ASSERT_EQ(base32hexchar(9), '9');
        ASSERT_EQ(base32hexchar(10), 'A');
        ASSERT_EQ(base32hexchar(15), 'F');
        ASSERT_EQ(base32hexchar(31), 'V');
}

TEST(unbase32hexchar) {
        ASSERT_EQ(unbase32hexchar('0'), 0);
        ASSERT_EQ(unbase32hexchar('9'), 9);
        ASSERT_EQ(unbase32hexchar('A'), 10);
        ASSERT_EQ(unbase32hexchar('V'), 31);
        /* base32hex only uses 0-9, A-V; W-Z and lowercase are invalid */
        ASSERT_EQ(unbase32hexchar('W'), -EINVAL);
        ASSERT_EQ(unbase32hexchar('a'), -EINVAL);
        ASSERT_EQ(unbase32hexchar(' '), -EINVAL);
}

TEST(base64char) {
        ASSERT_EQ(base64char(0), 'A');
        ASSERT_EQ(base64char(25), 'Z');
        ASSERT_EQ(base64char(26), 'a');
        ASSERT_EQ(base64char(51), 'z');
        ASSERT_EQ(base64char(52), '0');
        ASSERT_EQ(base64char(61), '9');
        ASSERT_EQ(base64char(62), '+');
        ASSERT_EQ(base64char(63), '/');
}

TEST(unbase64char) {
        ASSERT_EQ(unbase64char('A'), 0);
        ASSERT_EQ(unbase64char('Z'), 25);
        ASSERT_EQ(unbase64char('a'), 26);
        ASSERT_EQ(unbase64char('z'), 51);
        ASSERT_EQ(unbase64char('0'), 52);
        ASSERT_EQ(unbase64char('9'), 61);
        ASSERT_EQ(unbase64char('+'), 62);
        ASSERT_EQ(unbase64char('/'), 63);
        ASSERT_EQ(unbase64char(' '), -EINVAL);
}

TEST(base32hexmem) {
        _cleanup_free_ char *encoded = NULL;
        /* base32hexmem returns char* directly (3 args: data, len, padding) */
        encoded = base32hexmem("", 0, false);
        ASSERT_NOT_NULL(encoded);
        ASSERT_STREQ(encoded, "");
        encoded = mfree(encoded);
        /* Simple test */
        encoded = base32hexmem("A", 1, false);
        ASSERT_NOT_NULL(encoded);
        ASSERT_EQ(strlen(encoded), 2u); /* 1 byte = 2 base32hex chars */
        encoded = mfree(encoded);
}

TEST(unbase32hexmem) {
        _cleanup_free_ void *decoded = NULL;
        size_t len = 0;
        /* unbase32hexmem takes (p, l, padding, mem, len) */
        ASSERT_OK(unbase32hexmem("00", 2, false, &decoded, &len));
        ASSERT_EQ(len, 1u);
        ASSERT_EQ(*(uint8_t*)decoded, 0);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
