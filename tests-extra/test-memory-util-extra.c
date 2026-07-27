/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <string.h>

#include "memory-util.h"
#include "tests.h"

TEST(memcmp_safe_basic) {
        const char a[] = "hello";
        const char b[] = "hello";
        const char c[] = "world";

        assert_se(memcmp_safe(a, b, 5) == 0);
        assert_se(memcmp_safe(a, c, 5) < 0);
        assert_se(memcmp_safe(c, a, 5) > 0);
        /* n == 0 → returns 0 */
        assert_se(memcmp_safe(a, c, 0) == 0);
}

TEST(memcmp_nn_basic) {
        /* Same content, same length → 0 */
        assert_se(memcmp_nn("abc", 3, "abc", 3) == 0);
        /* Same prefix, different length: shorter < longer */
        assert_se(memcmp_nn("ab", 2, "abc", 3) < 0);
        assert_se(memcmp_nn("abc", 3, "ab", 2) > 0);
        /* Different content */
        assert_se(memcmp_nn("aaa", 3, "bbb", 3) < 0);
        /* Both zero length → CMP(0,0) == 0 */
        assert_se(memcmp_nn("x", 0, "y", 0) == 0);
}

TEST(memmem_safe_basic) {
        const char haystack[] = "hello world";

        assert_se(memmem_safe(haystack, 11, "world", 5) == haystack + 6);
        assert_se(memmem_safe(haystack, 11, "hello", 5) == haystack);
        assert_se(memmem_safe(haystack, 11, "xyz", 3) == NULL);
        /* needlelen == 0 → returns haystack */
        assert_se(memmem_safe(haystack, 11, "x", 0) == (void*) haystack);
        /* haystack smaller than needle → NULL */
        assert_se(memmem_safe(haystack, 5, "world", 5) == NULL);
}

TEST(mempmem_safe_basic) {
        const char haystack[] = "hello world";

        /* Returns pointer PAST the found needle */
        void *p = mempmem_safe(haystack, 11, "hello", 5);
        assert_se(p == haystack + 5);
        assert_se(memcmp_safe(p, " world", 6) == 0);

        /* Not found → NULL */
        assert_se(mempmem_safe(haystack, 11, "xyz", 3) == NULL);
}

TEST(mempset_basic) {
        uint8_t buf[8];
        void *p = mempset(buf, 0xAA, 4);
        assert_se(p == buf + 4);
        assert_se(buf[0] == 0xAA);
        assert_se(buf[3] == 0xAA);
        assert_se(buf[4] != 0xAA);  /* not touched */
}

TEST(memcpy_safe_basic) {
        const char src[] = "test";
        char dst[8] = {0};

        assert_se(memcpy_safe(dst, src, 4) == dst);
        assert_se(memcmp(dst, "test", 4) == 0);

        /* n == 0 → returns dst, no crash */
        char x = 0;
        assert_se(memcpy_safe(&x, NULL, 0) == &x);
}

TEST(size_multiply_overflow_basic) {
        assert_se(!size_multiply_overflow(10, 20));
        assert_se(!size_multiply_overflow(1, SIZE_MAX));
        assert_se(size_multiply_overflow(2, SIZE_MAX));
        assert_se(size_multiply_overflow(SIZE_MAX, 2));
        assert_se(!size_multiply_overflow(10, 0));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
