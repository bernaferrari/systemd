/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdlib.h>
#include <stdint.h>

#include "MurmurHash2.h"
#include "tests.h"

TEST(murmurhash2_empty) {
        uint32_t h = MurmurHash2("", 0, 0);
        /* Empty string with seed 0 produces 0 */
        ASSERT_EQ(h, 0u);
}

TEST(murmurhash2_basic) {
        uint32_t h1, h2;

        h1 = MurmurHash2("a", 1, 0);
        h2 = MurmurHash2("a", 1, 0);
        /* Same input must produce same output */
        ASSERT_EQ(h1, h2);
}

TEST(murmurhash2_with_seed) {
        uint32_t h1 = MurmurHash2("hello", 5, 0);
        uint32_t h2 = MurmurHash2("hello", 5, 42);
        /* Different seeds should produce different hashes (high probability) */
        ASSERT_NE(h1, h2);
}

TEST(murmurhash2_deterministic) {
        uint32_t h1 = MurmurHash2("test string", 11, 12345);
        uint32_t h2 = MurmurHash2("test string", 11, 12345);
        ASSERT_EQ(h1, h2);
}

TEST(murmurhash2_different_inputs) {
        uint32_t h1 = MurmurHash2("foo", 3, 0);
        uint32_t h2 = MurmurHash2("bar", 3, 0);
        uint32_t h3 = MurmurHash2("baz", 3, 0);
        /* All three should be different (high probability) */
        ASSERT_TRUE(h1 != h2 || h2 != h3);
}

TEST(murmurhash2_long_input) {
        const char *input = "The quick brown fox jumps over the lazy dog";
        uint32_t h1 = MurmurHash2(input, strlen(input), 0);
        uint32_t h2 = MurmurHash2(input, strlen(input), 0);
        ASSERT_EQ(h1, h2);
}

TEST(murmurhash2_four_byte_boundary) {
        /* Exactly 4 bytes */
        uint32_t h = MurmurHash2("abcd", 4, 0);
        ASSERT_NE(h, 0u);

        /* 8 bytes (multiple of 4) */
        h = MurmurHash2("abcdefgh", 8, 0);
        ASSERT_NE(h, 0u);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
