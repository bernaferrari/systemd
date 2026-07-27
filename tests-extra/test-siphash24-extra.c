/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "siphash24.h"
#include "tests.h"

TEST(siphash24_string) {
        uint8_t key[16] = {};
        uint64_t h = siphash24_string("test", key);
        /* Same input should produce same hash */
        ASSERT_EQ(siphash24_string("test", key), h);
        /* Different input should (very likely) produce different hash */
        ASSERT_NE(siphash24_string("test", key), siphash24_string("other", key));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
