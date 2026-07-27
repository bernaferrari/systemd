/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "random-util.h"
#include "tests.h"

TEST(random_bytes_basic) {
        uint8_t buf[32] = {};
        random_bytes(buf, sizeof(buf));
        /* Verify not all zeros (extremely unlikely) */
        bool all_zero = true;
        for (size_t i = 0; i < sizeof(buf); i++)
                if (buf[i] != 0) all_zero = false;
        assert_se(!all_zero);
}

TEST(random_bytes_zero) {
        /* Zero-length should be safe */
        random_bytes(NULL, 0);
}

TEST(random_u64_basic) {
        uint64_t v = random_u64();
        assert_se(v != 0 || random_u64() != 0); /* extremely unlikely both are 0 */
        log_debug("random_u64: %" PRIu64, v);
}

TEST(random_u32_basic) {
        uint32_t v = random_u32();
        log_debug("random_u32: %" PRIu32, v);
}

TEST(random_pool_size_basic) {
        size_t s = random_pool_size();
        assert_se(s > 0);
        log_debug("random_pool_size: %zu", s);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
