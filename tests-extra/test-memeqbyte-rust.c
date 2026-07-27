/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "memory-util.h"
#include "rust/memory_util.h"
#include "tests.h"

TEST(memeqbyte_all_zeros) {
        uint8_t buf[128] = {};
        assert_se(memeqbyte(0, buf, 128));
        assert_se(rs_memeqbyte(0, buf, 128));
}

TEST(memeqbyte_all_0x42) {
        uint8_t buf[64];
        memset(buf, 0x42, sizeof(buf));
        assert_se(memeqbyte(0x42, buf, 64));
        assert_se(rs_memeqbyte(0x42, buf, 64));
}

TEST(memeqbyte_mismatch) {
        uint8_t buf[64];
        memset(buf, 0x42, sizeof(buf));
        buf[63] = 0x43;
        assert_se(!memeqbyte(0x42, buf, 64));
        assert_se(!rs_memeqbyte(0x42, buf, 64));
}

TEST(memeqbyte_zero_length) {
        assert_se(memeqbyte(0, NULL, 0));
        assert_se(rs_memeqbyte(0, NULL, 0));
        assert_se(memeqbyte(0xFF, NULL, 0));
        assert_se(rs_memeqbyte(0xFF, NULL, 0));
}

TEST(memeqbyte_short) {
        uint8_t buf[3] = {0xAB, 0xAB, 0xAB};
        assert_se(memeqbyte(0xAB, buf, 3));
        assert_se(rs_memeqbyte(0xAB, buf, 3));
        assert_se(!memeqbyte(0xCD, buf, 3));
        assert_se(!rs_memeqbyte(0xCD, buf, 3));
}

TEST(memeqbyte_c_vs_rust) {
        /* Test various sizes including boundary at 16 bytes */
        for (size_t len = 0; len <= 256; len++) {
                uint8_t buf[256];
                memset(buf, 0x55, len);

                bool cr = memeqbyte(0x55, len > 0 ? buf : NULL, len);
                bool rr = rs_memeqbyte(0x55, len > 0 ? buf : NULL, len);
                assert_se(cr == rr);

                if (len > 0) {
                        bool cr2 = memeqbyte(0xAA, buf, len);
                        bool rr2 = rs_memeqbyte(0xAA, buf, len);
                        assert_se(cr2 == rr2);
                }
        }
}

DEFINE_TEST_MAIN(LOG_INFO);
