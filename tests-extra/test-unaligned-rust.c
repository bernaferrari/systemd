/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Shadow test: C unaligned read/write vs Rust */

#include <assert.h>
#include <string.h>
#include <stdint.h>
#include "tests.h"
#include "unaligned.h"
#include "rust/unaligned.h"

#define TEST_MISALIGNED_READ_WRITE(suffix, type, value, ...) do {               \
        const uint8_t expected[sizeof(type)] = { __VA_ARGS__ };                  \
        for (size_t offset = 1; offset < sizeof(type); offset++) {               \
                uint64_t c_storage[3], rust_storage[3];                          \
                uint8_t *c_bytes = (uint8_t*) c_storage;                         \
                uint8_t *rust_bytes = (uint8_t*) rust_storage;                   \
                                                                                \
                memset(c_bytes, 0xa5, sizeof(c_storage));                        \
                memset(rust_bytes, 0x5a, sizeof(rust_storage));                  \
                unaligned_write_##suffix(c_bytes + offset, (type) (value));      \
                rs_unaligned_write_##suffix(rust_bytes + offset, (type) (value));\
                                                                                \
                assert_se(memcmp(c_bytes + offset, expected, sizeof(expected)) == 0); \
                assert_se(memcmp(rust_bytes + offset, expected, sizeof(expected)) == 0); \
                assert_se(memcmp(c_bytes + offset,                               \
                                 rust_bytes + offset, sizeof(type)) == 0);        \
                assert_se(unaligned_read_##suffix(c_bytes + offset) == (type) (value)); \
                assert_se(rs_unaligned_read_##suffix(rust_bytes + offset) == (type) (value)); \
                assert_se(c_bytes[offset - 1] == 0xa5);                          \
                assert_se(rust_bytes[offset - 1] == 0x5a);                       \
                assert_se(c_bytes[offset + sizeof(type)] == 0xa5);               \
                assert_se(rust_bytes[offset + sizeof(type)] == 0x5a);            \
        }                                                                        \
} while (false)

static void test_unaligned_be16(void) {
        uint8_t buf[2] = {0x12, 0x34};
        uint16_t cr, rr;

        cr = unaligned_read_be16(buf);
        rr = rs_unaligned_read_be16(buf);
        assert_se(cr == rr && cr == 0x1234);

        /* Write and read back */
        unaligned_write_be16(buf, 0xABCD);
        cr = unaligned_read_be16(buf);
        rs_unaligned_write_be16(buf, 0xABCD);
        rr = rs_unaligned_read_be16(buf);
        assert_se(cr == rr);

        /* Zero */
        unaligned_write_be16(buf, 0);
        cr = unaligned_read_be16(buf);
        rs_unaligned_write_be16(buf, 0);
        rr = rs_unaligned_read_be16(buf);
        assert_se(cr == rr && cr == 0);

        /* Max value */
        unaligned_write_be16(buf, 0xFFFF);
        cr = unaligned_read_be16(buf);
        rs_unaligned_write_be16(buf, 0xFFFF);
        rr = rs_unaligned_read_be16(buf);
        assert_se(cr == rr && cr == 0xFFFF);
}

static void test_unaligned_be32(void) {
        uint8_t buf[4] = {0x12, 0x34, 0x56, 0x78};
        uint32_t cr, rr;

        cr = unaligned_read_be32(buf);
        rr = rs_unaligned_read_be32(buf);
        assert_se(cr == rr && cr == 0x12345678);

        unaligned_write_be32(buf, 0xDEADBEEF);
        cr = unaligned_read_be32(buf);
        rs_unaligned_write_be32(buf, 0xDEADBEEF);
        rr = rs_unaligned_read_be32(buf);
        assert_se(cr == rr);

        unaligned_write_be32(buf, 0);
        cr = unaligned_read_be32(buf);
        rs_unaligned_write_be32(buf, 0);
        rr = rs_unaligned_read_be32(buf);
        assert_se(cr == rr && cr == 0);

        unaligned_write_be32(buf, 0xFFFFFFFF);
        cr = unaligned_read_be32(buf);
        rs_unaligned_write_be32(buf, 0xFFFFFFFF);
        rr = rs_unaligned_read_be32(buf);
        assert_se(cr == rr && cr == 0xFFFFFFFF);
}

static void test_unaligned_be64(void) {
        uint8_t buf[8] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF};
        uint64_t cr, rr;

        cr = unaligned_read_be64(buf);
        rr = rs_unaligned_read_be64(buf);
        assert_se(cr == rr && cr == 0x0123456789ABCDEFULL);

        unaligned_write_be64(buf, 0xCAFEBABEDEADC0DEULL);
        cr = unaligned_read_be64(buf);
        rs_unaligned_write_be64(buf, 0xCAFEBABEDEADC0DEULL);
        rr = rs_unaligned_read_be64(buf);
        assert_se(cr == rr);

        unaligned_write_be64(buf, 0);
        cr = unaligned_read_be64(buf);
        rs_unaligned_write_be64(buf, 0);
        rr = rs_unaligned_read_be64(buf);
        assert_se(cr == rr && cr == 0);

        unaligned_write_be64(buf, 0xFFFFFFFFFFFFFFFFULL);
        cr = unaligned_read_be64(buf);
        rs_unaligned_write_be64(buf, 0xFFFFFFFFFFFFFFFFULL);
        rr = rs_unaligned_read_be64(buf);
        assert_se(cr == rr && cr == 0xFFFFFFFFFFFFFFFFULL);
}

static void test_unaligned_le16(void) {
        uint8_t buf[2] = {0x34, 0x12};
        uint16_t cr, rr;

        cr = unaligned_read_le16(buf);
        rr = rs_unaligned_read_le16(buf);
        assert_se(cr == rr && cr == 0x1234);

        unaligned_write_le16(buf, 0xABCD);
        cr = unaligned_read_le16(buf);
        rs_unaligned_write_le16(buf, 0xABCD);
        rr = rs_unaligned_read_le16(buf);
        assert_se(cr == rr);

        unaligned_write_le16(buf, 0);
        cr = unaligned_read_le16(buf);
        rs_unaligned_write_le16(buf, 0);
        rr = rs_unaligned_read_le16(buf);
        assert_se(cr == rr && cr == 0);

        unaligned_write_le16(buf, 0xFFFF);
        cr = unaligned_read_le16(buf);
        rs_unaligned_write_le16(buf, 0xFFFF);
        rr = rs_unaligned_read_le16(buf);
        assert_se(cr == rr && cr == 0xFFFF);
}

static void test_unaligned_le32(void) {
        uint8_t buf[4] = {0x78, 0x56, 0x34, 0x12};
        uint32_t cr, rr;

        cr = unaligned_read_le32(buf);
        rr = rs_unaligned_read_le32(buf);
        assert_se(cr == rr && cr == 0x12345678);

        unaligned_write_le32(buf, 0xDEADBEEF);
        cr = unaligned_read_le32(buf);
        rs_unaligned_write_le32(buf, 0xDEADBEEF);
        rr = rs_unaligned_read_le32(buf);
        assert_se(cr == rr);

        unaligned_write_le32(buf, 0);
        cr = unaligned_read_le32(buf);
        rs_unaligned_write_le32(buf, 0);
        rr = rs_unaligned_read_le32(buf);
        assert_se(cr == rr && cr == 0);

        unaligned_write_le32(buf, 0xFFFFFFFF);
        cr = unaligned_read_le32(buf);
        rs_unaligned_write_le32(buf, 0xFFFFFFFF);
        rr = rs_unaligned_read_le32(buf);
        assert_se(cr == rr && cr == 0xFFFFFFFF);
}

static void test_unaligned_le64(void) {
        uint8_t buf[8] = {0xEF, 0xCD, 0xAB, 0x89, 0x67, 0x45, 0x23, 0x01};
        uint64_t cr, rr;

        cr = unaligned_read_le64(buf);
        rr = rs_unaligned_read_le64(buf);
        assert_se(cr == rr && cr == 0x0123456789ABCDEFULL);

        unaligned_write_le64(buf, 0xCAFEBABEDEADC0DEULL);
        cr = unaligned_read_le64(buf);
        rs_unaligned_write_le64(buf, 0xCAFEBABEDEADC0DEULL);
        rr = rs_unaligned_read_le64(buf);
        assert_se(cr == rr);

        unaligned_write_le64(buf, 0);
        cr = unaligned_read_le64(buf);
        rs_unaligned_write_le64(buf, 0);
        rr = rs_unaligned_read_le64(buf);
        assert_se(cr == rr && cr == 0);

        unaligned_write_le64(buf, 0xFFFFFFFFFFFFFFFFULL);
        cr = unaligned_read_le64(buf);
        rs_unaligned_write_le64(buf, 0xFFFFFFFFFFFFFFFFULL);
        rr = rs_unaligned_read_le64(buf);
        assert_se(cr == rr && cr == 0xFFFFFFFFFFFFFFFFULL);
}

static void test_misaligned_independent_buffers(void) {
        TEST_MISALIGNED_READ_WRITE(be16, uint16_t, UINT16_C(0x1234), 0x12, 0x34);
        TEST_MISALIGNED_READ_WRITE(be32, uint32_t, UINT32_C(0x12345678), 0x12, 0x34, 0x56, 0x78);
        TEST_MISALIGNED_READ_WRITE(be64, uint64_t, UINT64_C(0x0123456789abcdef),
                                   0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef);
        TEST_MISALIGNED_READ_WRITE(le16, uint16_t, UINT16_C(0x1234), 0x34, 0x12);
        TEST_MISALIGNED_READ_WRITE(le32, uint32_t, UINT32_C(0x12345678), 0x78, 0x56, 0x34, 0x12);
        TEST_MISALIGNED_READ_WRITE(le64, uint64_t, UINT64_C(0x0123456789abcdef),
                                   0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01);
}

int main(int argc, char **argv) {
        test_unaligned_be16();
        test_unaligned_be32();
        test_unaligned_be64();
        test_unaligned_le16();
        test_unaligned_le32();
        test_unaligned_le64();
        test_misaligned_independent_buffers();
        return 0;
}
