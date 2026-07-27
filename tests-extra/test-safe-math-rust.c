/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Shadow test: C macro.h safe math vs Rust */

#include <assert.h>
#include <limits.h>
#include <stdint.h>

#include "rust/safe_math.h"
#include "tests.h"

static void test_u64_multiply_safe(void) {
        assert_se(u64_multiply_safe(0, 0) == rs_u64_multiply_safe(0, 0));
        assert_se(u64_multiply_safe(1, 1) == rs_u64_multiply_safe(1, 1));
        assert_se(u64_multiply_safe(42, 13) == rs_u64_multiply_safe(42, 13));
        assert_se(u64_multiply_safe(UINT64_MAX, 1) == rs_u64_multiply_safe(UINT64_MAX, 1));
        assert_se(u64_multiply_safe(1, UINT64_MAX) == rs_u64_multiply_safe(1, UINT64_MAX));
        assert_se(u64_multiply_safe(UINT64_MAX, UINT64_MAX) == rs_u64_multiply_safe(UINT64_MAX, UINT64_MAX));
        assert_se(u64_multiply_safe(UINT64_MAX, 2) == rs_u64_multiply_safe(UINT64_MAX, 2));
        assert_se(u64_multiply_safe(2, UINT64_MAX) == rs_u64_multiply_safe(2, UINT64_MAX));
        assert_se(u64_multiply_safe(1000000, 1000000) == rs_u64_multiply_safe(1000000, 1000000));
        /* Overflow at exact boundary: UINT64_MAX / 3 * 3 should succeed */
        assert_se(u64_multiply_safe(UINT64_MAX / 3, 3) == rs_u64_multiply_safe(UINT64_MAX / 3, 3));
        /* UINT64_MAX / 3 + 1 * 3 should overflow */
        assert_se(u64_multiply_safe(UINT64_MAX / 3 + 1, 3) == rs_u64_multiply_safe(UINT64_MAX / 3 + 1, 3));
}

static void test_ALIGN_POWER2(void) {
        assert_se(ALIGN_POWER2(0) == rs_ALIGN_POWER2(0));
        assert_se(ALIGN_POWER2(1) == rs_ALIGN_POWER2(1));
        assert_se(ALIGN_POWER2(2) == rs_ALIGN_POWER2(2));
        assert_se(ALIGN_POWER2(3) == rs_ALIGN_POWER2(3));
        assert_se(ALIGN_POWER2(4) == rs_ALIGN_POWER2(4));
        assert_se(ALIGN_POWER2(5) == rs_ALIGN_POWER2(5));
        assert_se(ALIGN_POWER2(7) == rs_ALIGN_POWER2(7));
        assert_se(ALIGN_POWER2(8) == rs_ALIGN_POWER2(8));
        assert_se(ALIGN_POWER2(9) == rs_ALIGN_POWER2(9));
        assert_se(ALIGN_POWER2(15) == rs_ALIGN_POWER2(15));
        assert_se(ALIGN_POWER2(16) == rs_ALIGN_POWER2(16));
        assert_se(ALIGN_POWER2(17) == rs_ALIGN_POWER2(17));
        assert_se(ALIGN_POWER2(1024) == rs_ALIGN_POWER2(1024));
        assert_se(ALIGN_POWER2(1023) == rs_ALIGN_POWER2(1023));
        assert_se(ALIGN_POWER2(ULONG_MAX) == rs_ALIGN_POWER2(ULONG_MAX));
        assert_se(ALIGN_POWER2(ULONG_MAX - 1) == rs_ALIGN_POWER2(ULONG_MAX - 1));
        assert_se(ALIGN_POWER2(ULONG_MAX / 2 + 1) == rs_ALIGN_POWER2(ULONG_MAX / 2 + 1));
}

static void test_size_add(void) {
        assert_se(size_add(0, 0) == rs_size_add(0, 0));
        assert_se(size_add(1, 1) == rs_size_add(1, 1));
        assert_se(size_add(100, 200) == rs_size_add(100, 200));
        assert_se(size_add(SIZE_MAX, 1) == rs_size_add(SIZE_MAX, 1));
        assert_se(size_add(1, SIZE_MAX) == rs_size_add(1, SIZE_MAX));
        assert_se(size_add(SIZE_MAX, SIZE_MAX) == rs_size_add(SIZE_MAX, SIZE_MAX));
        assert_se(size_add(SIZE_MAX / 2, SIZE_MAX / 2) == rs_size_add(SIZE_MAX / 2, SIZE_MAX / 2));
        assert_se(size_add(SIZE_MAX / 2 + 1, SIZE_MAX / 2) == rs_size_add(SIZE_MAX / 2 + 1, SIZE_MAX / 2));
}

int main(int argc, char **argv) {
        test_u64_multiply_safe();
        test_ALIGN_POWER2();
        test_size_add();
        return 0;
}
