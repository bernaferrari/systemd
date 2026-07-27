/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Shadow test: C convert_meminfo_value_to_uint64_bytes vs Rust */

#include <assert.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include "tests.h"
#include "procfs-util.h"
#include "rust/procfs_util.h"

/* -- convert_meminfo_value_to_uint64_bytes ---------------------------------- */

static void test_convert_meminfo_value_to_uint64_bytes(void) {
        uint64_t cr, rr;
        int c_ret, r_ret;

        /* Valid: 0 kB → 0 */
        c_ret = convert_meminfo_value_to_uint64_bytes("0 kB", &cr);
        r_ret = rs_convert_meminfo_value_to_uint64_bytes("0 kB", &rr);
        assert_se(c_ret == r_ret);
        assert_se(c_ret == 0);
        assert_se(cr == rr && cr == 0);

        /* Valid: 1 kB → 1024 */
        c_ret = convert_meminfo_value_to_uint64_bytes("1 kB", &cr);
        r_ret = rs_convert_meminfo_value_to_uint64_bytes("1 kB", &rr);
        assert_se(c_ret == r_ret);
        assert_se(cr == rr && cr == 1024);

        /* Valid: 1024 kB → 1048576 */
        c_ret = convert_meminfo_value_to_uint64_bytes("1024 kB", &cr);
        r_ret = rs_convert_meminfo_value_to_uint64_bytes("1024 kB", &rr);
        assert_se(c_ret == r_ret);
        assert_se(cr == rr && cr == 1048576ULL);

        /* Valid: 8192 kB → 8388608 */
        c_ret = convert_meminfo_value_to_uint64_bytes("8192 kB", &cr);
        r_ret = rs_convert_meminfo_value_to_uint64_bytes("8192 kB", &rr);
        assert_se(c_ret == r_ret);
        assert_se(cr == rr && cr == 8388608ULL);

        /* Valid: large value 12345678 kB */
        c_ret = convert_meminfo_value_to_uint64_bytes("12345678 kB", &cr);
        r_ret = rs_convert_meminfo_value_to_uint64_bytes("12345678 kB", &rr);
        assert_se(c_ret == r_ret);
        assert_se(cr == rr && cr == 12345678ULL * 1024ULL);

        c_ret = convert_meminfo_value_to_uint64_bytes("0x10 kB", &cr);
        r_ret = rs_convert_meminfo_value_to_uint64_bytes("0x10 kB", &rr);
        assert_se(c_ret == r_ret);
        assert_se(cr == rr && cr == 16ULL * 1024ULL);

        c_ret = convert_meminfo_value_to_uint64_bytes("\"16\" kB", &cr);
        r_ret = rs_convert_meminfo_value_to_uint64_bytes("\"16\" kB", &rr);
        assert_se(c_ret == r_ret);
        assert_se(c_ret < 0);

        /* Valid: with extra whitespace */
        c_ret = convert_meminfo_value_to_uint64_bytes("1024  kB", &cr);
        r_ret = rs_convert_meminfo_value_to_uint64_bytes("1024  kB", &rr);
        assert_se(c_ret == r_ret);
        assert_se(cr == rr && cr == 1048576ULL);

        /* Valid: leading whitespace */
        c_ret = convert_meminfo_value_to_uint64_bytes("  1024 kB", &cr);
        r_ret = rs_convert_meminfo_value_to_uint64_bytes("  1024 kB", &rr);
        assert_se(c_ret == r_ret);
        assert_se(cr == rr && cr == 1048576ULL);

        /* Invalid: empty string */
        c_ret = convert_meminfo_value_to_uint64_bytes("", &cr);
        r_ret = rs_convert_meminfo_value_to_uint64_bytes("", &rr);
        assert_se(c_ret == r_ret);
        assert_se(c_ret == -EINVAL);

        /* Invalid: wrong suffix "MB" */
        c_ret = convert_meminfo_value_to_uint64_bytes("12345 MB", &cr);
        r_ret = rs_convert_meminfo_value_to_uint64_bytes("12345 MB", &rr);
        assert_se(c_ret == r_ret);
        assert_se(c_ret < 0);

        /* Invalid: not a number */
        c_ret = convert_meminfo_value_to_uint64_bytes("abc kB", &cr);
        r_ret = rs_convert_meminfo_value_to_uint64_bytes("abc kB", &rr);
        assert_se(c_ret == r_ret);
        assert_se(c_ret < 0);

        /* Invalid: only whitespace */
        c_ret = convert_meminfo_value_to_uint64_bytes("   ", &cr);
        r_ret = rs_convert_meminfo_value_to_uint64_bytes("   ", &rr);
        assert_se(c_ret == r_ret);
        assert_se(c_ret == -EINVAL);

        /* Invalid: wrong suffix "kb" (lowercase) */
        c_ret = convert_meminfo_value_to_uint64_bytes("12345 kb", &cr);
        r_ret = rs_convert_meminfo_value_to_uint64_bytes("12345 kb", &rr);
        assert_se(c_ret == r_ret);
        assert_se(c_ret < 0);

        /* Rust-only: no suffix case (C function crashes on this input
         * because extract_first_word sets *p=NULL when the entire string
         * is consumed, then streq(NULL, "kB") SIGSEGVs. The Rust version
         * handles this gracefully.) */
        r_ret = rs_convert_meminfo_value_to_uint64_bytes("12345", &rr);
        assert_se(r_ret < 0);

        rr = 4711;
        assert_se(rs_convert_meminfo_value_to_uint64_bytes(NULL, &rr) == -EINVAL);
        assert_se(rr == 4711);
        assert_se(rs_convert_meminfo_value_to_uint64_bytes("1 kB", NULL) == -EINVAL);
        assert_se(rs_convert_meminfo_value_to_uint64_bytes("/ kB", &rr) == -EINVAL);
        assert_se(rr == 4711);
}

/* -- live procfs boundary parity ------------------------------------------- */

typedef int (*procfs_single_u64_fn_t)(uint64_t *ret);

static void assert_same_procfs_single(
                procfs_single_u64_fn_t c_fn,
                procfs_single_u64_fn_t rust_fn) {

        uint64_t c_value = UINT64_MAX, rust_value = UINT64_MAX;
        int c_ret, rust_ret;

        c_ret = c_fn(&c_value);
        rust_ret = rust_fn(&rust_value);
        assert_se(c_ret == rust_ret);
        if (c_ret >= 0)
                assert_se(c_value == rust_value);
}

static void test_procfs_runtime_abi(void) {
        uint64_t c_total = UINT64_MAX, c_used = UINT64_MAX;
        uint64_t rust_total = UINT64_MAX, rust_used = UINT64_MAX;
        int c_ret, rust_ret;

        assert_same_procfs_single(procfs_get_pid_max, rs_procfs_get_pid_max);
        assert_same_procfs_single(procfs_get_threads_max, rs_procfs_get_threads_max);
        assert_same_procfs_single(procfs_tasks_get_current, rs_procfs_tasks_get_current);
        assert_same_procfs_single(procfs_cpu_get_usage, rs_procfs_cpu_get_usage);

        c_ret = procfs_memory_get(&c_total, &c_used);
        rust_ret = rs_procfs_memory_get(&rust_total, &rust_used);
        assert_se(c_ret == rust_ret);
        if (c_ret >= 0) {
                assert_se(c_total == rust_total);
                assert_se(c_used == rust_used);
        }

        /* The C API asserts on mandatory NULL outputs. The Rust C ABI is
         * deliberately fail-closed and must leave caller storage untouched. */
        assert_se(rs_procfs_get_pid_max(NULL) == -EINVAL);
        assert_se(rs_procfs_get_threads_max(NULL) == -EINVAL);
        assert_se(rs_procfs_tasks_get_current(NULL) == -EINVAL);
        assert_se(rs_procfs_cpu_get_usage(NULL) == -EINVAL);
        assert_se(rs_procfs_tasks_set_limit(0) == -EINVAL);
}

int main(int argc, char **argv) {
        test_convert_meminfo_value_to_uint64_bytes();
        test_procfs_runtime_abi();
        return 0;
}
