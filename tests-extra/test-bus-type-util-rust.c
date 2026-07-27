/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <assert.h>
#include <stdint.h>
#include <string.h>

#include "tests.h"

#include "rust/bus_type_util.h"

/* ── bus_type_is_valid ─────────────────────────────────────────────────── */

static void test_bus_type_is_valid_all(void) {
        /* All valid D-Bus type characters */
        const char valid[] = "ybnqiuxtdsogvaerh";
        for (int i = 0; valid[i]; i++) {
                assert_se(rs_bus_type_is_valid(valid[i]));
        }
}

static void test_bus_type_is_valid_invalid(void) {
        /* Some invalid characters */
        assert_se(!rs_bus_type_is_valid('z'));
        assert_se(!rs_bus_type_is_valid('A'));
        assert_se(!rs_bus_type_is_valid(' '));
        assert_se(!rs_bus_type_is_valid(0));
        assert_se(!rs_bus_type_is_valid('('));
        assert_se(!rs_bus_type_is_valid(')'));
        assert_se(!rs_bus_type_is_valid('{'));
        assert_se(!rs_bus_type_is_valid('}'));
}

/* ── bus_type_is_basic ─────────────────────────────────────────────────── */

static void test_bus_type_is_basic_all(void) {
        /* Basic types: ybnqiuxtdsogh (no containers a, v, r, e) */
        const char basic[] = "ybnqiuxtdsogh";
        for (int i = 0; basic[i]; i++) {
                assert_se(rs_bus_type_is_basic(basic[i]));
        }
}

static void test_bus_type_is_basic_containers_excluded(void) {
        /* Container types must NOT be basic */
        assert_se(!rs_bus_type_is_basic('a')); /* ARRAY */
        assert_se(!rs_bus_type_is_basic('v')); /* VARIANT */
        assert_se(!rs_bus_type_is_basic('r')); /* STRUCT */
        assert_se(!rs_bus_type_is_basic('e')); /* DICT_ENTRY */
}

/* ── bus_type_is_trivial ───────────────────────────────────────────────── */

static void test_bus_type_is_trivial_all(void) {
        /* Trivial types: ybnqiuxtd (fixed-size, no string/object_path) */
        const char trivial[] = "ybnqiuxtd";
        for (int i = 0; trivial[i]; i++) {
                assert_se(rs_bus_type_is_trivial(trivial[i]));
        }
}

static void test_bus_type_is_trivial_non_trivial(void) {
        /* String-like types are not trivial */
        assert_se(!rs_bus_type_is_trivial('s')); /* STRING */
        assert_se(!rs_bus_type_is_trivial('o')); /* OBJECT_PATH */
        assert_se(!rs_bus_type_is_trivial('g')); /* SIGNATURE */
        assert_se(!rs_bus_type_is_trivial('h')); /* UNIX_FD */
        assert_se(!rs_bus_type_is_trivial('a')); /* ARRAY */
}

/* ── bus_type_is_container ─────────────────────────────────────────────── */

static void test_bus_type_is_container_all(void) {
        assert_se(rs_bus_type_is_container('a')); /* ARRAY */
        assert_se(rs_bus_type_is_container('v')); /* VARIANT */
        assert_se(rs_bus_type_is_container('r')); /* STRUCT */
        assert_se(rs_bus_type_is_container('e')); /* DICT_ENTRY */
}

static void test_bus_type_is_container_basic_excluded(void) {
        assert_se(!rs_bus_type_is_container('y'));
        assert_se(!rs_bus_type_is_container('b'));
        assert_se(!rs_bus_type_is_container('s'));
}

/* ── bus_type_get_alignment ────────────────────────────────────────────── */

static void test_bus_type_get_alignment(void) {
        assert_se(rs_bus_type_get_alignment('y') == 1); /* BYTE */
        assert_se(rs_bus_type_get_alignment('g') == 1); /* SIGNATURE */
        assert_se(rs_bus_type_get_alignment('v') == 1); /* VARIANT */

        assert_se(rs_bus_type_get_alignment('n') == 2); /* INT16 */
        assert_se(rs_bus_type_get_alignment('q') == 2); /* UINT16 */

        assert_se(rs_bus_type_get_alignment('b') == 4); /* BOOLEAN */
        assert_se(rs_bus_type_get_alignment('i') == 4); /* INT32 */
        assert_se(rs_bus_type_get_alignment('u') == 4); /* UINT32 */
        assert_se(rs_bus_type_get_alignment('s') == 4); /* STRING */
        assert_se(rs_bus_type_get_alignment('o') == 4); /* OBJECT_PATH */
        assert_se(rs_bus_type_get_alignment('a') == 4); /* ARRAY */
        assert_se(rs_bus_type_get_alignment('h') == 4); /* UNIX_FD */

        assert_se(rs_bus_type_get_alignment('x') == 8); /* INT64 */
        assert_se(rs_bus_type_get_alignment('t') == 8); /* UINT64 */
        assert_se(rs_bus_type_get_alignment('d') == 8); /* DOUBLE */
        assert_se(rs_bus_type_get_alignment('r') == 8); /* STRUCT */
        assert_se(rs_bus_type_get_alignment('e') == 8); /* DICT_ENTRY */
        assert_se(rs_bus_type_get_alignment('(') == 8); /* STRUCT_BEGIN */
        assert_se(rs_bus_type_get_alignment('{') == 8); /* DICT_ENTRY_BEGIN */
}

static void test_bus_type_get_alignment_invalid(void) {
        assert_se(rs_bus_type_get_alignment('z') == -22); /* -EINVAL */
        assert_se(rs_bus_type_get_alignment('s') != 8);
        assert_se(rs_bus_type_get_alignment('y') != 4);
}

/* ── bus_type_get_size ─────────────────────────────────────────────────── */

static void test_bus_type_get_size(void) {
        assert_se(rs_bus_type_get_size('y') == 1);  /* BYTE */
        assert_se(rs_bus_type_get_size('n') == 2);  /* INT16 */
        assert_se(rs_bus_type_get_size('q') == 2);  /* UINT16 */
        assert_se(rs_bus_type_get_size('b') == 4);  /* BOOLEAN */
        assert_se(rs_bus_type_get_size('i') == 4);  /* INT32 */
        assert_se(rs_bus_type_get_size('u') == 4);  /* UINT32 */
        assert_se(rs_bus_type_get_size('h') == 4);  /* UNIX_FD */
        assert_se(rs_bus_type_get_size('x') == 8);  /* INT64 */
        assert_se(rs_bus_type_get_size('t') == 8);  /* UINT64 */
        assert_se(rs_bus_type_get_size('d') == 8);  /* DOUBLE */
}

static void test_bus_type_get_size_invalid(void) {
        assert_se(rs_bus_type_get_size('z') == -22); /* -EINVAL */
        assert_se(rs_bus_type_get_size('s') == -22); /* STRING has no fixed size */
        assert_se(rs_bus_type_get_size('a') == -22); /* ARRAY has no fixed size */
}

/* ── trivial_compare_func (C comparison possible — in hash-funcs.c/libshared) ── */

extern int trivial_compare_func(const void *a, const void *b);

static void test_trivial_compare_func_same(void) {
        int x = 42;
        int r_c = trivial_compare_func(&x, &x);
        int r_r = rs_trivial_compare_func(&x, &x);
        assert_se(r_c == r_r);
}

static void test_trivial_compare_func_less(void) {
        int a = 1, b = 2;
        int r_c = trivial_compare_func(&a, &b);
        int r_r = rs_trivial_compare_func(&a, &b);
        assert_se(r_c == r_r);
        /* Note: result depends on pointer addresses, not values */
}

static void test_trivial_compare_func_greater(void) {
        int a = 2, b = 1;
        int r_c = trivial_compare_func(&a, &b);
        int r_r = rs_trivial_compare_func(&a, &b);
        assert_se(r_c == r_r);
}

static void test_trivial_compare_func_null(void) {
        int x = 0;
        int r_c = trivial_compare_func(NULL, &x);
        int r_r = rs_trivial_compare_func(NULL, &x);
        assert_se(r_c == r_r);
}

/* ── uint64_compare_func (C comparison possible — in hash-funcs.c/libshared) ── */

extern int uint64_compare_func(const uint64_t *a, const uint64_t *b);

static void test_uint64_compare_func_equal(void) {
        uint64_t v = 42;
        int r_c = uint64_compare_func(&v, &v);
        int r_r = rs_uint64_compare_func(&v, &v);
        assert_se(r_c == r_r);
        assert_se(r_r == 0);
}

static void test_uint64_compare_func_less(void) {
        uint64_t a = 10, b = 20;
        int r_c = uint64_compare_func(&a, &b);
        int r_r = rs_uint64_compare_func(&a, &b);
        assert_se(r_c == r_r);
        assert_se(r_r < 0);
}

static void test_uint64_compare_func_greater(void) {
        uint64_t a = 20, b = 10;
        int r_c = uint64_compare_func(&a, &b);
        int r_r = rs_uint64_compare_func(&a, &b);
        assert_se(r_c == r_r);
        assert_se(r_r > 0);
}

static void test_uint64_compare_func_zero(void) {
        uint64_t a = 0, b = 0;
        assert_se(rs_uint64_compare_func(&a, &b) == 0);
}

static void test_uint64_compare_func_max(void) {
        uint64_t a = UINT64_MAX, b = 0;
        assert_se(rs_uint64_compare_func(&a, &b) > 0);
        assert_se(rs_uint64_compare_func(&b, &a) < 0);
}

int main(int argc, char *argv[]) {
        test_bus_type_is_valid_all();
        test_bus_type_is_valid_invalid();
        test_bus_type_is_basic_all();
        test_bus_type_is_basic_containers_excluded();
        test_bus_type_is_trivial_all();
        test_bus_type_is_trivial_non_trivial();
        test_bus_type_is_container_all();
        test_bus_type_is_container_basic_excluded();
        test_bus_type_get_alignment();
        test_bus_type_get_alignment_invalid();
        test_bus_type_get_size();
        test_bus_type_get_size_invalid();
        test_trivial_compare_func_same();
        test_trivial_compare_func_less();
        test_trivial_compare_func_greater();
        test_trivial_compare_func_null();
        test_uint64_compare_func_equal();
        test_uint64_compare_func_less();
        test_uint64_compare_func_greater();
        test_uint64_compare_func_zero();
        test_uint64_compare_func_max();

        return 0;
}
