/* SPDX-License-Identifier: LGPL-2.1-or-later */

/* Rust SipHash callback coverage. */

#include <assert.h>
#include <string.h>
#include <stdint.h>

#include "tests.h"

#include "rust/siphash24.h"

static void test_string_hash_func(void) {
        struct rs_siphash c_state, rs_state;
        uint8_t key[16] = {};

        const char *s = "hello world";

        rs_siphash24_init(&c_state, key);
        rs_siphash24_init(&rs_state, key);

        /* Call C function via cast — same struct layout, just different name */
        ((void (*)(const char *, struct rs_siphash *))rs_string_hash_func)(s, &c_state);
        rs_string_hash_func(s, &rs_state);

        assert_se(c_state.v0 == rs_state.v0);
        assert_se(c_state.v1 == rs_state.v1);
        assert_se(c_state.v2 == rs_state.v2);
        assert_se(c_state.v3 == rs_state.v3);
        assert_se(c_state.inlen == rs_state.inlen);
}

static void test_string_hash_func_empty(void) {
        struct rs_siphash c_state, rs_state;
        uint8_t key[16] = {};

        rs_siphash24_init(&c_state, key);
        rs_siphash24_init(&rs_state, key);

        rs_string_hash_func("", &c_state);
        rs_string_hash_func("", &rs_state);

        assert_se(c_state.v0 == rs_state.v0);
        assert_se(c_state.inlen == rs_state.inlen);
}

static void test_string_hash_func_different(void) {
        struct rs_siphash s1_state, s2_state;
        /* Use non-zero key to avoid collisions */
        uint8_t key[16] = { [0 ... 14] = 0xaa, [15] = 0xbb };

        rs_siphash24_init(&s1_state, key);
        rs_siphash24_init(&s2_state, key);

        rs_string_hash_func("hello", &s1_state);
        rs_string_hash_func("world", &s2_state);

        /* Finalize to get a definitive hash value */
        uint64_t h1 = rs_siphash24_finalize(&s1_state);
        uint64_t h2 = rs_siphash24_finalize(&s2_state);
        assert_se(h1 != h2);
}

static void test_path_hash_func_absolute(void) {
        struct rs_siphash c_state, rs_state;
        uint8_t key[16] = {};

        rs_siphash24_init(&c_state, key);
        rs_siphash24_init(&rs_state, key);

        rs_path_hash_func("/usr/bin/systemd", &c_state);
        rs_path_hash_func("/usr/bin/systemd", &rs_state);

        assert_se(c_state.v0 == rs_state.v0);
        assert_se(c_state.inlen == rs_state.inlen);
}

static void test_path_hash_func_trailing_slash(void) {
        struct rs_siphash c_state1, rs_state1;
        struct rs_siphash c_state2, rs_state2;
        uint8_t key[16] = {};

        /* Both "/usr/bin" and "/usr/bin/" should produce the same hash */
        rs_siphash24_init(&c_state1, key);
        rs_siphash24_init(&rs_state1, key);
        rs_siphash24_init(&c_state2, key);
        rs_siphash24_init(&rs_state2, key);

        rs_path_hash_func("/usr/bin", &c_state1);
        rs_path_hash_func("/usr/bin", &rs_state1);
        rs_path_hash_func("/usr/bin/", &c_state2);
        rs_path_hash_func("/usr/bin/", &rs_state2);

        assert_se(c_state1.v0 == rs_state1.v0);
        assert_se(c_state2.v0 == rs_state2.v0);
        /* Trailing slash doesn't affect hash */
        assert_se(c_state1.v0 == c_state2.v0);
        assert_se(rs_state1.v0 == rs_state2.v0);
}

static void test_path_hash_func_double_slash(void) {
        struct rs_siphash c_state1, rs_state1;
        struct rs_siphash c_state2, rs_state2;
        uint8_t key[16] = {};

        /* "/usr//bin" and "/usr/bin" should produce the same hash */
        rs_siphash24_init(&c_state1, key);
        rs_siphash24_init(&rs_state1, key);
        rs_siphash24_init(&c_state2, key);
        rs_siphash24_init(&rs_state2, key);

        rs_path_hash_func("/usr/bin", &c_state1);
        rs_path_hash_func("/usr/bin", &rs_state1);
        rs_path_hash_func("/usr//bin", &c_state2);
        rs_path_hash_func("/usr//bin", &rs_state2);

        assert_se(c_state1.v0 == rs_state1.v0);
        assert_se(c_state2.v0 == rs_state2.v0);
        assert_se(c_state1.v0 == c_state2.v0);
}

static void test_path_hash_func_relative(void) {
        struct rs_siphash c_state, rs_state;
        uint8_t key[16] = {};

        rs_siphash24_init(&c_state, key);
        rs_siphash24_init(&rs_state, key);

        rs_path_hash_func("foo/bar/baz", &c_state);
        rs_path_hash_func("foo/bar/baz", &rs_state);

        assert_se(c_state.v0 == rs_state.v0);
        assert_se(c_state.inlen == rs_state.inlen);
}

static void test_path_hash_func_root(void) {
        struct rs_siphash c_state, rs_state;
        uint8_t key[16] = {};

        rs_siphash24_init(&c_state, key);
        rs_siphash24_init(&rs_state, key);

        rs_path_hash_func("/", &c_state);
        rs_path_hash_func("/", &rs_state);

        assert_se(c_state.v0 == rs_state.v0);
}

static void test_path_hash_func_absolute_vs_relative(void) {
        struct rs_siphash c_abs, rs_abs;
        struct rs_siphash c_rel, rs_rel;
        uint8_t key[16] = {};

        rs_siphash24_init(&c_abs, key);
        rs_siphash24_init(&rs_abs, key);
        rs_siphash24_init(&c_rel, key);
        rs_siphash24_init(&rs_rel, key);

        rs_path_hash_func("usr/bin", &c_rel);
        rs_path_hash_func("usr/bin", &rs_rel);
        rs_path_hash_func("/usr/bin", &c_abs);
        rs_path_hash_func("/usr/bin", &rs_abs);

        assert_se(c_rel.v0 == rs_rel.v0);
        assert_se(c_abs.v0 == rs_abs.v0);
        /* Absolute and relative differ */
        assert_se(c_abs.v0 != c_rel.v0);
}

int main(int argc, char *argv[]) {
        test_string_hash_func();
        test_string_hash_func_empty();
        test_string_hash_func_different();
        test_path_hash_func_absolute();
        test_path_hash_func_trailing_slash();
        test_path_hash_func_double_slash();
        test_path_hash_func_relative();
        test_path_hash_func_root();
        test_path_hash_func_absolute_vs_relative();
        return 0;
}
