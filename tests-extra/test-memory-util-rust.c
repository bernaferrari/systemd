/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Shadow test: C memory-util vs Rust rs_memory_util */
/* RUST-CONTRACT: page-size */
/* RUST-CONTRACT: counted-copy-and-fill */
/* RUST-CONTRACT: counted-comparison */
/* RUST-CONTRACT: counted-search */
/* RUST-CONTRACT: uniform-byte-predicate */

#include <string.h>

#include "memory-util.h"
#include "rust/memory_util.h"

/* ── page_size ────────────────────────────────────────────────────────── */

static void test_page_size(void) {
        size_t c_pgsz = page_size();
        size_t r_pgsz = rs_page_size();

        assert_se(c_pgsz > 0);
        assert_se(r_pgsz > 0);
        assert_se(c_pgsz == r_pgsz);

        /* Verify it's a power of two */
        assert_se((c_pgsz & (c_pgsz - 1)) == 0);
}

/* ── no-dereference early return ──────────────────────────────────────── */

static void test_memmem_safe_zero_length_null(void) {
        assert_se(memmem_safe(NULL, 0, NULL, 0) == NULL);
        assert_se(rs_memmem_safe(NULL, 0, NULL, 0) == NULL);

        assert_se(mempmem_safe(NULL, 0, NULL, 0) == NULL);
        assert_se(rs_mempmem_safe(NULL, 0, NULL, 0) == NULL);
}

/* ── counted memory primitives ────────────────────────────────────────── */

static void test_memory_primitives(void) {
        uint8_t source[] = { 0x00, 0x7f, 0x80, 0xff };
        uint8_t c_copy[4] = {};
        uint8_t r_copy[4] = {};
        uint8_t c_fill[4] = {};
        uint8_t r_fill[4] = {};
        const uint8_t short_prefix[] = { 0x00, 0x7f };
        const uint8_t longer_prefix[] = { 0x00, 0x7f, 0x80 };
        const uint8_t haystack[] = { 'a', 'b', 'a', 'b', 'a' };
        const uint8_t needle[] = { 'a', 'b', 'a' };
        uint8_t repeated[20];

        assert_se(memcpy_safe(c_copy, source, sizeof(source)) == c_copy);
        assert_se(rs_memcpy_safe(r_copy, source, sizeof(source)) == r_copy);
        assert_se(memcmp(c_copy, r_copy, sizeof(c_copy)) == 0);
        assert_se(memcpy_safe(NULL, NULL, 0) == NULL);
        assert_se(rs_memcpy_safe(NULL, NULL, 0) == NULL);

        memset(c_copy, 0, sizeof(c_copy));
        memset(r_copy, 0, sizeof(r_copy));
        assert_se(mempcpy_safe(c_copy, source, sizeof(source)) == c_copy + sizeof(c_copy));
        assert_se(rs_mempcpy_safe(r_copy, source, sizeof(source)) == r_copy + sizeof(r_copy));
        assert_se(memcmp(c_copy, r_copy, sizeof(c_copy)) == 0);
        assert_se(mempcpy_safe(NULL, NULL, 0) == NULL);
        assert_se(rs_mempcpy_safe(NULL, NULL, 0) == NULL);

        assert_se(memcmp_safe(source, r_copy, sizeof(source)) ==
                  rs_memcmp_safe(source, r_copy, sizeof(source)));
        assert_se(memcmp_safe(NULL, NULL, 0) == 0);
        assert_se(rs_memcmp_safe(NULL, NULL, 0) == 0);
        assert_se(memcmp_nn(short_prefix, sizeof(short_prefix), longer_prefix, sizeof(longer_prefix)) ==
                  rs_memcmp_nn(short_prefix, sizeof(short_prefix), longer_prefix, sizeof(longer_prefix)));
        assert_se(memcmp_nn(longer_prefix, sizeof(longer_prefix), short_prefix, sizeof(short_prefix)) ==
                  rs_memcmp_nn(longer_prefix, sizeof(longer_prefix), short_prefix, sizeof(short_prefix)));

        assert_se(mempset(c_fill, 0xa5, sizeof(c_fill)) == c_fill + sizeof(c_fill));
        assert_se(rs_mempset(r_fill, 0xa5, sizeof(r_fill)) == r_fill + sizeof(r_fill));
        assert_se(memcmp(c_fill, r_fill, sizeof(c_fill)) == 0);
        assert_se(mempset(c_fill, 0, 0) == c_fill);
        assert_se(rs_mempset(r_fill, 0, 0) == r_fill);

        assert_se(memmem_safe(haystack, sizeof(haystack), needle, sizeof(needle)) == haystack);
        assert_se(rs_memmem_safe(haystack, sizeof(haystack), needle, sizeof(needle)) == haystack);
        assert_se(mempmem_safe(haystack, sizeof(haystack), needle, sizeof(needle)) == haystack + sizeof(needle));
        assert_se(rs_mempmem_safe(haystack, sizeof(haystack), needle, sizeof(needle)) == haystack + sizeof(needle));
        assert_se(memmem_safe(NULL, 0, needle, sizeof(needle)) == NULL);
        assert_se(rs_memmem_safe(NULL, 0, needle, sizeof(needle)) == NULL);
        assert_se(mempmem_safe(NULL, 0, needle, sizeof(needle)) == NULL);
        assert_se(rs_mempmem_safe(NULL, 0, needle, sizeof(needle)) == NULL);

        memset(repeated, 0x5a, sizeof(repeated));
        assert_se(memeqbyte(0x5a, repeated, sizeof(repeated)) ==
                  rs_memeqbyte(0x5a, repeated, sizeof(repeated)));
        repeated[17] = 0x00;
        assert_se(memeqbyte(0x5a, repeated, sizeof(repeated)) ==
                  rs_memeqbyte(0x5a, repeated, sizeof(repeated)));
        assert_se(memeqbyte(0x5a, NULL, 0) == rs_memeqbyte(0x5a, NULL, 0));
}

/* ── Main ─────────────────────────────────────────────────────────────── */

int main(int argc, char **argv) {
        test_page_size();
        test_memmem_safe_zero_length_null();
        test_memory_primitives();

        return 0;
}
