/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Shadow test: C memory-util vs Rust rs_memory_util */

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

/* ── memdup_reverse ───────────────────────────────────────────────────── */

static void test_memdup_reverse(void) {
        const char input[] = "abcdef";
        size_t len = strlen(input);

        char *c_rev = memdup_reverse(input, len);
        char *r_rev = rs_memdup_reverse(input, len);

        assert_se(c_rev != NULL);
        assert_se(r_rev != NULL);
        assert_se(memcmp(c_rev, r_rev, len) == 0);
        assert_se(memcmp(c_rev, "fedcba", len) == 0);

        free(c_rev);
        free(r_rev);
}

/* ── memdup_reverse odd length ────────────────────────────────────────── */

static void test_memdup_reverse_odd(void) {
        const char input[] = "abcde";
        size_t len = strlen(input);

        char *c_rev = memdup_reverse(input, len);
        char *r_rev = rs_memdup_reverse(input, len);

        assert_se(c_rev != NULL);
        assert_se(r_rev != NULL);
        assert_se(memcmp(c_rev, r_rev, len) == 0);
        assert_se(memcmp(c_rev, "edcba", len) == 0);

        free(c_rev);
        free(r_rev);
}

/* ── memdup_reverse single byte ───────────────────────────────────────── */

static void test_memdup_reverse_single(void) {
        const char input[] = "x";

        char *c_rev = memdup_reverse(input, 1);
        char *r_rev = rs_memdup_reverse(input, 1);

        assert_se(c_rev != NULL);
        assert_se(r_rev != NULL);
        assert_se(*c_rev == 'x');
        assert_se(*r_rev == 'x');
        assert_se(*c_rev == *r_rev);

        free(c_rev);
        free(r_rev);
}

/* ── Main ─────────────────────────────────────────────────────────────── */

int main(int argc, char **argv) {
        test_page_size();
        test_memdup_reverse();
        test_memdup_reverse_odd();
        test_memdup_reverse_single();

        return 0;
}
