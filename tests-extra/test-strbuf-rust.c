/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Shadow test: C strbuf vs Rust rs_strbuf */

#include <string.h>

#include "strbuf.h"
#include "rust/strbuf.h"

/* ── new / free ───────────────────────────────────────────────────────── */

static void test_strbuf_new_free(void) {
        struct strbuf *c = strbuf_new();
        struct rs_Strbuf *r = rs_strbuf_new();

        assert_se(c != NULL);
        assert_se(r != NULL);
        assert_se(c->len == 1);  /* initial NUL byte */
        assert_se(c->nodes_count == 1);
        assert_se(c->in_count == 0);

        assert_se(strbuf_free(c) == NULL);
        assert_se(rs_strbuf_free(r) == NULL);

        /* NULL input */
        assert_se(strbuf_free(NULL) == NULL);
        assert_se(rs_strbuf_free(NULL) == NULL);
}

/* ── add_string (deduplication) ───────────────────────────────────────── */

static void test_strbuf_add_string(void) {
        struct strbuf *c = strbuf_new();
        struct rs_Strbuf *r = rs_strbuf_new();

        /* Add first string */
        ssize_t c_off1 = strbuf_add_string(c, "hello");
        ssize_t r_off1 = rs_strbuf_add_string_full(r, "hello", SIZE_MAX);
        assert_se(c_off1 >= 0);
        assert_se(r_off1 >= 0);
        assert_se(c_off1 == r_off1);  /* both start at same offset */
        assert_se(strcmp(c->buf + c_off1, "hello") == 0);

        /* Add same string again — should deduplicate */
        ssize_t c_off2 = strbuf_add_string(c, "hello");
        ssize_t r_off2 = rs_strbuf_add_string_full(r, "hello", SIZE_MAX);
        assert_se(c_off2 == c_off1);
        assert_se(r_off2 == r_off1);

        /* Add different string */
        ssize_t c_off3 = strbuf_add_string(c, "world");
        ssize_t r_off3 = rs_strbuf_add_string_full(r, "world", SIZE_MAX);
        assert_se(c_off3 > c_off1);
        assert_se(r_off3 > r_off1);

        strbuf_free(c);
        rs_strbuf_free(r);
}

/* ── tail deduplication ──────────────────────────────────────────────── */

static void test_strbuf_tail_dedup(void) {
        struct strbuf *c = strbuf_new();
        struct rs_Strbuf *r = rs_strbuf_new();

        /* "kitten" and "smitten" share tail "itten" */
        ssize_t c_off1 = strbuf_add_string(c, "kitten");
        ssize_t r_off1 = rs_strbuf_add_string_full(r, "kitten", SIZE_MAX);
        assert_se(c_off1 >= 0);
        assert_se(r_off1 >= 0);

        ssize_t c_off2 = strbuf_add_string(c, "smitten");
        ssize_t r_off2 = rs_strbuf_add_string_full(r, "smitten", SIZE_MAX);
        assert_se(c_off2 >= 0);
        assert_se(r_off2 >= 0);

        /* Both should return same offsets (matching C behavior) */
        assert_se(c_off1 == r_off1);
        assert_se(c_off2 == r_off2);
        assert_se(c_off1 != c_off2);

        strbuf_free(c);
        rs_strbuf_free(r);
}

/* ── add_string_full with explicit length ─────────────────────────────── */

static void test_strbuf_add_string_full(void) {
        struct strbuf *c = strbuf_new();
        struct rs_Strbuf *r = rs_strbuf_new();

        /* Explicit length (not NUL-terminated) */
        ssize_t c_off = strbuf_add_string_full(c, "hello world", 5);
        ssize_t r_off = rs_strbuf_add_string_full(r, "hello world", 5);
        assert_se(c_off >= 0);
        assert_se(r_off >= 0);
        assert_se(c_off == r_off);
        assert_se(memcmp(c->buf + c_off, "hello", 5) == 0);

        /* Zero-length string */
        ssize_t c_off0 = strbuf_add_string_full(c, "test", 0);
        ssize_t r_off0 = rs_strbuf_add_string_full(r, "test", 0);
        assert_se(c_off0 == 0);
        assert_se(r_off0 == 0);

        strbuf_free(c);
        rs_strbuf_free(r);
}

/* ── strbuf_complete ──────────────────────────────────────────────────── */

static void test_strbuf_complete(void) {
        struct strbuf *c = strbuf_new();
        struct rs_Strbuf *r = rs_strbuf_new();

        strbuf_add_string(c, "hello");
        rs_strbuf_add_string_full(r, "hello", SIZE_MAX);

        /* Complete: frees trie but keeps buffer */
        strbuf_complete(c);
        rs_strbuf_complete(r);
        assert_se(c->root == NULL);

        /* Buffer should still be readable */
        assert_se(strcmp(c->buf + 1, "hello") == 0);

        strbuf_free(c);
        rs_strbuf_free(r);
}

/* ── Main ─────────────────────────────────────────────────────────────── */

int main(int argc, char **argv) {
        test_strbuf_new_free();
        test_strbuf_add_string();
        test_strbuf_tail_dedup();
        test_strbuf_add_string_full();
        test_strbuf_complete();

        return 0;
}
