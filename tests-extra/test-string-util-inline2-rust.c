/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Shadow test: string-util.h inline functions (batch 2) and signal-util.h vs Rust */

#include <assert.h>
#include <signal.h>
#include <string.h>
#include "tests.h"
#include "string-util.h"
#include "signal-util.h"
#include "rust/signal_util.h"
#include "rust/string_util.h"

/* C helpers for runtime signal constants (needed by Rust FFI) */
int rs_get_sigrtmin(void);
int rs_get_sigrtmax(void);
int rs_get_nsig(void);
int rs_get_sigrtmin(void) { return SIGRTMIN; }
int rs_get_sigrtmax(void) { return SIGRTMAX; }
int rs_get_nsig(void) { return _NSIG; }

/* ── strstr_ptr_internal ──────────────────────────────────────────────── */

static void test_strstr_ptr_internal(void) {
        const char *haystack = "hello world foo bar";

        assert_se(strstr_ptr_internal(haystack, "world") == rs_strstr_ptr_internal(haystack, "world"));
        assert_se(strstr_ptr_internal(haystack, "foo") == rs_strstr_ptr_internal(haystack, "foo"));
        assert_se(strstr_ptr_internal(haystack, "baz") == rs_strstr_ptr_internal(haystack, "baz"));
        assert_se(strstr_ptr_internal(haystack, "") == rs_strstr_ptr_internal(haystack, ""));
        assert_se(strstr_ptr_internal(haystack, "hello") == rs_strstr_ptr_internal(haystack, "hello"));

        /* NULL inputs */
        assert_se(rs_strstr_ptr_internal(NULL, "world") == NULL);
        assert_se(rs_strstr_ptr_internal("hello", NULL) == NULL);
        assert_se(rs_strstr_ptr_internal(NULL, NULL) == NULL);
}

/* ── strstrafter_internal ─────────────────────────────────────────────── */

static void test_strstrafter_internal(void) {
        const char *haystack = "hello world foo bar";

        assert_se(streq(strstrafter_internal(haystack, "hello "), rs_strstrafter_internal(haystack, "hello ")));
        assert_se(streq(strstrafter_internal(haystack, "world"), rs_strstrafter_internal(haystack, "world")));
        assert_se(strstrafter_internal(haystack, "baz") == NULL);
        assert_se(rs_strstrafter_internal(haystack, "baz") == NULL);
        assert_se(strstrafter_internal(haystack, "") == rs_strstrafter_internal(haystack, ""));

        /* NULL inputs — both return NULL */
        assert_se(rs_strstrafter_internal(NULL, "world") == NULL);
        assert_se(rs_strstrafter_internal("hello", NULL) == NULL);
}

/* ── memory_startswith_no_case ────────────────────────────────────────── */

static void test_memory_startswith_no_case(void) {
        const char *p = "Hello World";
        size_t sz = strlen(p);

        assert_se(memory_startswith_no_case(p, sz, "hello") == rs_memory_startswith_no_case(p, sz, "hello"));
        assert_se(memory_startswith_no_case(p, sz, "HELLO") == rs_memory_startswith_no_case(p, sz, "HELLO"));
        assert_se(memory_startswith_no_case(p, sz, "HeLLo") == rs_memory_startswith_no_case(p, sz, "HeLLo"));
        assert_se(memory_startswith_no_case(p, sz, "world") == rs_memory_startswith_no_case(p, sz, "world"));
        assert_se(memory_startswith_no_case(p, sz, "Hello World") == rs_memory_startswith_no_case(p, sz, "Hello World"));
        assert_se(memory_startswith_no_case(p, sz, "Hello World!") == rs_memory_startswith_no_case(p, sz, "Hello World!"));
        assert_se(memory_startswith_no_case(p, sz, "") == rs_memory_startswith_no_case(p, sz, ""));
        assert_se(memory_startswith_no_case(p, 3, "hel") == rs_memory_startswith_no_case(p, 3, "hel"));
        assert_se(memory_startswith_no_case(p, 3, "hell") == rs_memory_startswith_no_case(p, 3, "hell"));
}

/* ── skip_leading_chars ───────────────────────────────────────────────── */

static void test_skip_leading_chars(void) {
        const char *s = "  hello";
        char *c_r = skip_leading_chars(s, NULL);
        char *rs_r = rs_skip_leading_chars(s, NULL);
        /* Compare offsets instead of pointers — ASAN may affect pointer comparison */
        assert_se((c_r - s) == (rs_r - s));
        assert_se((c_r - s) == 2);

        s = "\t\nhello";
        c_r = skip_leading_chars(s, NULL);
        rs_r = rs_skip_leading_chars(s, NULL);
        assert_se((c_r - s) == (rs_r - s));

        s = "hello";
        c_r = skip_leading_chars(s, NULL);
        rs_r = rs_skip_leading_chars(s, NULL);
        assert_se((c_r - s) == (rs_r - s));

        s = "   ";
        c_r = skip_leading_chars(s, NULL);
        rs_r = rs_skip_leading_chars(s, NULL);
        assert_se((c_r - s) == (rs_r - s));

        /* Custom bad chars */
        assert_se(streq(skip_leading_chars("xxhello", "x"), rs_skip_leading_chars("xxhello", "x")));
        assert_se(streq(skip_leading_chars("abchello", "abc"), rs_skip_leading_chars("abchello", "abc")));

        /* NULL s */
        assert_se(skip_leading_chars(NULL, NULL) == NULL);
        assert_se(rs_skip_leading_chars(NULL, NULL) == NULL);
        assert_se(rs_skip_leading_chars(NULL, "x") == NULL);
}

/* ── strncpy_exact ────────────────────────────────────────────────────── */

static void test_strncpy_exact(void) {
        char c_buf[16], rs_buf[16];

        /* Normal copy */
        memset(c_buf, 'X', sizeof(c_buf));
        memset(rs_buf, 'X', sizeof(rs_buf));
        strncpy_exact(c_buf, "hello", 16);
        rs_strncpy_exact(rs_buf, "hello", 16);
        assert_se(memcmp(c_buf, rs_buf, 16) == 0);

        /* Truncated copy */
        memset(c_buf, 'X', sizeof(c_buf));
        memset(rs_buf, 'X', sizeof(rs_buf));
        strncpy_exact(c_buf, "hello world", 8);
        rs_strncpy_exact(rs_buf, "hello world", 8);
        assert_se(memcmp(c_buf, rs_buf, 8) == 0);

        /* Exact fit */
        memset(c_buf, 'X', sizeof(c_buf));
        memset(rs_buf, 'X', sizeof(rs_buf));
        strncpy_exact(c_buf, "hello", 6);
        rs_strncpy_exact(rs_buf, "hello", 6);
        assert_se(memcmp(c_buf, rs_buf, 6) == 0);

        /* Short copy (NUL padding) */
        memset(c_buf, 'X', sizeof(c_buf));
        memset(rs_buf, 'X', sizeof(rs_buf));
        strncpy_exact(c_buf, "hi", 10);
        rs_strncpy_exact(rs_buf, "hi", 10);
        assert_se(memcmp(c_buf, rs_buf, 10) == 0);
}

/* ── truncate_nl ──────────────────────────────────────────────────────── */

static void test_truncate_nl(void) {
        char c_buf[64], rs_buf[64];

        /* String with newline */
        strcpy(c_buf, "hello\n");
        strcpy(rs_buf, "hello\n");
        assert_se(streq(truncate_nl(c_buf), rs_truncate_nl(rs_buf)));
        assert_se(streq(c_buf, rs_buf));
        assert_se(streq(c_buf, "hello"));

        /* String without newline */
        strcpy(c_buf, "hello");
        strcpy(rs_buf, "hello");
        assert_se(streq(truncate_nl(c_buf), rs_truncate_nl(rs_buf)));

        /* Empty string */
        strcpy(c_buf, "");
        strcpy(rs_buf, "");
        assert_se(streq(truncate_nl(c_buf), rs_truncate_nl(rs_buf)));

        /* Multiple newlines */
        strcpy(c_buf, "hello\nworld\n");
        strcpy(rs_buf, "hello\nworld\n");
        assert_se(streq(truncate_nl(c_buf), rs_truncate_nl(rs_buf)));
        assert_se(streq(c_buf, rs_buf));
}

/* ── strdup_to ────────────────────────────────────────────────────────── */

static void test_strdup_to(void) {
        char *c_ret = NULL, *rs_ret = NULL;
        int c_r, rs_r;

        /* Normal string */
        c_r = strdup_to(&c_ret, "hello");
        rs_r = rs_strdup_to(&rs_ret, "hello");
        assert_se(c_r == rs_r);
        assert_se(c_r == 0);
        assert_se(streq(c_ret, rs_ret));
        free(c_ret); c_ret = NULL;
        free(rs_ret); rs_ret = NULL;

        /* NULL source */
        c_r = strdup_to(&c_ret, NULL);
        rs_r = rs_strdup_to(&rs_ret, NULL);
        assert_se(c_r == rs_r);
        assert_se(c_r == 0);
        assert_se(c_ret == NULL);
        assert_se(rs_ret == NULL);

        /* Empty string */
        c_r = strdup_to(&c_ret, "");
        rs_r = rs_strdup_to(&rs_ret, "");
        assert_se(c_r == rs_r);
        assert_se(streq(c_ret, rs_ret));
        free(c_ret); c_ret = NULL;
        free(rs_ret); rs_ret = NULL;
}

/* ── string_contains_word ─────────────────────────────────────────────── */

static void test_string_contains_word(void) {
        assert_se(string_contains_word("hello world foo", WHITESPACE, "hello") ==
                  rs_string_contains_word("hello world foo", WHITESPACE, "hello"));
        assert_se(string_contains_word("hello world foo", WHITESPACE, "world") ==
                  rs_string_contains_word("hello world foo", WHITESPACE, "world"));
        assert_se(string_contains_word("hello world foo", WHITESPACE, "foo") ==
                  rs_string_contains_word("hello world foo", WHITESPACE, "foo"));
        assert_se(string_contains_word("hello world foo", WHITESPACE, "bar") ==
                  rs_string_contains_word("hello world foo", WHITESPACE, "bar"));
        assert_se(string_contains_word("hello,world,foo", ",", "world") ==
                  rs_string_contains_word("hello,world,foo", ",", "world"));
}

/* ── empty_or_dash_to_null ────────────────────────────────────────────── */

static void test_empty_or_dash_to_null(void) {
        /* empty_or_dash_to_null is a GCC statement-expression macro using typeof(p),
         * which doesn't work with string literals (array type). Use const char* vars. */
        const char *p_hello = "hello", *p_empty = "", *p_dash = "-", *p_ddash = "--";

        assert_se(empty_or_dash_to_null(p_hello) == rs_empty_or_dash_to_null(p_hello));
        assert_se(empty_or_dash_to_null(p_empty) == rs_empty_or_dash_to_null(p_empty));
        assert_se(empty_or_dash_to_null(p_dash) == rs_empty_or_dash_to_null(p_dash));
        assert_se(empty_or_dash_to_null(NULL) == rs_empty_or_dash_to_null(NULL));
        assert_se(empty_or_dash_to_null(p_ddash) == rs_empty_or_dash_to_null(p_ddash));
}

/* ── SIGNAL_VALID / signal_to_string_with_check ───────────────────────── */

static void test_signal_valid(void) {
        assert_se(SIGNAL_VALID(SIGTERM) == rs_signal_is_valid(SIGTERM));
        assert_se(SIGNAL_VALID(SIGKILL) == rs_signal_is_valid(SIGKILL));
        assert_se(SIGNAL_VALID(0) == rs_signal_is_valid(0));
        assert_se(SIGNAL_VALID(-1) == rs_signal_is_valid(-1));
        assert_se(SIGNAL_VALID(99999) == rs_signal_is_valid(99999));
        assert_se(SIGNAL_VALID(SIGRTMAX) == rs_signal_is_valid(SIGRTMAX));
        assert_se(SIGNAL_VALID(SIGRTMAX + 1) == rs_signal_is_valid(SIGRTMAX + 1));
}

static void test_signal_to_string_with_check(void) {
        assert_se(signal_to_string_with_check(SIGTERM) == NULL || streq(signal_to_string_with_check(SIGTERM), rs_signal_to_string_with_check(SIGTERM)));
        assert_se(signal_to_string_with_check(SIGKILL) == NULL || streq(signal_to_string_with_check(SIGKILL), rs_signal_to_string_with_check(SIGKILL)));
        assert_se(signal_to_string_with_check(SIGUSR1) == NULL || streq(signal_to_string_with_check(SIGUSR1), rs_signal_to_string_with_check(SIGUSR1)));
        assert_se(streq(signal_to_string_with_check(SIGRTMIN), rs_signal_to_string_with_check(SIGRTMIN)));

        /* Invalid signals */
        assert_se(signal_to_string_with_check(0) == NULL);
        assert_se(rs_signal_to_string_with_check(0) == NULL);
        assert_se(signal_to_string_with_check(-1) == NULL);
        assert_se(rs_signal_to_string_with_check(-1) == NULL);
        assert_se(signal_to_string_with_check(99999) == NULL);
        assert_se(rs_signal_to_string_with_check(99999) == NULL);
}

int main(int argc, char **argv) {
        test_strstr_ptr_internal();
        test_strstrafter_internal();
        test_memory_startswith_no_case();
        test_skip_leading_chars();
        test_strncpy_exact();
        test_truncate_nl();
        test_strdup_to();
        test_string_contains_word();
        test_empty_or_dash_to_null();
        test_signal_valid();
        test_signal_to_string_with_check();
        return 0;
}
