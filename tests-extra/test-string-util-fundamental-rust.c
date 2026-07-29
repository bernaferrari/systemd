/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Shadow test: string-util.h inline functions vs Rust */

#include <assert.h>
#include <string.h>
#include "tests.h"
#include "string-util.h"
#include "rust/string_util.h"

static void test_strcmp_ptr(void) {
        assert_se(strcmp_ptr("hello", "hello") == rs_strcmp_ptr("hello", "hello"));
        assert_se(strcmp_ptr("abc", "abd") == rs_strcmp_ptr("abc", "abd"));
        assert_se(strcmp_ptr("abd", "abc") == rs_strcmp_ptr("abd", "abc"));
        assert_se(strcmp_ptr("a", "z") == rs_strcmp_ptr("a", "z"));
        assert_se(strcmp_ptr("abc", "abcd") == rs_strcmp_ptr("abc", "abcd"));
        assert_se(strcmp_ptr(NULL, NULL) == rs_strcmp_ptr(NULL, NULL));
        assert_se(strcmp_ptr(NULL, "abc") == rs_strcmp_ptr(NULL, "abc"));
        assert_se(strcmp_ptr("abc", NULL) == rs_strcmp_ptr("abc", NULL));
}

static void test_strncmp_ptr(void) {
        assert_se(strncmp_ptr("hello", "hello", 5) == rs_strncmp_ptr("hello", "hello", 5));
        assert_se(strncmp_ptr("abc", "abd", 2) == rs_strncmp_ptr("abc", "abd", 2));
        assert_se(strncmp_ptr("abc", "abd", 3) == rs_strncmp_ptr("abc", "abd", 3));
        assert_se(strncmp_ptr("a", "z", 1) == rs_strncmp_ptr("a", "z", 1));
        assert_se(strncmp_ptr("abc", "abcd", 4) == rs_strncmp_ptr("abc", "abcd", 4));
        assert_se(strncmp_ptr(NULL, NULL, 5) == rs_strncmp_ptr(NULL, NULL, 5));
        assert_se(strncmp_ptr(NULL, "abc", 5) == rs_strncmp_ptr(NULL, "abc", 5));
        assert_se(strncmp_ptr("abc", NULL, 5) == rs_strncmp_ptr("abc", NULL, 5));
}

static void test_strcasecmp_ptr(void) {
        assert_se(strcasecmp_ptr("Hello", "hello") == rs_strcasecmp_ptr("Hello", "hello"));
        assert_se(strcasecmp_ptr("abc", "ABD") == rs_strcasecmp_ptr("abc", "ABD"));
        assert_se(strcasecmp_ptr("Alpha", "zulu") == rs_strcasecmp_ptr("Alpha", "zulu"));
        assert_se(strcasecmp_ptr("abc", "ABCD") == rs_strcasecmp_ptr("abc", "ABCD"));
        assert_se(strcasecmp_ptr(NULL, NULL) == rs_strcasecmp_ptr(NULL, NULL));
        assert_se(strcasecmp_ptr(NULL, "abc") == rs_strcasecmp_ptr(NULL, "abc"));
        assert_se(strcasecmp_ptr("abc", NULL) == rs_strcasecmp_ptr("abc", NULL));
}

static void test_streq_ptr(void) {
        assert_se(streq_ptr("hello", "hello") == rs_streq_ptr("hello", "hello"));
        assert_se(streq_ptr("abc", "abd") == rs_streq_ptr("abc", "abd"));
        assert_se(streq_ptr(NULL, NULL) == rs_streq_ptr(NULL, NULL));
        assert_se(streq_ptr(NULL, "abc") == rs_streq_ptr(NULL, "abc"));
        assert_se(streq_ptr("abc", NULL) == rs_streq_ptr("abc", NULL));
}

static void test_strneq_ptr(void) {
        assert_se(strneq_ptr("hello", "hello", 5) == rs_strneq_ptr("hello", "hello", 5));
        assert_se(strneq_ptr("abc", "abd", 2) == rs_strneq_ptr("abc", "abd", 2));
        assert_se(strneq_ptr("abc", "abd", 3) == rs_strneq_ptr("abc", "abd", 3));
        assert_se(strneq_ptr(NULL, NULL, 5) == rs_strneq_ptr(NULL, NULL, 5));
}

static void test_strcaseeq_ptr(void) {
        assert_se(strcaseeq_ptr("Hello", "hello") == rs_strcaseeq_ptr("Hello", "hello"));
        assert_se(strcaseeq_ptr("abc", "ABD") == rs_strcaseeq_ptr("abc", "ABD"));
        assert_se(strcaseeq_ptr(NULL, NULL) == rs_strcaseeq_ptr(NULL, NULL));
}

static void test_strlen_ptr(void) {
        assert_se(strlen_ptr("hello") == rs_strlen_ptr("hello"));
        assert_se(strlen_ptr("") == rs_strlen_ptr(""));
        assert_se(strlen_ptr(NULL) == rs_strlen_ptr(NULL));
}

static void test_isempty(void) {
        assert_se(isempty(NULL) == rs_isempty(NULL));
        assert_se(isempty("") == rs_isempty(""));
        assert_se(isempty("hello") == rs_isempty("hello"));
}

static void test_strempty(void) {
        assert_se(strempty(NULL) != NULL);
        assert_se(rs_strempty(NULL) != NULL);
        assert_se(streq(strempty(NULL), rs_strempty(NULL)));
        assert_se(streq(strempty("hello"), rs_strempty("hello")));
        assert_se(streq(strempty(""), rs_strempty("")));
}

static void test_yes_no(void) {
        assert_se(streq(yes_no(true), rs_yes_no(true)));
        assert_se(streq(yes_no(false), rs_yes_no(false)));
}

static void test_on_off(void) {
        assert_se(streq(on_off(true), rs_on_off(true)));
        assert_se(streq(on_off(false), rs_on_off(false)));
}

static void test_comparison_operator(void) {
        assert_se(streq(comparison_operator(-1), rs_comparison_operator(-1)));
        assert_se(streq(comparison_operator(0), rs_comparison_operator(0)));
        assert_se(streq(comparison_operator(1), rs_comparison_operator(1)));
        assert_se(streq(comparison_operator(-42), rs_comparison_operator(-42)));
        assert_se(streq(comparison_operator(42), rs_comparison_operator(42)));
}

static void test_memory_startswith(void) {
        const char data[] = "hello world";
        /* Match at start */
        void *c_r = memory_startswith(data, 11, "hello");
        void *rs_r = rs_memory_startswith(data, 11, "hello");
        assert_se(c_r != NULL);
        assert_se(rs_r != NULL);
        assert_se(strcmp(c_r, rs_r) == 0);
        /* No match */
        c_r = memory_startswith(data, 11, "world");
        rs_r = rs_memory_startswith(data, 11, "world");
        assert_se(c_r == NULL);
        assert_se(rs_r == NULL);
        /* Buffer too short */
        c_r = memory_startswith(data, 3, "hello");
        rs_r = rs_memory_startswith(data, 3, "hello");
        assert_se(c_r == NULL);
        assert_se(rs_r == NULL);
        /* Empty token */
        c_r = memory_startswith(data, 11, "");
        rs_r = rs_memory_startswith(data, 11, "");
        assert_se(c_r != NULL);
        assert_se(rs_r != NULL);
}

static void test_ascii_isdigit(void) {
        assert_se(ascii_isdigit('0') == rs_ascii_isdigit('0'));
        assert_se(ascii_isdigit('9') == rs_ascii_isdigit('9'));
        assert_se(ascii_isdigit('a') == rs_ascii_isdigit('a'));
        assert_se(ascii_isdigit(' ') == rs_ascii_isdigit(' '));
        assert_se(ascii_isdigit(0) == rs_ascii_isdigit(0));
}

static void test_ascii_ishex(void) {
        assert_se(ascii_ishex('0') == rs_ascii_ishex('0'));
        assert_se(ascii_ishex('9') == rs_ascii_ishex('9'));
        assert_se(ascii_ishex('a') == rs_ascii_ishex('a'));
        assert_se(ascii_ishex('f') == rs_ascii_ishex('f'));
        assert_se(ascii_ishex('A') == rs_ascii_ishex('A'));
        assert_se(ascii_ishex('F') == rs_ascii_ishex('F'));
        assert_se(ascii_ishex('g') == rs_ascii_ishex('g'));
        assert_se(ascii_ishex(' ') == rs_ascii_ishex(' '));
}

static void test_ascii_isalpha(void) {
        assert_se(ascii_isalpha('a') == rs_ascii_isalpha('a'));
        assert_se(ascii_isalpha('z') == rs_ascii_isalpha('z'));
        assert_se(ascii_isalpha('A') == rs_ascii_isalpha('A'));
        assert_se(ascii_isalpha('Z') == rs_ascii_isalpha('Z'));
        assert_se(ascii_isalpha('0') == rs_ascii_isalpha('0'));
        assert_se(ascii_isalpha(' ') == rs_ascii_isalpha(' '));
}

int main(int argc, char **argv) {
        test_strcmp_ptr();
        test_strncmp_ptr();
        test_strcasecmp_ptr();
        test_streq_ptr();
        test_strneq_ptr();
        test_strcaseeq_ptr();
        test_strlen_ptr();
        test_isempty();
        test_strempty();
        test_yes_no();
        test_on_off();
        test_comparison_operator();
        test_memory_startswith();
        test_ascii_isdigit();
        test_ascii_ishex();
        test_ascii_isalpha();
        return 0;
}
