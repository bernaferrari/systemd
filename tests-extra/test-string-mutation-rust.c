/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Shadow test: string mutation and compare-operator functions vs Rust */

#include <assert.h>
#include <string.h>
#include "tests.h"
#include "string-util.h"
#include "rust/string_util.h"

static void test_strstrip(void) {
        char a[] = "  hello world  ";
        char b[] = "  hello world  ";

        rs_strstrip(a);
        strstrip(b);
        assert_se(streq(a, b));

        /* NULL */
        assert_se(rs_strstrip(NULL) == strstrip(NULL));

        /* Already stripped */
        char c[] = "hello";
        char d[] = "hello";
        rs_strstrip(c);
        strstrip(d);
        assert_se(streq(c, d));
}

static void test_delete_chars(void) {
        char a[] = "he-llo wo-rld";
        char b[] = "he-llo wo-rld";

        rs_delete_chars(a, "-");
        delete_chars(b, "-");
        assert_se(streq(a, b));

        assert_se(rs_delete_chars(NULL, "-") == delete_chars(NULL, "-"));

        /* An explicitly empty reject set deletes nothing; only NULL defaults
         * to whitespace. Preserve arbitrary non-UTF-8 bytes. */
        char c[] = { ' ', (char) 0xff, 'x', 0 };
        char d[] = { ' ', (char) 0xff, 'x', 0 };
        rs_delete_chars(c, "");
        delete_chars(d, "");
        assert_se(memcmp(c, d, sizeof(c)) == 0);

        char alias_c[] = "abca";
        char alias_rs[] = "abca";
        delete_chars(alias_c, alias_c + 2);
        rs_delete_chars(alias_rs, alias_rs + 2);
        assert_se(streq(alias_c, alias_rs));
}

static void test_delete_trailing_chars(void) {
        char a[] = "hello...  ";
        char b[] = "hello...  ";

        rs_delete_trailing_chars(a, ".");
        delete_trailing_chars(b, ".");
        assert_se(streq(a, b));

        assert_se(rs_delete_trailing_chars(NULL, ".") == delete_trailing_chars(NULL, "."));

        char c[] = { 'x', (char) 0xff, ' ', 0 };
        char d[] = { 'x', (char) 0xff, ' ', 0 };
        rs_delete_trailing_chars(c, "");
        delete_trailing_chars(d, "");
        assert_se(memcmp(c, d, sizeof(c)) == 0);
}

static void test_truncate_nl_full(void) {
        char a[] = "hello\nworld";
        char b[] = "hello\nworld";
        size_t ra, rb;

        rs_truncate_nl_full(a, &ra);
        truncate_nl_full(b, &rb);
        assert_se(streq(a, b));
        assert_se(ra == rb);
}

static void test_ascii_strlower_upper(void) {
        char a[] = "Hello WORLD";
        char b[] = "Hello WORLD";

        rs_ascii_strlower(a);
        ascii_strlower(b);
        assert_se(streq(a, b));

        char c[] = "hello world";
        char d[] = "hello world";
        rs_ascii_strupper(c);
        ascii_strupper(d);
        assert_se(streq(c, d));
}

static void test_ascii_strlower_n(void) {
        char a[] = "HELLO world";
        char b[] = "HELLO world";

        rs_ascii_strlower_n(a, 5);
        ascii_strlower_n(b, 5);
        assert_se(streq(a, b));
}

static void test_first_word(void) {
        assert_se(first_word("hello world", "hello") == rs_first_word("hello world", "hello"));
        assert_se(first_word("hello", "hello") == rs_first_word("hello", "hello"));
        assert_se(first_word("helloworld", "hello") == rs_first_word("helloworld", "hello"));
        assert_se(first_word("hello world", "") == rs_first_word("hello world", ""));
}

static void test_string_truncate_lines(void) {
        char *c_r, *rs_r;

        assert_se(string_truncate_lines("line1\nline2\nline3", 2, &c_r) == rs_string_truncate_lines("line1\nline2\nline3", 2, &rs_r));
        assert_se(streq(c_r, rs_r));
        free(c_r);
        free(rs_r);

        /* All lines fit */
        assert_se(string_truncate_lines("hello\nworld", 10, &c_r) == rs_string_truncate_lines("hello\nworld", 10, &rs_r));
        assert_se(streq(c_r, rs_r));
        free(c_r);
        free(rs_r);

        /* NULL/empty */
        assert_se(string_truncate_lines("", 5, &c_r) == rs_string_truncate_lines("", 5, &rs_r));
}

static void test_string_extract_line(void) {
        char *c_r, *rs_r;

        assert_se(string_extract_line("line1\nline2\nline3", 0, &c_r) == rs_string_extract_line("line1\nline2\nline3", 0, &rs_r));
        assert_se(streq(c_r, rs_r));
        free(c_r);
        free(rs_r);

        assert_se(string_extract_line("line1\nline2\nline3", 2, &c_r) == rs_string_extract_line("line1\nline2\nline3", 2, &rs_r));
        assert_se(streq(c_r, rs_r));
        free(c_r);
        free(rs_r);

        assert_se(string_extract_line("line1\nline2\nline3", 5, &c_r) == rs_string_extract_line("line1\nline2\nline3", 5, &rs_r));
}

static void test_find_line_startswith(void) {
        assert_se(find_line_startswith_internal("aaa\nhello world\nbbb", "hello") ==
                  rs_find_line_startswith_internal("aaa\nhello world\nbbb", "hello"));
        assert_se(find_line_startswith_internal("aaa\nbbb", "hello") ==
                  rs_find_line_startswith_internal("aaa\nbbb", "hello"));
        assert_se(find_line_startswith_internal("hello", "hello") ==
                  rs_find_line_startswith_internal("hello", "hello"));
        assert_se(find_line_startswith_internal("", "") ==
                  rs_find_line_startswith_internal("", ""));
}

static void test_find_line_internal(void) {
        assert_se(find_line_internal("aaa\nhello there\nbbb", "hello") ==
                  rs_find_line_internal("aaa\nhello there\nbbb", "hello"));
        assert_se(find_line_internal("aaa\nbbb", "hello") ==
                  rs_find_line_internal("aaa\nbbb", "hello"));
}

static void test_find_line_after(void) {
        assert_se(find_line_after_internal("aaa\n  hello there\nbbb", "hello") ==
                  rs_find_line_after_internal("aaa\n  hello there\nbbb", "hello"));
        assert_se(find_line_after_internal("aaa\nbbb", "hello") ==
                  rs_find_line_after_internal("aaa\nbbb", "hello"));
}

static void test_string_contains_word_strv(void) {
        char * const words[] = { (char*)"hello", (char*)"world", NULL };
        char * const empty_word[] = { (char*)"", NULL };
        const char *found_c, *found_rs;

        assert_se(string_contains_word_strv("this is hello and world", " ", words, &found_c) ==
                  rs_string_contains_word_strv("this is hello and world", " ", words, &found_rs));
        assert_se(streq_ptr(found_c, found_rs));

        assert_se(string_contains_word_strv("no match here", " ", words, &found_c) ==
                  rs_string_contains_word_strv("no match here", " ", words, &found_rs));
        assert_se(found_c == NULL);
        assert_se(found_rs == NULL);

        /* Explicit separators do not coalesce, so the empty field is visible. */
        assert_se(string_contains_word_strv("a,,b", ",", empty_word, &found_c) ==
                  rs_string_contains_word_strv("a,,b", ",", empty_word, &found_rs));
        assert_se(streq_ptr(found_c, found_rs));
}

int main(int argc, char **argv) {
        test_strstrip();
        test_delete_chars();
        test_delete_trailing_chars();
        test_truncate_nl_full();
        test_ascii_strlower_upper();
        test_ascii_strlower_n();
        test_first_word();
        test_string_truncate_lines();
        test_string_extract_line();
        test_find_line_startswith();
        test_find_line_internal();
        test_find_line_after();
        test_string_contains_word_strv();
        return 0;
}
