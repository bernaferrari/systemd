/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "string-util.h"
#include "tests.h"

TEST(startswith_basic) {
        assert_se(startswith("foobar", "foo"));
        assert_se(startswith("foobar", ""));
        assert_se(!startswith("foobar", "bar"));
        assert_se(!startswith("foobar", "foobarbaz"));
}

TEST(endswith_basic) {
        assert_se(endswith("foobar", "bar"));
        assert_se(endswith("foobar", ""));
        assert_se(!endswith("foobar", "foo"));
        assert_se(!endswith("foobar", "bazfoobar"));
}

TEST(startswith_no_case_basic) {
        assert_se(startswith_no_case("FooBar", "foo"));
        assert_se(startswith_no_case("FooBar", "FOO"));
        assert_se(!startswith_no_case("FooBar", "bar"));
}

TEST(endswith_no_case_basic) {
        assert_se(endswith_no_case("FooBar", "BAR"));
        assert_se(endswith_no_case("FooBar", "bar"));
        assert_se(!endswith_no_case("FooBar", "foo"));
}

TEST(first_word_basic) {
        assert_se(first_word("hello world", "hello"));
        assert_se(first_word("hello\tworld", "hello"));
        assert_se(first_word("hello\nworld", "hello"));
        assert_se(!first_word("helloworld", "hello"));
        assert_se(!first_word("world hello", "hello"));
}

TEST(streq_ptr_basic) {
        assert_se(streq_ptr("foo", "foo"));
        assert_se(!streq_ptr("foo", "bar"));
        assert_se(!streq_ptr("foo", NULL));
        assert_se(!streq_ptr(NULL, "foo"));
        assert_se(streq_ptr(NULL, NULL));
}

TEST(strlen_ptr_basic) {
        assert_se(strlen_ptr("hello") == 5);
        assert_se(strlen_ptr("") == 0);
        assert_se(strlen_ptr(NULL) == 0);
}

TEST(isempty_basic) {
        assert_se(isempty(NULL));
        assert_se(isempty(""));
        assert_se(!isempty("a"));
}

TEST(yes_no_basic) {
        assert_se(streq(yes_no(true), "yes"));
        assert_se(streq(yes_no(false), "no"));
}

TEST(on_off_basic) {
        assert_se(streq(on_off(true), "on"));
        assert_se(streq(on_off(false), "off"));
}

TEST(in_charset_basic) {
        assert_se(in_charset("abc123", LETTERS DIGITS));
        assert_se(!in_charset("abc 123", LETTERS DIGITS));
        assert_se(in_charset("", LETTERS));
}

TEST(skip_leading_chars_basic) {
        assert_se(streq(skip_leading_chars("  hello", WHITESPACE), "hello"));
        assert_se(streq(skip_leading_chars("hello", WHITESPACE), "hello"));
        assert_se(streq(skip_leading_chars("   ", WHITESPACE), ""));
}

TEST(truncate_nl_basic) {
        char s[] = "hello\n";
        assert_se(streq(truncate_nl(s), "hello"));

        char s2[] = "hello\r\n";
        assert_se(streq(truncate_nl(s2), "hello"));

        char s3[] = "hello";
        assert_se(streq(truncate_nl(s3), "hello"));
}

TEST(strrstr_basic) {
        assert_se(streq(strrstr("hello world hello", "hello"), "hello"));
        assert_se(strrstr("hello world", "xyz") == NULL);
        assert_se(strrstr("hello", "hello") != NULL);
}

TEST(str_common_prefix_basic) {
        assert_se(str_common_prefix("foobar", "foobaz") == 5);
        assert_se(str_common_prefix("hello", "hello") == SIZE_MAX); /* identical → SIZE_MAX */
        assert_se(str_common_prefix("abc", "xyz") == 0);
        assert_se(str_common_prefix("", "abc") == 0);
}

TEST(string_is_safe_basic) {
        assert_se(string_is_safe("hello world"));
        assert_se(!string_is_safe("hello\x01world")); /* control char */
}

TEST(version_is_valid_basic) {
        assert_se(version_is_valid("1.0"));
        assert_se(version_is_valid("1.0.0"));
        assert_se(version_is_valid("123.456.789"));
        assert_se(!version_is_valid(""));
}

TEST(empty_or_dash_basic) {
        assert_se(empty_or_dash(NULL));
        assert_se(empty_or_dash(""));
        assert_se(empty_or_dash("-"));
        assert_se(!empty_or_dash("hello"));
}

TEST(empty_to_null_basic) {
        const char *e = "";
        const char *h = "hello";
        assert_se(empty_to_null(e) == NULL);
        assert_se(streq(empty_to_null(h), "hello"));
}

TEST(strcmp_ptr_basic) {
        assert_se(strcmp_ptr("abc", "abc") == 0);
        assert_se(strcmp_ptr("abc", "def") < 0);
        assert_se(strcmp_ptr("def", "abc") > 0);
        assert_se(strcmp_ptr(NULL, NULL) == 0);
        assert_se(strcmp_ptr(NULL, "abc") < 0);
        assert_se(strcmp_ptr("abc", NULL) > 0);
}

TEST(strlevenshtein_basic) {
        assert_se(strlevenshtein("hello", "hello") == 0);
        assert_se(strlevenshtein("", "") == 0);
        assert_se(strlevenshtein("abc", "") == 3);
        assert_se(strlevenshtein("", "abc") == 3);
        assert_se(strlevenshtein("kitten", "sitting") == 3);
}

TEST(chars_intersect_basic) {
        assert_se(chars_intersect("abc", "cde"));     /* 'c' in common */
        assert_se(!chars_intersect("abc", "xyz"));    /* no common chars */
        assert_se(!chars_intersect("", "abc"));
}

TEST(strspn_from_end_basic) {
        assert_se(strspn_from_end("hello123", DIGITS) == 3);
        assert_se(strspn_from_end("hello", DIGITS) == 0);
        assert_se(strspn_from_end("12345", DIGITS) == 5);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
