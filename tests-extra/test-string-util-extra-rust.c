/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Shadow test: additional string-util functions vs Rust */

#include <assert.h>
#include <stdint.h>
#include <string.h>
#include "tests.h"
#include "string-util.h"
#include "rust/string_util.h"

static void test_in_charset(void) {
        assert_se(in_charset("abc", "abc") == rs_in_charset("abc", "abc"));
        assert_se(in_charset("abc", "abcd") == rs_in_charset("abc", "abcd"));
        assert_se(in_charset("abc", "ab") == rs_in_charset("abc", "ab"));
        assert_se(in_charset("", "abc") == rs_in_charset("", "abc"));
        assert_se(in_charset("123", "0123456789") == rs_in_charset("123", "0123456789"));
        assert_se(in_charset("abc", "") == rs_in_charset("abc", ""));
}

static void test_char_is_cc(void) {
        assert_se(char_is_cc('\0') == rs_char_is_cc('\0'));
        assert_se(char_is_cc('\n') == rs_char_is_cc('\n'));
        assert_se(char_is_cc('\t') == rs_char_is_cc('\t'));
        assert_se(char_is_cc(' ') == rs_char_is_cc(' '));
        assert_se(char_is_cc(127) == rs_char_is_cc(127));
        assert_se(char_is_cc('a') == rs_char_is_cc('a'));
        assert_se(char_is_cc('Z') == rs_char_is_cc('Z'));
        assert_se(char_is_cc('~') == rs_char_is_cc('~'));
        assert_se(char_is_cc((char) 0x80) == rs_char_is_cc((char) 0x80));
        assert_se(char_is_cc((char) 0xff) == rs_char_is_cc((char) 0xff));
}

static void test_strshorten(void) {
        char buf1[] = "hello";
        char buf2[] = "hello";

        assert_se(streq(rs_strshorten(buf1, 3), strshorten(buf2, 3)));
        assert_se(streq(buf1, buf2));

        /* Already short enough */
        char buf3[] = "hi";
        char buf4[] = "hi";
        assert_se(streq(rs_strshorten(buf3, 10), strshorten(buf4, 10)));
        assert_se(streq(buf3, buf4));

        assert_se(streq(rs_strshorten(buf3, SIZE_MAX), strshorten(buf4, SIZE_MAX)));
        assert_se(streq(rs_strshorten(buf3, SIZE_MAX - 1), strshorten(buf4, SIZE_MAX - 1)));
}

static void test_strrstr_internal(void) {
        assert_se(rs_strrstr_internal("hello world hello", "hello") == strrstr_internal("hello world hello", "hello"));
        assert_se(rs_strrstr_internal("hello", "hello") == strrstr_internal("hello", "hello"));
        assert_se(rs_strrstr_internal("hello", "xyz") == strrstr_internal("hello", "xyz"));
        assert_se(rs_strrstr_internal("hello", "") == strrstr_internal("hello", ""));
        assert_se(rs_strrstr_internal(NULL, "a") == strrstr_internal(NULL, "a"));
        assert_se(rs_strrstr_internal("a", NULL) == strrstr_internal("a", NULL));
        assert_se(rs_strrstr_internal(NULL, NULL) == strrstr_internal(NULL, NULL));
        assert_se(rs_strrstr_internal("", "") == strrstr_internal("", ""));
        assert_se(rs_strrstr_internal("aaa", "aa") == strrstr_internal("aaa", "aa"));
}

static void test_strlevenshtein(void) {
        assert_se(rs_strlevenshtein("kitten", "sitting") == strlevenshtein("kitten", "sitting"));
        assert_se(rs_strlevenshtein("", "") == strlevenshtein("", ""));
        assert_se(rs_strlevenshtein("a", "") == strlevenshtein("a", ""));
        assert_se(rs_strlevenshtein("", "a") == strlevenshtein("", "a"));
        assert_se(rs_strlevenshtein("abc", "abc") == strlevenshtein("abc", "abc"));
        assert_se(rs_strlevenshtein("abc", "axc") == strlevenshtein("abc", "axc"));
        assert_se(rs_strlevenshtein(NULL, NULL) == strlevenshtein(NULL, NULL));
        assert_se(rs_strlevenshtein(NULL, "abc") == strlevenshtein(NULL, "abc"));
        assert_se(rs_strlevenshtein("abc", NULL) == strlevenshtein("abc", NULL));

        /* Test Damerau-Levenshtein (transposition) */
        assert_se(rs_strlevenshtein("ca", "ac") == strlevenshtein("ca", "ac"));
        assert_se(rs_strlevenshtein("ab", "ba") == strlevenshtein("ab", "ba"));
        assert_se(rs_strlevenshtein("\xc3\xa9", "e") == strlevenshtein("\xc3\xa9", "e"));
}

static void test_version_is_valid(void) {
        assert_se(version_is_valid("1.0", 0) == rs_version_is_valid("1.0", 0));
        assert_se(version_is_valid("1.0~rc1^5", 0) == rs_version_is_valid("1.0~rc1^5", 0));
        assert_se(version_is_valid("1_2", 0) == rs_version_is_valid("1_2", 0));
        assert_se(version_is_valid("1_2", VERSION_ALLOW_UNDERSCORE) == rs_version_is_valid("1_2", VERSION_ALLOW_UNDERSCORE));
        assert_se(version_is_valid("1+2", VERSION_ALLOW_PLUS) == rs_version_is_valid("1+2", VERSION_ALLOW_PLUS));
        assert_se(version_is_valid("1_2+3", VERSION_ALLOW_UNDERSCORE|VERSION_ALLOW_PLUS) == rs_version_is_valid("1_2+3", VERSION_ALLOW_UNDERSCORE|VERSION_ALLOW_PLUS));
        assert_se(version_is_valid("", 0) == rs_version_is_valid("", 0));
        assert_se(version_is_valid("", VERSION_ALLOW_EMPTY) == rs_version_is_valid("", VERSION_ALLOW_EMPTY));
        assert_se(version_is_valid(NULL, VERSION_ALLOW_EMPTY) == rs_version_is_valid(NULL, VERSION_ALLOW_EMPTY));
        assert_se(version_is_valid("1 0", VERSION_ALLOW_UNDERSCORE|VERSION_ALLOW_PLUS) == rs_version_is_valid("1 0", VERSION_ALLOW_UNDERSCORE|VERSION_ALLOW_PLUS));
        assert_se(version_is_valid("1/2", VERSION_ALLOW_UNDERSCORE|VERSION_ALLOW_PLUS) == rs_version_is_valid("1/2", VERSION_ALLOW_UNDERSCORE|VERSION_ALLOW_PLUS));
}

int main(int argc, char **argv) {
        test_in_charset();
        test_char_is_cc();
        test_strshorten();
        test_strrstr_internal();
        test_strlevenshtein();
        test_version_is_valid();
        return 0;
}
