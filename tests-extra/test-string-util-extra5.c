/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "string-util.h"
#include "tests.h"

TEST(strreplace_basic) {
        _cleanup_free_ char *result = NULL;

        /* Simple replacement */
        result = strreplace("hello world", "world", "there");
        assert_se(result);
        assert_se(streq(result, "hello there"));
        result = mfree(result);

        /* No match → returns copy of original */
        result = strreplace("hello world", "foo", "bar");
        assert_se(result);
        assert_se(streq(result, "hello world"));
        result = mfree(result);

        /* Multiple occurrences → replaces all */
        result = strreplace("aaa", "a", "b");
        assert_se(result);
        assert_se(streq(result, "bbb"));
        result = mfree(result);
}

TEST(string_erase_basic) {
        char x[] = "secret data here";

        string_erase(x);
        /* After erase, string should be all zeros */
        assert_se(x[0] == '\0');

        /* NULL is safe */
        assert_se(string_erase(NULL) == NULL);
}

TEST(string_replace_char_basic) {
        char s[] = "hello world";

        string_replace_char(s, 'o', '0');
        assert_se(streq(s, "hell0 w0rld"));
}

TEST(strstrip_basic) {
        char s1[] = "   hello world   ";
        assert_se(streq(strstrip(s1), "hello world"));

        char s2[] = "\t\nhello\t\n";
        assert_se(streq(strstrip(s2), "hello"));

        char s3[] = "nochange";
        assert_se(streq(strstrip(s3), "nochange"));
}

TEST(delete_chars_basic) {
        char s[] = "hello world";
        delete_chars(s, "ol");
        /* 'l', 'o' chars should be removed */
        assert_se(streq(s, "he wrd"));
}

TEST(ascii_strlower_basic) {
        char s[] = "HELLO World 123";
        ascii_strlower(s);
        assert_se(streq(s, "hello world 123"));
}

TEST(ascii_strupper_basic) {
        char s[] = "hello world 123";
        ascii_strupper(s);
        assert_se(streq(s, "HELLO WORLD 123"));
}

TEST(strrep_basic) {
        _cleanup_free_ char *r = NULL;

        r = strrep("abc", 3);
        assert_se(r);
        assert_se(streq(r, "abcabcabc"));
}

TEST(strdupspn_basic) {
        _cleanup_free_ char *r = NULL;

        r = strdupspn("hello world", "abcdefghijklmnopqrstuvwxyz");
        assert_se(r);
        assert_se(streq(r, "hello"));

        r = mfree(r);
        r = strdupspn("123abc", DIGITS);
        assert_se(r);
        assert_se(streq(r, "123"));
}

TEST(split_pair_basic) {
        _cleanup_free_ char *left = NULL, *right = NULL;
        int r;

        r = split_pair("key=value", "=", &left, &right);
        assert_se(r >= 0);
        assert_se(streq(left, "key"));
        assert_se(streq(right, "value"));
        left = mfree(left);
        right = mfree(right);

        /* Multiple separators → split at first */
        r = split_pair("a=b=c", "=", &left, &right);
        assert_se(r >= 0);
        assert_se(streq(left, "a"));
        assert_se(streq(right, "b=c"));
        left = mfree(left);
        right = mfree(right);

        /* No separator → error */
        assert_se(split_pair("noequals", "=", &left, &right) == -EINVAL);
}

TEST(strshorten_basic) {
        char s1[] = "hello world";
        strshorten(s1, 5);
        assert_se(streq(s1, "hello"));

        /* Short enough → no change */
        char s2[] = "hi";
        strshorten(s2, 10);
        assert_se(streq(s2, "hi"));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
