/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Shadow test: C strreplace vs Rust */

#include "tests.h"
#include "string-util.h"
#include "rust/string_util.h"

static void test_strreplace(void) {
        _cleanup_free_ char *cr = NULL, *rr = NULL;

        /* NULL text */
        cr = strreplace(NULL, "a", "b");
        rr = rs_strreplace(NULL, "a", "b");
        assert_se(cr == NULL);
        assert_se(rr == NULL);

        /* No occurrences */
        cr = strreplace("hello world", "x", "y");
        rr = rs_strreplace("hello world", "x", "y");
        assert_se(cr && rr);
        assert_se(streq(cr, rr));
        cr = mfree(cr); rr = mfree(rr);

        /* Single occurrence */
        cr = strreplace("hello world", "world", "earth");
        rr = rs_strreplace("hello world", "world", "earth");
        assert_se(cr && rr);
        assert_se(streq(cr, rr));
        assert_se(streq(rr, "hello earth"));
        cr = mfree(cr); rr = mfree(rr);

        /* Multiple occurrences */
        cr = strreplace("aaa", "a", "bb");
        rr = rs_strreplace("aaa", "a", "bb");
        assert_se(cr && rr);
        assert_se(streq(cr, rr));
        assert_se(streq(rr, "bbbbbb"));
        cr = mfree(cr); rr = mfree(rr);

        /* At start */
        cr = strreplace("foobar", "foo", "baz");
        rr = rs_strreplace("foobar", "foo", "baz");
        assert_se(cr && rr);
        assert_se(streq(cr, rr));
        assert_se(streq(rr, "bazbar"));
        cr = mfree(cr); rr = mfree(rr);

        /* At end */
        cr = strreplace("foobar", "bar", "baz");
        rr = rs_strreplace("foobar", "bar", "baz");
        assert_se(cr && rr);
        assert_se(streq(cr, rr));
        assert_se(streq(rr, "foobaz"));
        cr = mfree(cr); rr = mfree(rr);

        /* Shrinking: new shorter than old */
        cr = strreplace("aaabbb", "aaa", "x");
        rr = rs_strreplace("aaabbb", "aaa", "x");
        assert_se(cr && rr);
        assert_se(streq(cr, rr));
        assert_se(streq(rr, "xbbb"));
        cr = mfree(cr); rr = mfree(rr);

        /* Growing: new longer than old */
        cr = strreplace("abc", "b", "XXXX");
        rr = rs_strreplace("abc", "b", "XXXX");
        assert_se(cr && rr);
        assert_se(streq(cr, rr));
        assert_se(streq(rr, "aXXXXc"));
        cr = mfree(cr); rr = mfree(rr);

        /* Empty text */
        cr = strreplace("", "a", "b");
        rr = rs_strreplace("", "a", "b");
        assert_se(cr && rr);
        assert_se(streq(cr, rr));
        assert_se(streq(rr, ""));
        cr = mfree(cr); rr = mfree(rr);

        /* Replace with empty string */
        cr = strreplace("abc", "b", "");
        rr = rs_strreplace("abc", "b", "");
        assert_se(cr && rr);
        assert_se(streq(cr, rr));
        assert_se(streq(rr, "ac"));
        cr = mfree(cr); rr = mfree(rr);

        /* Multi-char old_string */
        cr = strreplace("ababab", "ab", "XY");
        rr = rs_strreplace("ababab", "ab", "XY");
        assert_se(cr && rr);
        assert_se(streq(cr, rr));
        assert_se(streq(rr, "XYXYXY"));
        cr = mfree(cr); rr = mfree(rr);

        /* Overlapping: "aaa" replace "aa" — C advances past match */
        cr = strreplace("aaa", "aa", "X");
        rr = rs_strreplace("aaa", "aa", "X");
        assert_se(cr && rr);
        assert_se(streq(cr, rr));
        assert_se(streq(rr, "Xa"));
        cr = mfree(cr); rr = mfree(rr);

        /* specifier_escape use case: percent escaping */
        cr = strreplace("100%", "%", "%%");
        rr = rs_strreplace("100%", "%", "%%");
        assert_se(cr && rr);
        assert_se(streq(cr, rr));
        assert_se(streq(rr, "100%%"));
        cr = mfree(cr); rr = mfree(rr);

        cr = strreplace("%CPU%MEM%IOW", "%", "%%");
        rr = rs_strreplace("%CPU%MEM%IOW", "%", "%%");
        assert_se(cr && rr);
        assert_se(streq(cr, rr));
        assert_se(streq(rr, "%%CPU%%MEM%%IOW"));
        cr = mfree(cr); rr = mfree(rr);

        /* Replace entire string */
        cr = strreplace("abc", "abc", "XYZ");
        rr = rs_strreplace("abc", "abc", "XYZ");
        assert_se(cr && rr);
        assert_se(streq(cr, rr));
        assert_se(streq(rr, "XYZ"));
        cr = mfree(cr); rr = mfree(rr);

        /* old_string same as new_string (identity) */
        cr = strreplace("hello", "ell", "ell");
        rr = rs_strreplace("hello", "ell", "ell");
        assert_se(cr && rr);
        assert_se(streq(cr, rr));
        assert_se(streq(rr, "hello"));
        cr = mfree(cr); rr = mfree(rr);
}

int main(int argc, char **argv) {
        test_strreplace();
        return 0;
}
