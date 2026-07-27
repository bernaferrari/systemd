/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "escape.h"
#include "tests.h"

TEST(cescape) {
        _cleanup_free_ char *escaped = NULL;
        /* No special chars */
        escaped = cescape("hello world");
        ASSERT_STREQ(escaped, "hello world");
        escaped = mfree(escaped);
        /* Tab */
        escaped = cescape("hello\tworld");
        ASSERT_STREQ(escaped, "hello\\tworld");
        escaped = mfree(escaped);
        /* Newline */
        escaped = cescape("line1\nline2");
        ASSERT_STREQ(escaped, "line1\\nline2");
        escaped = mfree(escaped);
        /* Backslash */
        escaped = cescape("back\\slash");
        ASSERT_STREQ(escaped, "back\\\\slash");
        escaped = mfree(escaped);
        /* Empty */
        escaped = cescape("");
        ASSERT_STREQ(escaped, "");
}

TEST(cunescape) {
        _cleanup_free_ char *unescaped = NULL;
        ssize_t r;
        /* No escapes */
        r = cunescape("hello world", 0, &unescaped);
        ASSERT_GE(r, 0);
        ASSERT_STREQ(unescaped, "hello world");
        unescaped = mfree(unescaped);
        /* Tab escape */
        r = cunescape("hello\\tworld", 0, &unescaped);
        ASSERT_GE(r, 0);
        ASSERT_STREQ(unescaped, "hello\tworld");
        unescaped = mfree(unescaped);
        /* Newline escape */
        r = cunescape("line1\\nline2", 0, &unescaped);
        ASSERT_GE(r, 0);
        ASSERT_STREQ(unescaped, "line1\nline2");
}

DEFINE_TEST_MAIN(LOG_DEBUG);
