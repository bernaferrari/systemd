/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "pretty-print.h"
#include "tests.h"

TEST(terminal_urlify) {
        _cleanup_free_ char *ret = NULL;

        /* With empty text, url is used as text */
        ASSERT_OK(terminal_urlify("https://example.com", "", &ret));
        ASSERT_STREQ(ret, "https://example.com");

        ret = mfree(ret);

        /* With text, returns non-NULL (exact format depends on urlify_enabled()) */
        ASSERT_OK(terminal_urlify("https://example.com", "click here", &ret));
        ASSERT_NOT_NULL(ret);
}

TEST(terminal_urlify_path) {
        _cleanup_free_ char *ret = NULL;

        /* Empty path returns -EINVAL */
        ASSERT_EQ(terminal_urlify_path("", "path link", &ret), -EINVAL);

        /* Empty text uses path as text, returns non-NULL */
        ASSERT_OK(terminal_urlify_path("/some/path", "", &ret));
        ASSERT_NOT_NULL(ret);

        ret = mfree(ret);

        /* Non-empty path + text produces output */
        ASSERT_OK(terminal_urlify_path("/some/path", "path link", &ret));
        ASSERT_NOT_NULL(ret);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
