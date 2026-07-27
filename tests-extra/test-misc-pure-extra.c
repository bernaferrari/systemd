/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "errno-list.h"
#include "tests.h"
#include "web-util.h"

/* errno_is_valid is a static inline, so test it directly */
TEST(errno_is_valid_basic) {
        /* Positive errno values are valid */
        assert_se(errno_is_valid(1));
        assert_se(errno_is_valid(EPERM));
        assert_se(errno_is_valid(ENOMEM));
        assert_se(errno_is_valid(EINVAL));

        /* Zero is not valid */
        assert_se(!errno_is_valid(0));

        /* Negative is not valid */
        assert_se(!errno_is_valid(-1));
        assert_se(!errno_is_valid(-EPERM));

        /* Max valid */
        assert_se(errno_is_valid(ERRNO_MAX));
        assert_se(!errno_is_valid(ERRNO_MAX + 1));
}

TEST(file_url_is_valid_basic) {
        /* Valid file URLs */
        assert_se(file_url_is_valid("file:///path/to/file"));
        assert_se(file_url_is_valid("file:///tmp/test"));
        assert_se(file_url_is_valid("file://"));

        /* Missing slashes after file: */
        assert_se(!file_url_is_valid("file:"));

        /* Must have at least file:/ */
        assert_se(!file_url_is_valid("file"));

        /* Not a file URL */
        assert_se(!file_url_is_valid("http://example.com"));
        assert_se(!file_url_is_valid("https://example.com"));
        assert_se(!file_url_is_valid("ftp://example.com"));

        /* Empty */
        assert_se(!file_url_is_valid(""));
        assert_se(!file_url_is_valid(NULL));
}

TEST(documentation_url_is_valid_basic) {
        /* Valid documentation URLs */
        assert_se(documentation_url_is_valid("https://example.com"));
        assert_se(documentation_url_is_valid("http://example.com"));
        assert_se(documentation_url_is_valid("https://example.com/path"));
        assert_se(documentation_url_is_valid("info:bar"));
        assert_se(documentation_url_is_valid("file:///path"));
        assert_se(documentation_url_is_valid("file:///tmp/test"));
        assert_se(documentation_url_is_valid("man:systemd(1)"));

        /* Empty */
        assert_se(!documentation_url_is_valid(""));
        assert_se(!documentation_url_is_valid(NULL));
}

TEST(http_etag_is_valid_basic) {
        /* Simple quoted ETag */
        assert_se(http_etag_is_valid("\"abc\""));

        /* Empty quoted ETag */
        assert_se(http_etag_is_valid("\"\""));

        /* ETag with special chars inside quotes */
        assert_se(http_etag_is_valid("\"foo-bar\""));
        assert_se(http_etag_is_valid("\"12345\""));

        /* Weak ETag */
        assert_se(http_etag_is_valid("W/\"abc\""));
        assert_se(http_etag_is_valid("W/\"\""));

        /* Missing closing quote */
        assert_se(!http_etag_is_valid("\"abc"));

        /* Missing opening quote */
        assert_se(!http_etag_is_valid("abc\""));

        /* No quotes at all */
        assert_se(!http_etag_is_valid("abc"));

        /* Empty */
        assert_se(!http_etag_is_valid(""));
        assert_se(!http_etag_is_valid(NULL));
}

DEFINE_TEST_MAIN(LOG_INFO);
