/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "web-util.h"
#include "tests.h"

TEST(http_url_is_valid) {
        assert_se(http_url_is_valid("http://example.com"));
        assert_se(http_url_is_valid("https://example.com/path"));
        assert_se(!http_url_is_valid(NULL));
        assert_se(!http_url_is_valid(""));
        assert_se(!http_url_is_valid("ftp://example.com"));
        assert_se(!http_url_is_valid("http://"));
}

TEST(file_url_is_valid) {
        assert_se(file_url_is_valid("file:///path/to/file"));
        assert_se(file_url_is_valid("file:/path"));
        assert_se(!file_url_is_valid(NULL));
        assert_se(!file_url_is_valid(""));
        assert_se(!file_url_is_valid("file:"));
}

TEST(documentation_url_is_valid) {
        assert_se(documentation_url_is_valid("http://example.com"));
        assert_se(documentation_url_is_valid("https://example.com/doc"));
        assert_se(documentation_url_is_valid("file:///usr/share/doc/foo"));
        assert_se(documentation_url_is_valid("man:systemd(1)"));
        assert_se(documentation_url_is_valid("info:coreutils"));
        assert_se(!documentation_url_is_valid(NULL));
        assert_se(!documentation_url_is_valid(""));
}

TEST(http_etag_is_valid) {
        assert_se(http_etag_is_valid("\"abc\""));
        assert_se(http_etag_is_valid("W/\"weak\""));
        assert_se(!http_etag_is_valid(NULL));
        assert_se(!http_etag_is_valid(""));
        assert_se(!http_etag_is_valid("noquotes"));
        assert_se(!http_etag_is_valid("\"missing_end"));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
