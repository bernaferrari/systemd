/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "import-util.h"
#include "string-util.h"
#include "tests.h"

TEST(import_url_last_component) {
        _cleanup_free_ char *ret = NULL;
        int r;

        /* Simple URL */
        r = import_url_last_component("https://example.com/image.raw", &ret);
        assert_se(r >= 0);
        assert_se(streq(ret, "image.raw"));
        ret = mfree(ret);

        /* URL with path components */
        r = import_url_last_component("https://example.com/path/to/file.tar.xz", &ret);
        assert_se(r >= 0);
        assert_se(streq(ret, "file.tar.xz"));
        ret = mfree(ret);

        /* URL with query string */
        r = import_url_last_component("https://example.com/file.raw?query=1", &ret);
        assert_se(r >= 0);
        assert_se(streq(ret, "file.raw"));
        ret = mfree(ret);

        /* URL with fragment */
        r = import_url_last_component("https://example.com/file.raw#fragment", &ret);
        assert_se(r >= 0);
        assert_se(streq(ret, "file.raw"));
        ret = mfree(ret);

        /* URL with trailing slash - still returns last component */
        r = import_url_last_component("https://example.com/path/", &ret);
        assert_se(r >= 0);
        assert_se(streq(ret, "path"));
        ret = mfree(ret);

        /* URL with no path component (just host) */
        r = import_url_last_component("https://example.com", &ret);
        assert_se(r == -EADDRNOTAVAIL);
        ret = mfree(ret);

        /* Invalid URL (no protocol) */
        r = import_url_last_component("not-a-url", &ret);
        assert_se(r < 0);
        ret = mfree(ret);
}

TEST(import_url_change_suffix) {
        _cleanup_free_ char *ret = NULL;
        int r;

        /* Replace last component */
        r = import_url_change_suffix("https://example.com/image.raw", 1, "image.tar", &ret);
        assert_se(r >= 0);
        assert_se(streq(ret, "https://example.com/image.tar"));
        ret = mfree(ret);

        /* Drop last component, append suffix */
        r = import_url_change_suffix("https://example.com/path/to/file.raw", 1, "file.tar", &ret);
        assert_se(r >= 0);
        assert_se(streq(ret, "https://example.com/path/to/file.tar"));
        ret = mfree(ret);

        /* Just append (n_drop=0) */
        r = import_url_change_suffix("https://example.com/path/", 0, "file.raw", &ret);
        assert_se(r >= 0);
        assert_se(streq(ret, "https://example.com/path/file.raw"));
        ret = mfree(ret);

        /* Drop and don't append (suffix=NULL) */
        r = import_url_change_suffix("https://example.com/path/file.raw", 1, NULL, &ret);
        assert_se(r >= 0);
        assert_se(streq(ret, "https://example.com/path/"));
        ret = mfree(ret);

        /* URL with query - query is stripped */
        r = import_url_change_suffix("https://example.com/file.raw?query=1", 0, "new.raw", &ret);
        assert_se(r >= 0);
        assert_se(streq(ret, "https://example.com/file.raw/new.raw"));
        ret = mfree(ret);
}

TEST(import_url_change_last_component) {
        _cleanup_free_ char *ret = NULL;
        int r;

        r = import_url_change_last_component("https://example.com/image.raw", "image.tar", &ret);
        assert_se(r >= 0);
        assert_se(streq(ret, "https://example.com/image.tar"));
        ret = mfree(ret);
}

TEST(import_url_append_component) {
        _cleanup_free_ char *ret = NULL;
        int r;

        r = import_url_append_component("https://example.com/path/", "file.raw", &ret);
        assert_se(r >= 0);
        assert_se(streq(ret, "https://example.com/path/file.raw"));
        ret = mfree(ret);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
