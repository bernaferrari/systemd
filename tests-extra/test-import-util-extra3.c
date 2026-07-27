/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "import-util.h"
#include "string-util.h"
#include "tests.h"

TEST(import_url_last_component) {
        _cleanup_free_ char *result = NULL;

        assert_se(import_url_last_component("https://example.com/foo", &result) >= 0);
        assert_se(streq(result, "foo"));
        result = mfree(result);

        assert_se(import_url_last_component("https://example.com/path/to/file.tar.xz", &result) >= 0);
        assert_se(streq(result, "file.tar.xz"));
        result = mfree(result);

        assert_se(import_url_last_component("https://example.com/a/b/c?query=1#frag", &result) >= 0);
        assert_se(streq(result, "c"));
        result = mfree(result);

        /* Trailing slash → no component */
        assert_se(import_url_last_component("https://example.com/", &result) == -EADDRNOTAVAIL);

        /* Invalid URL */
        assert_se(import_url_last_component("", &result) < 0);
        assert_se(import_url_last_component("noscheme", &result) < 0);
}

TEST(import_url_change_suffix) {
        _cleanup_free_ char *result = NULL;

        assert_se(import_url_change_suffix("https://example.com/foo.tar.xz", 1, "bar.tar.xz", &result) >= 0);
        assert_se(streq(result, "https://example.com/bar.tar.xz"));
        result = mfree(result);

        assert_se(import_url_change_suffix("https://example.com/a/b/c.tar", 0, "d.tar", &result) >= 0);
        assert_se(streq(result, "https://example.com/a/b/c.tar/d.tar"));
        result = mfree(result);
}

TEST(tar_strip_suffixes) {
        _cleanup_free_ char *result = NULL;

        assert_se(tar_strip_suffixes("foo.tar", &result) >= 0);
        assert_se(streq(result, "foo"));
        result = mfree(result);

        assert_se(tar_strip_suffixes("foo.tar.xz", &result) >= 0);
        assert_se(streq(result, "foo"));
        result = mfree(result);

        assert_se(tar_strip_suffixes("foo.tar.gz", &result) >= 0);
        assert_se(streq(result, "foo"));
        result = mfree(result);

        assert_se(tar_strip_suffixes("foo.tar.bz2", &result) >= 0);
        assert_se(streq(result, "foo"));
        result = mfree(result);

        assert_se(tar_strip_suffixes("foo.tar.zst", &result) >= 0);
        assert_se(streq(result, "foo"));
        result = mfree(result);

        assert_se(tar_strip_suffixes("foo.tgz", &result) >= 0);
        assert_se(streq(result, "foo"));
        result = mfree(result);

        /* No suffix → return full name */
        assert_se(tar_strip_suffixes("foo", &result) >= 0);
        assert_se(streq(result, "foo"));
}

TEST(raw_strip_suffixes) {
        _cleanup_free_ char *result = NULL;

        assert_se(raw_strip_suffixes("foo.raw", &result) >= 0);
        assert_se(streq(result, "foo"));
        result = mfree(result);

        assert_se(raw_strip_suffixes("foo.xz", &result) >= 0);
        assert_se(streq(result, "foo"));
        result = mfree(result);

        assert_se(raw_strip_suffixes("foo.qcow2", &result) >= 0);
        assert_se(streq(result, "foo"));
        result = mfree(result);

        assert_se(raw_strip_suffixes("foo.img", &result) >= 0);
        assert_se(streq(result, "foo"));
        result = mfree(result);

        assert_se(raw_strip_suffixes("foo.bin", &result) >= 0);
        assert_se(streq(result, "foo"));
        result = mfree(result);

        /* No suffix → return full name */
        assert_se(raw_strip_suffixes("foo", &result) >= 0);
        assert_se(streq(result, "foo"));
}

TEST(import_type_roundtrip) {
        for (int i = 0; i < _IMPORT_TYPE_MAX; i++) {
                const char *s = import_type_to_string(i);
                assert_se(s);
                assert_se(import_type_from_string(s) == i);
        }
}

TEST(import_verify_roundtrip) {
        for (int i = 0; i < _IMPORT_VERIFY_MAX; i++) {
                const char *s = import_verify_to_string(i);
                assert_se(s);
                assert_se(import_verify_from_string(s) == i);
        }
}

DEFINE_TEST_MAIN(LOG_DEBUG);
