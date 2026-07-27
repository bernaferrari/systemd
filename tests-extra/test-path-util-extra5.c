/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "path-util.h"
#include "string-util.h"
#include "tests.h"

TEST(empty_or_root_basic) {
        assert_se(empty_or_root("/"));
        assert_se(empty_or_root(""));

        assert_se(!empty_or_root("/foo"));
        assert_se(!empty_or_root("bar"));
}

TEST(path_make_relative_basic) {
        _cleanup_free_ char *result = NULL;

        /* Child under parent */
        assert_se(path_make_relative("/a/b", "/a/b/c", &result) >= 0);
        assert_se(streq(result, "c"));
        result = mfree(result);

        /* Same path → empty */
        assert_se(path_make_relative("/a/b", "/a/b", &result) >= 0);
        assert_se(streq(result, "."));
        result = mfree(result);

        /* Child with multiple levels */
        assert_se(path_make_relative("/a", "/a/b/c/d", &result) >= 0);
        assert_se(streq(result, "b/c/d"));
        result = mfree(result);

        /* Unrelated paths → uses ../ */
        assert_se(path_make_relative("/a/b", "/x/y", &result) >= 0);
        assert_se(streq(result, "../../x/y"));
        result = mfree(result);
}

TEST(path_simplify_basic) {
        /* Double slashes removed, trailing slash removed */
        char p1[] = "/a//b///c/";
        assert_se(streq(path_simplify(p1), "/a/b/c"));

        /* /../ at beginning of absolute path is skipped */
        char p3[] = "/../a/";
        assert_se(streq(path_simplify(p3), "/a"));

        /* Root stays root */
        char p4[] = "/";
        assert_se(streq(path_simplify(p4), "/"));

        /* Already clean stays the same */
        char p5[] = "/a/b/c";
        assert_se(streq(path_simplify(p5), "/a/b/c"));

        /* Dot-only components are removed */
        char p6[] = "/a/./b/./c";
        assert_se(streq(path_simplify(p6), "/a/b/c"));
}

TEST(path_startswith_basic) {
        const char *r;

        r = path_startswith("/a/b/c", "/a/b");
        assert_se(r && streq(r, "c"));

        r = path_startswith("/a/b/c", "/a/b/c");
        assert_se(r && streq(r, ""));

        r = path_startswith("/a/b/c", "/x");
        assert_se(r == NULL);
}

TEST(path_extract_filename_basic) {
        _cleanup_free_ char *fn = NULL;
        int r;

        r = path_extract_filename("/path/to/file.txt", &fn);
        assert_se(r >= 0);
        assert_se(streq(fn, "file.txt"));
        fn = mfree(fn);

        r = path_extract_filename("/file.txt", &fn);
        assert_se(r >= 0);
        assert_se(streq(fn, "file.txt"));
        fn = mfree(fn);

        /* Root path → no filename */
        assert_se(path_extract_filename("/", &fn) < 0);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
