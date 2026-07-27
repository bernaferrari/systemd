/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Shadow test: path_equal, path_startswith, path_is_valid, path_is_safe,
 * filename_or_absolute_path_is_valid, skip_dev_prefix, path_simplify,
 * path_startswith_strv, path_strv_contains, prefixed_path_strv_contains,
 * path_split_prefix_filename, path_extract_filename, path_extract_directory,
 * path_compare_filename, path_equal_filename */

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include "tests.h"
#include "path-util.h"
#include "rust/path_util.h"

static void test_path_equal(void) {
        assert_se(path_equal("/foo/bar", "/foo/bar") == rs_path_equal("/foo/bar", "/foo/bar"));
        assert_se(path_equal("/foo/bar", "/foo/baz") == rs_path_equal("/foo/bar", "/foo/baz"));
        assert_se(path_equal("/foo", "/foo/") == rs_path_equal("/foo", "/foo/"));
        assert_se(path_equal("/", "/") == rs_path_equal("/", "/"));
        assert_se(path_equal(NULL, NULL) == rs_path_equal(NULL, NULL));
        assert_se(path_equal("/a", "/b") == rs_path_equal("/a", "/b"));
        assert_se(path_equal("foo", "bar") == rs_path_equal("foo", "bar"));
        assert_se(path_equal(NULL, "/a") == rs_path_equal(NULL, "/a"));
}

static void test_path_startswith(void) {
        char *c_r, *rs_r;

        c_r = path_startswith("/foo/bar", "/foo");
        rs_r = rs_path_startswith("/foo/bar", "/foo");
        assert_se(c_r && rs_r && streq(c_r, rs_r));

        c_r = path_startswith("/foo/bar", "/foo/");
        rs_r = rs_path_startswith("/foo/bar", "/foo/");
        assert_se(c_r && rs_r && streq(c_r, rs_r));

        c_r = path_startswith("/foo", "/foo");
        rs_r = rs_path_startswith("/foo", "/foo");
        assert_se(c_r && rs_r && streq(c_r, rs_r));

        c_r = path_startswith("/foo", "/bar");
        rs_r = rs_path_startswith("/foo", "/bar");
        assert_se(c_r == NULL && rs_r == NULL);

        c_r = path_startswith("/foo/bar", "/foo/bar/baz");
        rs_r = rs_path_startswith("/foo/bar", "/foo/bar/baz");
        assert_se(c_r == NULL && rs_r == NULL);
}

static void test_path_is_valid(void) {
        assert_se(path_is_valid("/foo/bar") == rs_path_is_valid("/foo/bar"));
        assert_se(path_is_valid("/foo/../bar") == rs_path_is_valid("/foo/../bar"));
        assert_se(path_is_valid("foo/bar") == rs_path_is_valid("foo/bar"));
        assert_se(path_is_valid("") == rs_path_is_valid(""));
        assert_se(path_is_valid("/") == rs_path_is_valid("/"));
        assert_se(path_is_valid(NULL) == rs_path_is_valid(NULL));
        assert_se(path_is_valid("///") == rs_path_is_valid("///"));
}

static void test_path_is_safe(void) {
        assert_se(path_is_safe("/foo/bar") == rs_path_is_safe("/foo/bar"));
        assert_se(path_is_safe("/foo/../bar") == rs_path_is_safe("/foo/../bar"));
        assert_se(path_is_safe("/foo") == rs_path_is_safe("/foo"));
        assert_se(path_is_safe(NULL) == rs_path_is_safe(NULL));
}

static void test_filename_or_absolute_path_is_valid(void) {
        assert_se(filename_or_absolute_path_is_valid("hello.txt") == rs_filename_or_absolute_path_is_valid("hello.txt"));
        assert_se(filename_or_absolute_path_is_valid("/foo/bar") == rs_filename_or_absolute_path_is_valid("/foo/bar"));
        assert_se(filename_or_absolute_path_is_valid(".") == rs_filename_or_absolute_path_is_valid("."));
        assert_se(filename_or_absolute_path_is_valid("") == rs_filename_or_absolute_path_is_valid(""));
        assert_se(filename_or_absolute_path_is_valid(NULL) == rs_filename_or_absolute_path_is_valid(NULL));
        assert_se(filename_or_absolute_path_is_valid("..") == rs_filename_or_absolute_path_is_valid(".."));
}

static void test_skip_dev_prefix(void) {
        const char *c_r, *rs_r;

        c_r = skip_dev_prefix("/dev/sda");
        rs_r = rs_skip_dev_prefix("/dev/sda");
        assert_se(streq(c_r, rs_r));

        c_r = skip_dev_prefix("/dev/null");
        rs_r = rs_skip_dev_prefix("/dev/null");
        assert_se(streq(c_r, rs_r));

        c_r = skip_dev_prefix("/foo/bar");
        rs_r = rs_skip_dev_prefix("/foo/bar");
        assert_se(streq(c_r, rs_r));

        c_r = skip_dev_prefix("dev/sda");
        rs_r = rs_skip_dev_prefix("dev/sda");
        assert_se(streq(c_r, rs_r));

        c_r = skip_dev_prefix("/dev/");
        rs_r = rs_skip_dev_prefix("/dev/");
        assert_se(streq(c_r, rs_r));
}

static void test_path_simplify(void) {
        char c_buf[256], rs_buf[256];

        strcpy(c_buf, "/foo//bar/../baz");
        strcpy(rs_buf, "/foo//bar/../baz");
        path_simplify(c_buf);
        rs_path_simplify(rs_buf);
        assert_se(streq(c_buf, rs_buf));

        strcpy(c_buf, "/foo/./bar");
        strcpy(rs_buf, "/foo/./bar");
        path_simplify(c_buf);
        rs_path_simplify(rs_buf);
        assert_se(streq(c_buf, rs_buf));

        strcpy(c_buf, "/");
        strcpy(rs_buf, "/");
        path_simplify(c_buf);
        rs_path_simplify(rs_buf);
        assert_se(streq(c_buf, rs_buf));

        strcpy(c_buf, "//");
        strcpy(rs_buf, "//");
        path_simplify(c_buf);
        rs_path_simplify(rs_buf);
        assert_se(streq(c_buf, rs_buf));

        strcpy(c_buf, "foo/bar/baz");
        strcpy(rs_buf, "foo/bar/baz");
        path_simplify(c_buf);
        rs_path_simplify(rs_buf);
        assert_se(streq(c_buf, rs_buf));
}

static void test_path_startswith_strv(void) {
        char *arr[] = { (char*)"/foo", (char*)"/bar", NULL };
        char *c_r, *rs_r;

        c_r = path_startswith_strv("/foo/bar", arr);
        rs_r = rs_path_startswith_strv("/foo/bar", arr);
        assert_se(c_r && rs_r && streq(c_r, rs_r));

        c_r = path_startswith_strv("/bar/baz", arr);
        rs_r = rs_path_startswith_strv("/bar/baz", arr);
        assert_se(c_r && rs_r && streq(c_r, rs_r));

        c_r = path_startswith_strv("/baz/qux", arr);
        rs_r = rs_path_startswith_strv("/baz/qux", arr);
        assert_se(c_r == NULL && rs_r == NULL);

        /* NULL strv */
        c_r = path_startswith_strv("/foo", NULL);
        rs_r = rs_path_startswith_strv("/foo", NULL);
        assert_se(c_r == NULL && rs_r == NULL);
}

static void test_path_strv_contains(void) {
        char *arr[] = { (char*)"/foo", (char*)"/bar/baz", NULL };

        assert_se(path_strv_contains(arr, "/foo") == rs_path_strv_contains(arr, "/foo"));
        assert_se(path_strv_contains(arr, "/bar/baz") == rs_path_strv_contains(arr, "/bar/baz"));
        assert_se(path_strv_contains(arr, "/bar") == rs_path_strv_contains(arr, "/bar"));
        assert_se(path_strv_contains(NULL, "/foo") == rs_path_strv_contains(NULL, "/foo"));
}

static void test_prefixed_path_strv_contains(void) {
        char *arr[] = { (char*)"/foo", (char*)"-/bar", (char*)"+/baz", NULL };

        assert_se(prefixed_path_strv_contains(arr, "/foo") == rs_prefixed_path_strv_contains(arr, "/foo"));
        assert_se(prefixed_path_strv_contains(arr, "/bar") == rs_prefixed_path_strv_contains(arr, "/bar"));
        assert_se(prefixed_path_strv_contains(arr, "/baz") == rs_prefixed_path_strv_contains(arr, "/baz"));
        assert_se(prefixed_path_strv_contains(arr, "/qux") == rs_prefixed_path_strv_contains(arr, "/qux"));
        assert_se(prefixed_path_strv_contains(NULL, "/foo") == rs_prefixed_path_strv_contains(NULL, "/foo"));
}

static void test_path_split_prefix_filename(void) {
        char *c_dir = NULL, *rs_dir = NULL;
        char *c_fn = NULL, *rs_fn = NULL;
        int c_ret, rs_ret;

        /* Simple absolute path */
        c_ret = path_split_prefix_filename("/foo/bar/baz", &c_dir, &c_fn);
        rs_ret = rs_path_split_prefix_filename("/foo/bar/baz", &rs_dir, &rs_fn);
        assert_se(c_ret == rs_ret);
        assert_se(c_dir && rs_dir && streq(c_dir, rs_dir));
        assert_se(c_fn && rs_fn && streq(c_fn, rs_fn));
        free(c_dir); c_dir = NULL;
        free(rs_dir); rs_dir = NULL;
        free(c_fn); c_fn = NULL;
        free(rs_fn); rs_fn = NULL;

        /* Root path */
        c_ret = path_split_prefix_filename("/", &c_dir, &c_fn);
        rs_ret = rs_path_split_prefix_filename("/", &rs_dir, &rs_fn);
        assert_se(c_ret == rs_ret);
        free(c_dir); c_dir = NULL;
        free(rs_dir); rs_dir = NULL;
        free(c_fn); c_fn = NULL;
        free(rs_fn); rs_fn = NULL;

        /* Filename only */
        c_ret = path_split_prefix_filename("hello.txt", &c_dir, &c_fn);
        rs_ret = rs_path_split_prefix_filename("hello.txt", &rs_dir, &rs_fn);
        assert_se(c_ret == rs_ret);
        assert_se(c_fn && rs_fn && streq(c_fn, rs_fn));
        free(c_dir); c_dir = NULL;
        free(rs_dir); rs_dir = NULL;
        free(c_fn); c_fn = NULL;
        free(rs_fn); rs_fn = NULL;

        /* A trailing slash is the native O_DIRECTORY value, not a sentinel. */
        c_ret = path_split_prefix_filename("/foo/bar/", &c_dir, &c_fn);
        rs_ret = rs_path_split_prefix_filename("/foo/bar/", &rs_dir, &rs_fn);
        assert_se(c_ret == O_DIRECTORY);
        assert_se(rs_ret == O_DIRECTORY);
        assert_se(c_dir && rs_dir && streq(c_dir, rs_dir));
        assert_se(c_fn && rs_fn && streq(c_fn, rs_fn));
        free(c_dir); c_dir = NULL;
        free(rs_dir); rs_dir = NULL;
        free(c_fn); c_fn = NULL;
        free(rs_fn); rs_fn = NULL;

        /* Arbitrary non-UTF-8 filename bytes remain byte-for-byte intact. */
        c_ret = path_split_prefix_filename("/foo/\xff/", &c_dir, &c_fn);
        rs_ret = rs_path_split_prefix_filename("/foo/\xff/", &rs_dir, &rs_fn);
        assert_se(c_ret == rs_ret);
        assert_se(c_ret == O_DIRECTORY);
        assert_se(c_dir && rs_dir && streq(c_dir, rs_dir));
        assert_se(c_fn && rs_fn && memcmp(c_fn, rs_fn, 2) == 0);
        free(c_dir); c_dir = NULL;
        free(rs_dir); rs_dir = NULL;
        free(c_fn); c_fn = NULL;
        free(rs_fn); rs_fn = NULL;

        /* Single component absolute path */
        c_ret = path_split_prefix_filename("/foo", &c_dir, &c_fn);
        rs_ret = rs_path_split_prefix_filename("/foo", &rs_dir, &rs_fn);
        assert_se(c_ret == rs_ret);
        assert_se(c_dir && rs_dir && streq(c_dir, rs_dir));
        assert_se(c_fn && rs_fn && streq(c_fn, rs_fn));
        free(c_dir); c_dir = NULL;
        free(rs_dir); rs_dir = NULL;
        free(c_fn); c_fn = NULL;
        free(rs_fn); rs_fn = NULL;

        /* Dot path */
        c_ret = path_split_prefix_filename(".", &c_dir, &c_fn);
        rs_ret = rs_path_split_prefix_filename(".", &rs_dir, &rs_fn);
        assert_se(c_ret == rs_ret);
        free(c_dir); c_dir = NULL;
        free(rs_dir); rs_dir = NULL;
        free(c_fn); c_fn = NULL;
        free(rs_fn); rs_fn = NULL;

        /* Empty path */
        c_ret = path_split_prefix_filename("", &c_dir, &c_fn);
        rs_ret = rs_path_split_prefix_filename("", &rs_dir, &rs_fn);
        assert_se(c_ret == rs_ret);
        free(c_dir); c_dir = NULL;
        free(rs_dir); rs_dir = NULL;
        free(c_fn); c_fn = NULL;
        free(rs_fn); rs_fn = NULL;
}

static void test_path_extract_filename(void) {
        char *c_fn = NULL, *rs_fn = NULL;
        int c_ret, rs_ret;

        c_ret = path_extract_filename("/foo/bar/baz", &c_fn);
        rs_ret = rs_path_extract_filename("/foo/bar/baz", &rs_fn);
        assert_se(c_ret == rs_ret);
        assert_se(c_fn && rs_fn && streq(c_fn, rs_fn));
        free(c_fn); c_fn = NULL;
        free(rs_fn); rs_fn = NULL;

        c_ret = path_extract_filename("hello.txt", &c_fn);
        rs_ret = rs_path_extract_filename("hello.txt", &rs_fn);
        assert_se(c_ret == rs_ret);
        assert_se(c_fn && rs_fn && streq(c_fn, rs_fn));
        free(c_fn); c_fn = NULL;
        free(rs_fn); rs_fn = NULL;

        c_ret = path_extract_filename("/", &c_fn);
        rs_ret = rs_path_extract_filename("/", &rs_fn);
        assert_se(c_ret == rs_ret);
        free(c_fn); c_fn = NULL;
        free(rs_fn); rs_fn = NULL;
}

static void test_path_extract_directory(void) {
        char *c_dir = NULL, *rs_dir = NULL;
        int c_ret, rs_ret;

        c_ret = path_extract_directory("/foo/bar/baz", &c_dir);
        rs_ret = rs_path_extract_directory("/foo/bar/baz", &rs_dir);
        assert_se(c_ret == rs_ret);
        assert_se(c_ret == 0); /* O_DIRECTORY suppressed */
        assert_se(c_dir && rs_dir && streq(c_dir, rs_dir));
        free(c_dir); c_dir = NULL;
        free(rs_dir); rs_dir = NULL;

        c_ret = path_extract_directory("/foo", &c_dir);
        rs_ret = rs_path_extract_directory("/foo", &rs_dir);
        assert_se(c_ret == rs_ret);
        assert_se(c_dir && rs_dir && streq(c_dir, rs_dir));
        free(c_dir); c_dir = NULL;
        free(rs_dir); rs_dir = NULL;

        c_ret = path_extract_directory("hello.txt", &c_dir);
        rs_ret = rs_path_extract_directory("hello.txt", &rs_dir);
        assert_se(c_ret == rs_ret);
        free(c_dir); c_dir = NULL;
        free(rs_dir); rs_dir = NULL;

        c_ret = path_extract_directory("/", &c_dir);
        rs_ret = rs_path_extract_directory("/", &rs_dir);
        assert_se(c_ret == rs_ret);
        free(c_dir); c_dir = NULL;
        free(rs_dir); rs_dir = NULL;
}

static void test_path_compare_filename(void) {
        assert_se(path_compare_filename("/foo/bar", "/baz/bar") == rs_path_compare_filename("/foo/bar", "/baz/bar"));
        assert_se(path_compare_filename("/foo", "/bar") == rs_path_compare_filename("/foo", "/bar"));
        assert_se(path_compare_filename("/a/b", "/a/c") == rs_path_compare_filename("/a/b", "/a/c"));
        assert_se(path_compare_filename("/", "/foo") == rs_path_compare_filename("/", "/foo"));
        /* Note: path_compare_filename(NULL, NULL) causes strcmp(NULL, NULL) which is UB — skip */
        assert_se(path_compare_filename(NULL, "/foo") == rs_path_compare_filename(NULL, "/foo"));
        assert_se(path_compare_filename("/foo", NULL) == rs_path_compare_filename("/foo", NULL));
}

static void test_path_equal_filename(void) {
        assert_se(path_equal_filename("/foo/bar", "/baz/bar") == rs_path_equal_filename("/foo/bar", "/baz/bar"));
        assert_se(path_equal_filename("/foo", "/bar") == rs_path_equal_filename("/foo", "/bar"));
        assert_se(path_equal_filename("/a/b", "/a/b") == rs_path_equal_filename("/a/b", "/a/b"));
        assert_se(path_equal_filename("/a/b", "/a/c") == rs_path_equal_filename("/a/b", "/a/c"));
}

int main(int argc, char **argv) {
        test_path_equal();
        test_path_startswith();
        test_path_is_valid();
        test_path_is_safe();
        test_filename_or_absolute_path_is_valid();
        test_skip_dev_prefix();
        test_path_simplify();
        test_path_startswith_strv();
        test_path_strv_contains();
        test_prefixed_path_strv_contains();
        test_path_split_prefix_filename();
        test_path_extract_filename();
        test_path_extract_directory();
        test_path_compare_filename();
        test_path_equal_filename();
        return 0;
}
