/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Shadow test: C vs Rust for path-util functions */

#include <assert.h>
#include <string.h>
#include "tests.h"
#include "path-util.h"
#include "rust/path_util.h"
#include "string-util.h"

/* -- path_find_first_component ------------------------------------------- */

/* RUST-CONTRACT: path-component-find */
static void test_path_find_first_component(void) {
        const char *p, *c;
        int r;

        /* Simple path */
        p = "aaa/bbb";
        r = path_find_first_component(&p, true, &c);
        assert_se(r == 3);
        assert_se(strneq(c, "aaa", 3));

        /* Leading slashes and dots */
        p = "//.//aaa///bbbbb/cc";
        r = path_find_first_component(&p, true, &c);
        assert_se(r == 3);
        assert_se(strneq(c, "aaa", 3));

        /* Dot component — "./" is skipped, so we get "foo" */
        p = "./foo";
        r = path_find_first_component(&p, true, &c);
        assert_se(r == 3);
        assert_se(strneq(c, "foo", 3));

        /* Root */
        p = "/";
        r = path_find_first_component(&p, true, &c);
        assert_se(r == 0);

        /* Empty */
        p = "";
        r = path_find_first_component(&p, true, &c);
        assert_se(r == 0);

        /* Dot-dot accepted */
        p = "../foo";
        r = path_find_first_component(&p, true, &c);
        assert_se(r == 2);
        assert_se(strneq(c, "..", 2));

        /* Dot-dot refused */
        p = "../foo";
        r = path_find_first_component(&p, false, &c);
        assert_se(r == -EINVAL);

        /* NULL ret pointer */
        p = "foo/bar";
        r = path_find_first_component(&p, true, NULL);
        assert_se(r == 3);

        /* -- Rust -- */
        p = "aaa/bbb";
        r = rs_path_find_first_component(&p, true, &c);
        assert_se(r == 3);
        assert_se(strneq(c, "aaa", 3));

        p = "//.//aaa///bbbbb/cc";
        r = rs_path_find_first_component(&p, true, &c);
        assert_se(r == 3);
        assert_se(strneq(c, "aaa", 3));

        p = "./foo";
        r = rs_path_find_first_component(&p, true, &c);
        assert_se(r == 3);
        assert_se(strneq(c, "foo", 3));

        p = "/";
        r = rs_path_find_first_component(&p, true, &c);
        assert_se(r == 0);

        p = "";
        r = rs_path_find_first_component(&p, true, &c);
        assert_se(r == 0);

        p = "../foo";
        r = rs_path_find_first_component(&p, true, &c);
        assert_se(r == 2);

        p = "../foo";
        r = rs_path_find_first_component(&p, false, &c);
        assert_se(r == -EINVAL);

        p = "foo/bar";
        r = rs_path_find_first_component(&p, true, NULL);
        assert_se(r == 3);
}

/* -- path_find_last_component -------------------------------------------- */

static void test_path_find_last_component(void) {
        const char *path = "//.//aaa///bbbbb/cc//././";
        const char *c_next = NULL, *rs_next = NULL;
        const char *c_ret, *rs_ret;
        int cr, rr;

        /* First call: get last component "cc" */
        cr = path_find_last_component(path, true, &c_next, &c_ret);
        rr = rs_path_find_last_component(path, true, &rs_next, &rs_ret);
        assert_se(cr == rr);
        assert_se(rr == 2);
        assert_se(strneq(c_ret, "cc", 2));
        assert_se(strneq(rs_ret, "cc", 2));

        /* Second call: get "bbbbb" */
        cr = path_find_last_component(path, true, &c_next, &c_ret);
        rr = rs_path_find_last_component(path, true, &rs_next, &rs_ret);
        assert_se(cr == rr);
        assert_se(rr == 5);
        assert_se(strneq(c_ret, "bbbbb", 5));
        assert_se(strneq(rs_ret, "bbbbb", 5));

        /* Third call: get "aaa" */
        cr = path_find_last_component(path, true, &c_next, &c_ret);
        rr = rs_path_find_last_component(path, true, &rs_next, &rs_ret);
        assert_se(cr == rr);
        assert_se(rr == 3);
        assert_se(strneq(c_ret, "aaa", 3));
        assert_se(strneq(rs_ret, "aaa", 3));

        /* Fourth call: exhausted */
        cr = path_find_last_component(path, true, &c_next, &c_ret);
        rr = rs_path_find_last_component(path, true, &rs_next, &rs_ret);
        assert_se(cr == rr);
        assert_se(rr == 0);

        /* Empty path */
        c_next = rs_next = NULL;
        cr = path_find_last_component("", true, &c_next, &c_ret);
        rr = rs_path_find_last_component("", true, &rs_next, &rs_ret);
        assert_se(cr == rr);
        assert_se(rr == 0);

        /* Root */
        c_next = rs_next = NULL;
        cr = path_find_last_component("/", true, &c_next, &c_ret);
        rr = rs_path_find_last_component("/", true, &rs_next, &rs_ret);
        assert_se(cr == rr);
        assert_se(rr == 0);

        /* Dot-dot refused: last component is ".." */
        path = "/foo/bar/..";
        c_next = rs_next = NULL;
        cr = path_find_last_component(path, false, &c_next, &c_ret);
        rr = rs_path_find_last_component(path, false, &rs_next, &rs_ret);
        assert_se(cr == rr);
        assert_se(rr == -EINVAL);
}

/* -- last_path_component ------------------------------------------------- */

/* RUST-CONTRACT: last-path-component */
static void test_last_path_component(void) {
        const char *c, *rs;

        c = last_path_component("a/b/c");
        rs = rs_last_path_component("a/b/c");
        assert_se(streq(c, rs));
        assert_se(streq(c, "c"));

        c = last_path_component("a/b/c/");
        rs = rs_last_path_component("a/b/c/");
        assert_se(streq(c, rs));
        assert_se(streq(c, "c/"));

        c = last_path_component("x");
        rs = rs_last_path_component("x");
        assert_se(streq(c, rs));
        assert_se(streq(c, "x"));

        c = last_path_component("x/");
        rs = rs_last_path_component("x/");
        assert_se(streq(c, rs));
        assert_se(streq(c, "x/"));

        c = last_path_component("/y");
        rs = rs_last_path_component("/y");
        assert_se(streq(c, rs));
        assert_se(streq(c, "y"));

        c = last_path_component("/y/");
        rs = rs_last_path_component("/y/");
        assert_se(streq(c, rs));
        assert_se(streq(c, "y/"));

        c = last_path_component("/");
        rs = rs_last_path_component("/");
        assert_se(streq(c, rs));
        assert_se(streq(c, "/"));

        c = last_path_component("//");
        rs = rs_last_path_component("//");
        assert_se(streq(c, rs));

        c = last_path_component("");
        rs = rs_last_path_component("");
        assert_se(streq(c, rs));

        c = last_path_component(NULL);
        rs = rs_last_path_component(NULL);
        assert_se(c == NULL);
        assert_se(rs == NULL);
}

/* -- path_compare -------------------------------------------------------- */

/* RUST-CONTRACT: path-compare */
static void test_path_compare(void) {
        int cr, rr;

        /* Equal paths */
        cr = path_compare("/foo/bar", "/foo/bar");
        rr = rs_path_compare("/foo/bar", "/foo/bar");
        assert_se(cr == rr);
        assert_se(cr == 0);

        /* Different paths */
        cr = path_compare("/foo/aaa", "/foo/b");
        rr = rs_path_compare("/foo/aaa", "/foo/b");
        assert_se(cr == rr);

        /* Prefix ordering */
        cr = path_compare("/foo", "/foo/bar");
        rr = rs_path_compare("/foo", "/foo/bar");
        assert_se(cr == rr);
        assert_se(cr < 0);

        cr = path_compare("/foo/bar", "/foo");
        rr = rs_path_compare("/foo/bar", "/foo");
        assert_se(cr == rr);
        assert_se(cr > 0);

        /* Same length different component */
        cr = path_compare("/foo/a", "/foo/b");
        rr = rs_path_compare("/foo/a", "/foo/b");
        assert_se(cr == rr);
        assert_se(cr < 0);

        /* NULL handling */
        cr = path_compare(NULL, "/foo");
        rr = rs_path_compare(NULL, "/foo");
        assert_se(cr == rr);
        assert_se(cr < 0);

        cr = path_compare("/foo", NULL);
        rr = rs_path_compare("/foo", NULL);
        assert_se(cr == rr);
        assert_se(cr > 0);

        /* NULL vs NULL — both C and Rust crash (assert on NULL in find_first_component) */
        /* cr = path_compare(NULL, NULL); — skip */

        /* Relative vs absolute */
        cr = path_compare("foo/bar", "/foo/bar");
        rr = rs_path_compare("foo/bar", "/foo/bar");
        assert_se(cr == rr);

        /* With extra slashes */
        cr = path_compare("//foo//bar", "/foo/bar");
        rr = rs_path_compare("//foo//bar", "/foo/bar");
        assert_se(cr == rr);

        /* Same component length */
        cr = path_compare("/foo/a", "/foo/aaa");
        rr = rs_path_compare("/foo/a", "/foo/aaa");
        assert_se(cr == rr);
        assert_se(cr < 0);
}

/* -- path_simplify_alloc ------------------------------------------------- */

/* RUST-CONTRACT: path-simplify-alloc */
static void test_path_simplify_alloc(void) {
        _cleanup_free_ char *c_ret = NULL, *rs_ret = NULL;
        int cr, rr;

        /* Simple path */
        cr = path_simplify_alloc("foo/bar", &c_ret);
        rr = rs_path_simplify_alloc("foo/bar", &rs_ret);
        assert_se(cr == rr);
        assert_se(streq(c_ret, rs_ret));

        c_ret = mfree(c_ret);
        rs_ret = mfree(rs_ret);

        /* Extra slashes */
        cr = path_simplify_alloc("///foo//./bar/.   ", &c_ret);
        rr = rs_path_simplify_alloc("///foo//./bar/.   ", &rs_ret);
        assert_se(cr == rr);
        if (cr >= 0)
                assert_se(streq(c_ret, rs_ret));

        c_ret = mfree(c_ret);
        rs_ret = mfree(rs_ret);

        /* Dot-dot in absolute path */
        cr = path_simplify_alloc("/../foo/bar", &c_ret);
        rr = rs_path_simplify_alloc("/../foo/bar", &rs_ret);
        assert_se(cr == rr);
        if (cr >= 0)
                assert_se(streq(c_ret, rs_ret));

        c_ret = mfree(c_ret);
        rs_ret = mfree(rs_ret);

        /* NULL */
        cr = path_simplify_alloc(NULL, &c_ret);
        rr = rs_path_simplify_alloc(NULL, &rs_ret);
        assert_se(cr == rr);
        assert_se(cr == 0);
        assert_se(c_ret == NULL);
        assert_se(rs_ret == NULL);

        /* Empty */
        c_ret = mfree(c_ret);
        rs_ret = mfree(rs_ret);
        cr = path_simplify_alloc("", &c_ret);
        rr = rs_path_simplify_alloc("", &rs_ret);
        assert_se(cr == rr);
        if (cr >= 0)
                assert_se(streq(c_ret, rs_ret));
}

/* -- path_simplify_full (in-place) --------------------------------------- */

/* RUST-CONTRACT: path-simplify-full */
static void test_path_simplify_full(void) {
        char c_buf[256], rs_buf[256];

        /* Basic simplification */
        strcpy(c_buf, "///foo//./bar/.");
        strcpy(rs_buf, "///foo//./bar/.");
        path_simplify_full(c_buf, 0);
        rs_path_simplify_full(rs_buf, 0);
        assert_se(streq(c_buf, rs_buf));

        /* Relative path with dots */
        strcpy(c_buf, ".//./foo//./bar/.");
        strcpy(rs_buf, ".//./foo//./bar/.");
        path_simplify_full(c_buf, 0);
        rs_path_simplify_full(rs_buf, 0);
        assert_se(streq(c_buf, rs_buf));

        /* Absolute with dot-dot at start */
        strcpy(c_buf, "/../foo/bar");
        strcpy(rs_buf, "/../foo/bar");
        path_simplify_full(c_buf, 0);
        rs_path_simplify_full(rs_buf, 0);
        assert_se(streq(c_buf, rs_buf));

        /* Empty */
        strcpy(c_buf, "");
        strcpy(rs_buf, "");
        path_simplify_full(c_buf, 0);
        rs_path_simplify_full(rs_buf, 0);
        assert_se(streq(c_buf, rs_buf));

        /* Just slashes */
        strcpy(c_buf, "///");
        strcpy(rs_buf, "///");
        path_simplify_full(c_buf, 0);
        rs_path_simplify_full(rs_buf, 0);
        assert_se(streq(c_buf, rs_buf));

        /* With trailing slash keep flag */
        strcpy(c_buf, "/foo/bar/");
        strcpy(rs_buf, "/foo/bar/");
        path_simplify_full(c_buf, PATH_SIMPLIFY_KEEP_TRAILING_SLASH);
        rs_path_simplify_full(rs_buf, PATH_SIMPLIFY_KEEP_TRAILING_SLASH);
        assert_se(streq(c_buf, rs_buf));
}

/* -- path_startswith_full ------------------------------------------------ */

/* RUST-CONTRACT: path-startswith-full */
static void test_path_startswith_full(void) {
        const char *c, *rs;

        /* Simple match */
        c = path_startswith_full("/foo/bar/baz", "/foo/bar", 0);
        rs = rs_path_startswith_full("/foo/bar/baz", "/foo/bar", 0);
        assert_se(streq(c, rs));
        assert_se(streq(c, "baz"));

        /* No match */
        c = path_startswith_full("/foo/bar/baz", "/foo/qux", 0);
        rs = rs_path_startswith_full("/foo/bar/baz", "/foo/qux", 0);
        assert_se(c == NULL);
        assert_se(rs == NULL);

        /* Exact match */
        c = path_startswith_full("/foo/bar", "/foo/bar", 0);
        rs = rs_path_startswith_full("/foo/bar", "/foo/bar", 0);
        assert_se((c == NULL && rs == NULL) || streq(c, rs));

        /* Prefix */
        c = path_startswith_full("/foo", "/foo/bar", 0);
        rs = rs_path_startswith_full("/foo", "/foo/bar", 0);
        assert_se(c == NULL);
        assert_se(rs == NULL);

        /* With extra slashes */
        c = path_startswith_full("/foo//bar/baz", "//foo/bar", 0);
        rs = rs_path_startswith_full("/foo//bar/baz", "//foo/bar", 0);
        assert_se(streq(c, rs));

        /* Relative paths */
        c = path_startswith_full("foo/bar/baz", "foo/bar", 0);
        rs = rs_path_startswith_full("foo/bar/baz", "foo/bar", 0);
        assert_se(streq(c, rs));
        assert_se(streq(c, "baz"));

        /* Mixed abs/rel */
        c = path_startswith_full("/foo/bar", "foo", 0);
        rs = rs_path_startswith_full("/foo/bar", "foo", 0);
        assert_se(c == NULL);
        assert_se(rs == NULL);
}

/* -- path_make_relative --------------------------------------------------- */

/* RUST-CONTRACT: path-make-relative */
static void test_path_make_relative(void) {
        _cleanup_free_ char *c_ret = NULL, *rs_ret = NULL;
        int cr, rr;

        /* Same path */
        cr = path_make_relative("/foo/bar", "/foo/bar", &c_ret);
        rr = rs_path_make_relative("/foo/bar", "/foo/bar", &rs_ret);
        assert_se(cr == rr);
        assert_se(streq(c_ret, rs_ret));
        c_ret = mfree(c_ret);
        rs_ret = mfree(rs_ret);

        /* to inside from */
        cr = path_make_relative("/foo", "/foo/bar", &c_ret);
        rr = rs_path_make_relative("/foo", "/foo/bar", &rs_ret);
        assert_se(cr == rr);
        if (cr >= 0)
                assert_se(streq(c_ret, rs_ret));
        c_ret = mfree(c_ret);
        rs_ret = mfree(rs_ret);

        /* Sibling paths */
        cr = path_make_relative("/foo/bar", "/foo/baz", &c_ret);
        rr = rs_path_make_relative("/foo/bar", "/foo/baz", &rs_ret);
        assert_se(cr == rr);
        if (cr >= 0)
                assert_se(streq(c_ret, rs_ret));
        c_ret = mfree(c_ret);
        rs_ret = mfree(rs_ret);

        /* Deeper nesting */
        cr = path_make_relative("/a/b/c", "/a/d/e", &c_ret);
        rr = rs_path_make_relative("/a/b/c", "/a/d/e", &rs_ret);
        assert_se(cr == rr);
        if (cr >= 0)
                assert_se(streq(c_ret, rs_ret));
        c_ret = mfree(c_ret);
        rs_ret = mfree(rs_ret);

        /* Root to nested */
        cr = path_make_relative("/", "/a/b", &c_ret);
        rr = rs_path_make_relative("/", "/a/b", &rs_ret);
        assert_se(cr == rr);
        if (cr >= 0)
                assert_se(streq(c_ret, rs_ret));
        c_ret = mfree(c_ret);
        rs_ret = mfree(rs_ret);

        /* Not absolute */
        cr = path_make_relative("foo/bar", "/foo/baz", &c_ret);
        rr = rs_path_make_relative("foo/bar", "/foo/baz", &rs_ret);
        assert_se(cr == rr);
        assert_se(cr < 0);

        /* NULL — C asserts on NULL, skip shadow test */
        rr = rs_path_make_relative(NULL, "/foo", &rs_ret);
        assert_se(rr < 0);
}

static void test_path_byte_abi_contract(void) {
        static const char non_utf8_path[] = "//\xff///x";
        static const char non_utf8_prefix[] = "/\xff";
        const char *cursor = non_utf8_path, *component = NULL, *suffix;
        char c_buf[] = "///\xff//./x/", rs_buf[] = "///\xff//./x/";
        char *published = UINT_TO_PTR(1);

        assert_se(rs_path_find_first_component(&cursor, true, &component) == 1);
        assert_se(component == non_utf8_path + 2);
        assert_se(cursor == non_utf8_path + 6);

        suffix = rs_path_startswith_full(non_utf8_path, non_utf8_prefix, 0);
        assert_se(suffix == non_utf8_path + 6);

        path_simplify_full(c_buf, PATH_SIMPLIFY_KEEP_TRAILING_SLASH);
        assert_se(rs_path_simplify_full(rs_buf, PATH_SIMPLIFY_KEEP_TRAILING_SLASH) == rs_buf);
        assert_se(memcmp(c_buf, rs_buf, sizeof(c_buf)) == 0);

        assert_se(rs_path_make_relative("relative", "/absolute", &published) == -EINVAL);
        assert_se(published == UINT_TO_PTR(1));
}

int main(int argc, char **argv) {
        test_path_find_first_component();
        test_path_find_last_component();
        test_last_path_component();
        test_path_compare();
        test_path_simplify_alloc();
        test_path_simplify_full();
        test_path_startswith_full();
        test_path_make_relative();
        test_path_byte_abi_contract();
        return 0;
}
