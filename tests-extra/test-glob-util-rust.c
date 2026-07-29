/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* RUST-CONTRACT: glob-classifier */
/* RUST-CONTRACT: glob-prefix */
/* Shadow test: C glob-util.c vs Rust */

#include <assert.h>
#include <string.h>
#include "tests.h"
#include "string-util.h"

/* C headers */
#include "glob-util.h"

/* Rust FFI */
#include "rust/glob_util.h"

/* ── string_is_glob ─────────────────────────────────────────────────── */

static void test_string_is_glob(void) {
        /* No glob chars */
        assert_se(string_is_glob("hello") == rs_string_is_glob("hello"));
        assert_se(string_is_glob("hello") == false);
        assert_se(string_is_glob("/usr/bin/systemd") == rs_string_is_glob("/usr/bin/systemd"));
        assert_se(string_is_glob("") == rs_string_is_glob(""));
        assert_se(string_is_glob("") == false);

        /* With glob chars */
        assert_se(string_is_glob("*.service") == rs_string_is_glob("*.service"));
        assert_se(string_is_glob("*.service") == true);
        assert_se(string_is_glob("systemd??.service") == rs_string_is_glob("systemd??.service"));
        assert_se(string_is_glob("systemd??.service") == true);
        assert_se(string_is_glob("systemd[abc].service") == rs_string_is_glob("systemd[abc].service"));
        assert_se(string_is_glob("systemd[abc].service") == true);
        assert_se(string_is_glob("foo\\*bar") == rs_string_is_glob("foo\\*bar"));
        assert_se(string_is_glob("foo\\*bar") == true);

        /* Multiple glob chars */
        assert_se(string_is_glob("/etc/*/*.conf") == rs_string_is_glob("/etc/*/*.conf"));
        assert_se(string_is_glob("/etc/*/*.conf") == true);

        /* Glob char at end */
        assert_se(string_is_glob("prefix*") == rs_string_is_glob("prefix*"));
        assert_se(string_is_glob("prefix*") == true);

        /* Backslash is NOT a glob char */
        assert_se(string_is_glob("foo\\bar") == rs_string_is_glob("foo\\bar"));
        assert_se(string_is_glob("foo\\bar") == false);
}

/* ── glob_non_glob_prefix ──────────────────────────────────────────── */

static void test_glob_non_glob_prefix(void) {
        char *c_ret = NULL, *r_ret = NULL;
        int cr, rr;

        /* Path with glob in middle of component */
        cr = glob_non_glob_prefix("/etc/systemd/*test.service", &c_ret);
        rr = rs_glob_non_glob_prefix("/etc/systemd/*test.service", &r_ret);
        assert_se(cr == rr);
        assert_se(cr == 0);
        assert_se(streq(c_ret, r_ret));
        free(c_ret); c_ret = NULL;
        free(r_ret); r_ret = NULL;

        /* Glob at start */
        cr = glob_non_glob_prefix("*.service", &c_ret);
        rr = rs_glob_non_glob_prefix("*.service", &r_ret);
        assert_se(cr == rr);
        assert_se(cr == -ENOENT);

        /* No glob chars at all — returns full path */
        cr = glob_non_glob_prefix("/etc/systemd/system", &c_ret);
        rr = rs_glob_non_glob_prefix("/etc/systemd/system", &r_ret);
        assert_se(cr == rr);
        assert_se(cr == 0);
        assert_se(streq(c_ret, r_ret));
        assert_se(streq(c_ret, "/etc/systemd/system"));
        free(c_ret); c_ret = NULL;
        free(r_ret); r_ret = NULL;

        /* Single component with glob */
        cr = glob_non_glob_prefix("foo*bar", &c_ret);
        rr = rs_glob_non_glob_prefix("foo*bar", &r_ret);
        assert_se(cr == rr);
        assert_se(cr == -ENOENT);

        /* Deep path with glob in last component */
        cr = glob_non_glob_prefix("/a/b/c/d/e/f*oo", &c_ret);
        rr = rs_glob_non_glob_prefix("/a/b/c/d/e/f*oo", &r_ret);
        assert_se(cr == rr);
        assert_se(cr == 0);
        assert_se(streq(c_ret, r_ret));
        assert_se(streq(c_ret, "/a/b/c/d/e/"));
        free(c_ret); c_ret = NULL;
        free(r_ret); r_ret = NULL;

        /* Path with glob after slash */
        cr = glob_non_glob_prefix("/etc/*.conf", &c_ret);
        rr = rs_glob_non_glob_prefix("/etc/*.conf", &r_ret);
        assert_se(cr == rr);
        assert_se(cr == 0);
        assert_se(streq(c_ret, r_ret));
        assert_se(streq(c_ret, "/etc/"));
        free(c_ret); c_ret = NULL;
        free(r_ret); r_ret = NULL;

        /* Question mark glob */
        cr = glob_non_glob_prefix("/etc/systemd/systemd?.service", &c_ret);
        rr = rs_glob_non_glob_prefix("/etc/systemd/systemd?.service", &r_ret);
        assert_se(cr == rr);
        assert_se(cr == 0);
        assert_se(streq(c_ret, r_ret));
        assert_se(streq(c_ret, "/etc/systemd/"));
        free(c_ret); c_ret = NULL;
        free(r_ret); r_ret = NULL;

        /* Bracket glob */
        cr = glob_non_glob_prefix("/etc/[abc]", &c_ret);
        rr = rs_glob_non_glob_prefix("/etc/[abc]", &r_ret);
        assert_se(cr == rr);
        assert_se(cr == 0);
        assert_se(streq(c_ret, r_ret));
        assert_se(streq(c_ret, "/etc/"));
        free(c_ret); c_ret = NULL;
        free(r_ret); r_ret = NULL;

        /* Backslash is NOT a glob char — returns full path */
        cr = glob_non_glob_prefix("/etc/systemd/\\test.service", &c_ret);
        rr = rs_glob_non_glob_prefix("/etc/systemd/\\test.service", &r_ret);
        assert_se(cr == rr);
        assert_se(cr == 0);
        assert_se(streq(c_ret, r_ret));
        free(c_ret); c_ret = NULL;
        free(r_ret); r_ret = NULL;
}

int main(int argc, char **argv) {
        test_string_is_glob();
        test_glob_non_glob_prefix();
        return 0;
}
