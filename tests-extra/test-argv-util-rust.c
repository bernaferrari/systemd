/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Shadow test: C argv-util vs Rust rs_argv_util */
/* RUST-CONTRACT: argv-invoked-as */
/* RUST-CONTRACT: argv-looks-like-help */

#include <assert.h>
#include <stdio.h>
#include "tests.h"
#include "argv-util.h"
#include "rust/argv_util.h"

TEST(invoked_as_c_vs_rs) {
        bool c_ret, r_ret;

        /* Simple match */
        char *argv0[] = { (char*)"/usr/bin/systemctl", NULL };
        c_ret = invoked_as(argv0, "system");
        r_ret = rs_invoked_as(argv0, "system");
        assert_se(c_ret == r_ret);
        assert_se(c_ret);

        /* C keeps a trailing slash in the last component. */
        char *argv_trailing[] = { (char*)"/usr/bin/systemctl/", NULL };
        c_ret = invoked_as(argv_trailing, "systemctl/");
        r_ret = rs_invoked_as(argv_trailing, "systemctl/");
        assert_se(c_ret == r_ret);
        assert_se(c_ret);

        /* Match in basename */
        char *argv1[] = { (char*)"/usr/lib/systemd/systemd-journald", NULL };
        c_ret = invoked_as(argv1, "journald");
        r_ret = rs_invoked_as(argv1, "journald");
        assert_se(c_ret == r_ret);
        assert_se(c_ret);

        /* No match */
        char *argv2[] = { (char*)"/usr/bin/foo", NULL };
        c_ret = invoked_as(argv2, "bar");
        r_ret = rs_invoked_as(argv2, "bar");
        assert_se(c_ret == r_ret);
        assert_se(!c_ret);

        /* C strings are byte strings, not UTF-8. */
        char non_utf8_arg[] = { '/', 'x', '/', (char) 0xff, 0 };
        char non_utf8_token[] = { (char) 0xff, 0 };
        char *argv_non_utf8[] = { non_utf8_arg, NULL };
        c_ret = invoked_as(argv_non_utf8, non_utf8_token);
        r_ret = rs_invoked_as(argv_non_utf8, non_utf8_token);
        assert_se(c_ret == r_ret);
        assert_se(c_ret);

        /* NULL argv */
        c_ret = invoked_as(NULL, "foo");
        r_ret = rs_invoked_as(NULL, "foo");
        assert_se(c_ret == r_ret);
        assert_se(!c_ret);

        /* Empty argv[0] */
        char *argv3[] = { (char*)"", NULL };
        c_ret = invoked_as(argv3, "foo");
        r_ret = rs_invoked_as(argv3, "foo");
        assert_se(c_ret == r_ret);
        assert_se(!c_ret);

        /* NULL token */
        char *argv4[] = { (char*)"/usr/bin/foo", NULL };
        c_ret = invoked_as(argv4, NULL);
        r_ret = rs_invoked_as(argv4, NULL);
        assert_se(c_ret == r_ret);
        assert_se(!c_ret);

        /* Empty token */
        char *argv5[] = { (char*)"/usr/bin/foo", NULL };
        c_ret = invoked_as(argv5, "");
        r_ret = rs_invoked_as(argv5, "");
        assert_se(c_ret == r_ret);
        assert_se(!c_ret);
}

TEST(argv_looks_like_help_c_vs_rs) {
        bool c_ret, r_ret;

        /* argc <= 1 → true */
        char *argv0[] = { (char*)"prog", NULL };
        c_ret = argv_looks_like_help(1, argv0);
        r_ret = rs_argv_looks_like_help(1, argv0);
        assert_se(c_ret == r_ret);
        assert_se(c_ret);

        /* C treats a null argv with argc == 0 as a help request. */
        c_ret = argv_looks_like_help(0, NULL);
        r_ret = rs_argv_looks_like_help(0, NULL);
        assert_se(c_ret == r_ret);
        assert_se(c_ret);

        /* argv[1] == "help" → true */
        char *argv1[] = { (char*)"prog", (char*)"help", NULL };
        c_ret = argv_looks_like_help(2, argv1);
        r_ret = rs_argv_looks_like_help(2, argv1);
        assert_se(c_ret == r_ret);
        assert_se(c_ret);

        /* argv contains --help → true */
        char *argv2[] = { (char*)"prog", (char*)"foo", (char*)"--help", (char*)"bar", NULL };
        c_ret = argv_looks_like_help(4, argv2);
        r_ret = rs_argv_looks_like_help(4, argv2);
        assert_se(c_ret == r_ret);
        assert_se(c_ret);

        /* argv contains -h → true */
        char *argv3[] = { (char*)"prog", (char*)"foo", (char*)"-h", NULL };
        c_ret = argv_looks_like_help(3, argv3);
        r_ret = rs_argv_looks_like_help(3, argv3);
        assert_se(c_ret == r_ret);
        assert_se(c_ret);

        /* No help indicators → false */
        char *argv4[] = { (char*)"prog", (char*)"foo", (char*)"bar", NULL };
        c_ret = argv_looks_like_help(3, argv4);
        r_ret = rs_argv_looks_like_help(3, argv4);
        assert_se(c_ret == r_ret);
        assert_se(!c_ret);

        /* "help" not at argv[1] → false */
        char *argv5[] = { (char*)"prog", (char*)"foo", (char*)"help", NULL };
        c_ret = argv_looks_like_help(3, argv5);
        r_ret = rs_argv_looks_like_help(3, argv5);
        assert_se(c_ret == r_ret);
        assert_se(!c_ret);

        /* -h only as argv[0] → false */
        char *argv6[] = { (char*)"-h", (char*)"foo", NULL };
        c_ret = argv_looks_like_help(2, argv6);
        r_ret = rs_argv_looks_like_help(2, argv6);
        assert_se(c_ret == r_ret);
        assert_se(!c_ret);
}

DEFINE_TEST_MAIN(LOG_INFO);
