/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Shadow test: C nsflags.c vs Rust */

/* RUST-CONTRACT: namespace-single-flag-name */
/* RUST-CONTRACT: namespace-flags-to-strv */
/* RUST-CONTRACT: namespace-flags-to-string */
/* RUST-CONTRACT: namespace-flags-from-string */

#include <sched.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include "tests.h"
#include "string-util.h"
#include "strv.h"

/* C headers */
#include "nsflags.h"

/* Rust FFI */
#include "rust/nsflags.h"

/* -- namespace_single_flag_to_string --------------------------------------- */

static void test_namespace_single_flag_to_string(void) {
        assert_se(streq_ptr(namespace_single_flag_to_string(CLONE_NEWCGROUP),
                            rs_namespace_single_flag_to_string(CLONE_NEWCGROUP)));
        assert_se(streq(namespace_single_flag_to_string(CLONE_NEWCGROUP), "cgroup"));

        assert_se(streq_ptr(namespace_single_flag_to_string(CLONE_NEWIPC),
                            rs_namespace_single_flag_to_string(CLONE_NEWIPC)));
        assert_se(streq(namespace_single_flag_to_string(CLONE_NEWIPC), "ipc"));

        assert_se(streq_ptr(namespace_single_flag_to_string(CLONE_NEWNET),
                            rs_namespace_single_flag_to_string(CLONE_NEWNET)));
        assert_se(streq(namespace_single_flag_to_string(CLONE_NEWNET), "net"));

        assert_se(streq_ptr(namespace_single_flag_to_string(CLONE_NEWNS),
                            rs_namespace_single_flag_to_string(CLONE_NEWNS)));
        assert_se(streq(namespace_single_flag_to_string(CLONE_NEWNS), "mnt"));

        assert_se(streq_ptr(namespace_single_flag_to_string(CLONE_NEWPID),
                            rs_namespace_single_flag_to_string(CLONE_NEWPID)));
        assert_se(streq(namespace_single_flag_to_string(CLONE_NEWPID), "pid"));

        assert_se(streq_ptr(namespace_single_flag_to_string(CLONE_NEWUSER),
                            rs_namespace_single_flag_to_string(CLONE_NEWUSER)));
        assert_se(streq(namespace_single_flag_to_string(CLONE_NEWUSER), "user"));

        assert_se(streq_ptr(namespace_single_flag_to_string(CLONE_NEWUTS),
                            rs_namespace_single_flag_to_string(CLONE_NEWUTS)));
        assert_se(streq(namespace_single_flag_to_string(CLONE_NEWUTS), "uts"));

        assert_se(streq_ptr(namespace_single_flag_to_string(CLONE_NEWTIME),
                            rs_namespace_single_flag_to_string(CLONE_NEWTIME)));
        assert_se(streq(namespace_single_flag_to_string(CLONE_NEWTIME), "time"));

        /* Unknown flag */
        assert_se(namespace_single_flag_to_string(0) == NULL);
        assert_se(rs_namespace_single_flag_to_string(0) == NULL);

        assert_se(namespace_single_flag_to_string(0xDEAD) == NULL);
        assert_se(rs_namespace_single_flag_to_string(0xDEAD) == NULL);
}

/* -- namespace_flags_to_string -------------------------------------------- */

static void test_namespace_flags_to_string(void) {
        _cleanup_free_ char *c_str = NULL;
        _cleanup_free_ char *rs_str = NULL;
        unsigned long flags;
        int r;

        /* Empty flags */
        r = namespace_flags_to_string(0, &c_str);
        assert_se(r >= 0);
        r = rs_namespace_flags_to_string(0, &rs_str);
        assert_se(r >= 0);
        assert_se(streq_ptr(c_str, rs_str));
        c_str = mfree(c_str);
        rs_str = mfree(rs_str);

        /* Single flag */
        flags = CLONE_NEWNET;
        r = namespace_flags_to_string(flags, &c_str);
        assert_se(r >= 0);
        r = rs_namespace_flags_to_string(flags, &rs_str);
        assert_se(r >= 0);
        assert_se(streq(c_str, rs_str));
        assert_se(streq(c_str, "net"));
        c_str = mfree(c_str);
        rs_str = mfree(rs_str);

        /* Two flags */
        flags = CLONE_NEWNET | CLONE_NEWIPC;
        r = namespace_flags_to_string(flags, &c_str);
        assert_se(r >= 0);
        r = rs_namespace_flags_to_string(flags, &rs_str);
        assert_se(r >= 0);
        assert_se(streq(c_str, rs_str));
        c_str = mfree(c_str);
        rs_str = mfree(rs_str);

        /* All flags */
        flags = NAMESPACE_FLAGS_ALL;
        r = namespace_flags_to_string(flags, &c_str);
        assert_se(r >= 0);
        r = rs_namespace_flags_to_string(flags, &rs_str);
        assert_se(r >= 0);
        assert_se(streq(c_str, rs_str));
}

/* -- namespace_flags_to_strv ---------------------------------------------- */

static void test_namespace_flags_to_strv(void) {
        _cleanup_strv_free_ char **c_list = NULL;
        _cleanup_strv_free_ char **rs_list = NULL;
        unsigned long flags;
        int r;

        /* Empty flags */
        r = namespace_flags_to_strv(0, &c_list);
        assert_se(r >= 0);
        r = rs_namespace_flags_to_strv(0, &rs_list);
        assert_se(r >= 0);
        assert_se(strv_isempty(c_list));
        assert_se(strv_isempty(rs_list));

        /* Single flag */
        flags = CLONE_NEWPID;
        r = namespace_flags_to_strv(flags, &c_list);
        assert_se(r >= 0);
        r = rs_namespace_flags_to_strv(flags, &rs_list);
        assert_se(r >= 0);
        assert_se(strv_equal(c_list, rs_list));
        c_list = strv_free(c_list);
        rs_list = strv_free(rs_list);

        /* Multiple flags */
        flags = CLONE_NEWUTS | CLONE_NEWIPC | CLONE_NEWNET;
        r = namespace_flags_to_strv(flags, &c_list);
        assert_se(r >= 0);
        r = rs_namespace_flags_to_strv(flags, &rs_list);
        assert_se(r >= 0);
        assert_se(strv_equal(c_list, rs_list));
        assert_se(strv_length(c_list) == 3);
}

/* -- namespace_flags_from_string ------------------------------------------ */

static void test_namespace_flags_from_string(void) {
        static const char c_whitespace[] = "\tmnt\nnet\ruser uts\r";
        static const char non_c_whitespace[] = "mnt\vnet\fuser";
        static const char escaped_names[] = "m\\nt n\\et";
        static const char invalid_utf8[] = { 'n', 'e', 't', (char) 0xff, 0 };
        unsigned long c_flags, rs_flags;
        int r;

        /* Empty string */
        r = namespace_flags_from_string("", &c_flags);
        assert_se(r >= 0);
        r = rs_namespace_flags_from_string("", &rs_flags);
        assert_se(r >= 0);
        assert_se(c_flags == rs_flags);

        /* Single namespace */
        r = namespace_flags_from_string("net", &c_flags);
        assert_se(r >= 0);
        r = rs_namespace_flags_from_string("net", &rs_flags);
        assert_se(r >= 0);
        assert_se(c_flags == rs_flags);
        assert_se(c_flags == CLONE_NEWNET);

        /* Multiple namespaces */
        r = namespace_flags_from_string("ipc net uts", &c_flags);
        assert_se(r >= 0);
        r = rs_namespace_flags_from_string("ipc net uts", &rs_flags);
        assert_se(r >= 0);
        assert_se(c_flags == rs_flags);
        assert_se(c_flags == (CLONE_NEWIPC | CLONE_NEWNET | CLONE_NEWUTS));

        /* All namespaces */
        r = namespace_flags_from_string("cgroup ipc net mnt pid user uts time", &c_flags);
        assert_se(r >= 0);
        r = rs_namespace_flags_from_string("cgroup ipc net mnt pid user uts time", &rs_flags);
        assert_se(r >= 0);
        assert_se(c_flags == rs_flags);
        assert_se(c_flags == NAMESPACE_FLAGS_ALL);

        /* Invalid namespace */
        c_flags = 0xdeadUL;
        rs_flags = 0xdeadUL;
        r = namespace_flags_from_string("invalid", &c_flags);
        assert_se(r == -EINVAL);
        r = rs_namespace_flags_from_string("invalid", &rs_flags);
        assert_se(r == -EINVAL);
        assert_se(c_flags == rs_flags);

        /* extract_first_word() uses WHITESPACE: space, tab, LF, and CR. */
        r = namespace_flags_from_string(c_whitespace, &c_flags);
        assert_se(r >= 0);
        r = rs_namespace_flags_from_string(c_whitespace, &rs_flags);
        assert_se(r >= 0);
        assert_se(c_flags == rs_flags);
        assert_se(c_flags == (CLONE_NEWNS | CLONE_NEWNET | CLONE_NEWUSER | CLONE_NEWUTS));

        /* Vertical tab and form feed are ordinary bytes, not separators. */
        c_flags = 0xdeadUL;
        rs_flags = 0xdeadUL;
        r = namespace_flags_from_string(non_c_whitespace, &c_flags);
        assert_se(r == -EINVAL);
        r = rs_namespace_flags_from_string(non_c_whitespace, &rs_flags);
        assert_se(r == -EINVAL);
        assert_se(c_flags == rs_flags);

        /* With zero extract flags, a backslash quotes the next byte. */
        r = namespace_flags_from_string(escaped_names, &c_flags);
        assert_se(r >= 0);
        r = rs_namespace_flags_from_string(escaped_names, &rs_flags);
        assert_se(r >= 0);
        assert_se(c_flags == rs_flags);
        assert_se(c_flags == (CLONE_NEWNS | CLONE_NEWNET));

        /* C comparison remains byte-oriented for malformed UTF-8. */
        r = namespace_flags_from_string(invalid_utf8, &c_flags);
        assert_se(r == -EINVAL);
        r = rs_namespace_flags_from_string(invalid_utf8, &rs_flags);
        assert_se(r == -EINVAL);

        /* NULL */
        r = rs_namespace_flags_from_string(NULL, &rs_flags);
        assert_se(r == -EINVAL);
}

int main(int argc, char **argv) {
        test_namespace_single_flag_to_string();
        test_namespace_flags_to_string();
        test_namespace_flags_to_strv();
        test_namespace_flags_from_string();
        return 0;
}
