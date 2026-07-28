/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Shadow test: C proc-cmdline vs Rust rs_proc_cmdline */
/* RUST-CONTRACT: proc-cmdline-key-prefix */
/* RUST-CONTRACT: proc-cmdline-key-equality */

#include "proc-cmdline.h"
#include "rust/proc_cmdline.h"
#include "string-util.h"
#include "tests.h"

/* ── proc_cmdline_key_streq ───────────────────────────────────────────── */

TEST(proc_cmdline_key_streq_identical) {
        assert_se(proc_cmdline_key_streq("hello", "hello") == rs_proc_cmdline_key_streq("hello", "hello"));
        assert_se(proc_cmdline_key_streq("hello", "hello"));
}

TEST(proc_cmdline_key_streq_dash_underscore) {
        assert_se(proc_cmdline_key_streq("foo_bar", "foo-bar") == rs_proc_cmdline_key_streq("foo_bar", "foo-bar"));
        assert_se(proc_cmdline_key_streq("foo_bar", "foo-bar"));

        assert_se(proc_cmdline_key_streq("foo-bar", "foo_bar") == rs_proc_cmdline_key_streq("foo-bar", "foo_bar"));
        assert_se(proc_cmdline_key_streq("foo-bar", "foo_bar"));

        assert_se(proc_cmdline_key_streq("foo_bar-baz", "foo-bar_baz") ==
                  rs_proc_cmdline_key_streq("foo_bar-baz", "foo-bar_baz"));
        assert_se(proc_cmdline_key_streq("foo_bar-baz", "foo-bar_baz"));
}

TEST(proc_cmdline_key_streq_different) {
        assert_se(proc_cmdline_key_streq("abc", "xyz") == rs_proc_cmdline_key_streq("abc", "xyz"));
        assert_se(!proc_cmdline_key_streq("abc", "xyz"));

        assert_se(proc_cmdline_key_streq("abc", "abcd") == rs_proc_cmdline_key_streq("abc", "abcd"));
        assert_se(!proc_cmdline_key_streq("abc", "abcd"));

        assert_se(proc_cmdline_key_streq("abcd", "abc") == rs_proc_cmdline_key_streq("abcd", "abc"));
        assert_se(!proc_cmdline_key_streq("abcd", "abc"));
}

TEST(proc_cmdline_key_streq_empty) {
        assert_se(proc_cmdline_key_streq("", "") == rs_proc_cmdline_key_streq("", ""));
        assert_se(proc_cmdline_key_streq("", ""));

        assert_se(proc_cmdline_key_streq("", "a") == rs_proc_cmdline_key_streq("", "a"));
        assert_se(!proc_cmdline_key_streq("", "a"));

        assert_se(proc_cmdline_key_streq("a", "") == rs_proc_cmdline_key_streq("a", ""));
        assert_se(!proc_cmdline_key_streq("a", ""));
}

TEST(proc_cmdline_key_streq_edge_cases) {
        /* dash vs other chars */
        assert_se(proc_cmdline_key_streq("-", "_") == rs_proc_cmdline_key_streq("-", "_"));
        assert_se(proc_cmdline_key_streq("-", "_"));

        /* mixed dash/underscore in same string */
        assert_se(proc_cmdline_key_streq("a_b-c", "a-b_c") == rs_proc_cmdline_key_streq("a_b-c", "a-b_c"));
        assert_se(proc_cmdline_key_streq("a_b-c", "a-b_c"));

        /* only dashes/underscores */
        assert_se(proc_cmdline_key_streq("_-", "-_") == rs_proc_cmdline_key_streq("_-", "-_"));
        assert_se(proc_cmdline_key_streq("_-", "-_"));

        assert_se(!proc_cmdline_key_streq("a.b", "a-b"));
        assert_se(proc_cmdline_key_streq("a.b", "a-b") ==
                  rs_proc_cmdline_key_streq("a.b", "a-b"));
}

/* ── proc_cmdline_key_startswith ─────────────────────────────────────── */

TEST(proc_cmdline_key_startswith_match) {
        const char *c_ret = proc_cmdline_key_startswith("foo_bar", "foo");
        const char *rs_ret = rs_proc_cmdline_key_startswith("foo_bar", "foo");
        assert_se(c_ret != NULL);
        assert_se(rs_ret != NULL);
        assert_se(streq(c_ret, rs_ret));
        assert_se(streq(c_ret, "_bar"));

        assert_se(c_ret == "foo_bar" + 3);
        assert_se(rs_ret == "foo_bar" + 3);
}

TEST(proc_cmdline_key_raw_bytes) {
        const char s[] = { 'x', (char) 0xff, '-', 'y', 0 };
        const char prefix[] = { 'x', (char) 0xff, '_', 0 };

        assert_se(proc_cmdline_key_startswith(s, prefix) == s + 3);
        assert_se(rs_proc_cmdline_key_startswith(s, prefix) == s + 3);
        assert_se(proc_cmdline_key_streq(s, prefix) ==
                  rs_proc_cmdline_key_streq(s, prefix));
}

TEST(proc_cmdline_key_startswith_relaxed) {
        /* prefix "foo_bar" (7 chars) matches "foo-bar" (7 chars) entirely */
        const char *c_ret = proc_cmdline_key_startswith("foo-bar", "foo_bar");
        const char *rs_ret = rs_proc_cmdline_key_startswith("foo-bar", "foo_bar");
        assert_se(c_ret != NULL);
        assert_se(rs_ret != NULL);
        assert_se(*c_ret == '\0');
        assert_se(*rs_ret == '\0');

        /* prefix "foo_bar" matches "foo-bar_baz" partially → returns "_baz" */
        c_ret = proc_cmdline_key_startswith("foo-bar_baz", "foo_bar");
        rs_ret = rs_proc_cmdline_key_startswith("foo-bar_baz", "foo_bar");
        assert_se(c_ret != NULL);
        assert_se(rs_ret != NULL);
        assert_se(streq(c_ret, rs_ret));
        assert_se(streq(c_ret, "_baz"));

        /* prefix "foo_bar-" matches "foo-bar_baz" → returns "baz" */
        c_ret = proc_cmdline_key_startswith("foo-bar_baz", "foo_bar-");
        rs_ret = rs_proc_cmdline_key_startswith("foo-bar_baz", "foo_bar-");
        assert_se(c_ret != NULL);
        assert_se(rs_ret != NULL);
        assert_se(streq(c_ret, rs_ret));
        assert_se(streq(c_ret, "baz"));
}

TEST(proc_cmdline_key_startswith_full) {
        const char *c_ret = proc_cmdline_key_startswith("hello", "hello");
        const char *rs_ret = rs_proc_cmdline_key_startswith("hello", "hello");
        assert_se(c_ret != NULL);
        assert_se(rs_ret != NULL);
        assert_se(*c_ret == '\0');
        assert_se(*rs_ret == '\0');
}

TEST(proc_cmdline_key_startswith_no_match) {
        const char *c_ret = proc_cmdline_key_startswith("hello", "xyz");
        const char *rs_ret = rs_proc_cmdline_key_startswith("hello", "xyz");
        assert_se(c_ret == NULL);
        assert_se(rs_ret == NULL);
}

TEST(proc_cmdline_key_startswith_empty_prefix) {
        const char *c_ret = proc_cmdline_key_startswith("hello", "");
        const char *rs_ret = rs_proc_cmdline_key_startswith("hello", "");
        assert_se(c_ret != NULL);
        assert_se(rs_ret != NULL);
        assert_se(streq(c_ret, rs_ret));
        assert_se(streq(c_ret, "hello"));
}

TEST(proc_cmdline_key_startswith_longer_prefix) {
        const char *c_ret = proc_cmdline_key_startswith("hi", "hello");
        const char *rs_ret = rs_proc_cmdline_key_startswith("hi", "hello");
        assert_se(c_ret == NULL);
        assert_se(rs_ret == NULL);
}

DEFINE_TEST_MAIN(LOG_INFO);
