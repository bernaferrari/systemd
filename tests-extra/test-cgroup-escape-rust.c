/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "cgroup-util.h"
#include "rust/unit_def.h"
#include "tests.h"

TEST(cg_needs_escape_normal) {
        /* Normal cgroup names don't need escaping */
        assert_se(!cg_needs_escape("myapp"));
        assert_se(!cg_needs_escape("user.slice"));
        assert_se(!cg_needs_escape("system.service"));
        assert_se(!cg_needs_escape("cpu"));
        assert_se(!cg_needs_escape("memory"));
}

TEST(cg_needs_escape_null) {
        assert_se(cg_needs_escape(NULL));
}

TEST(cg_needs_escape_empty) {
        assert_se(cg_needs_escape(""));
}

TEST(cg_needs_escape_underscore_prefix) {
        assert_se(cg_needs_escape("_foo"));
        assert_se(cg_needs_escape("_hidden"));
}

TEST(cg_needs_escape_dot_prefix) {
        assert_se(cg_needs_escape(".hidden"));
        assert_se(cg_needs_escape(".something"));
}

TEST(cg_needs_escape_special_names) {
        assert_se(cg_needs_escape("notify_on_release"));
        assert_se(cg_needs_escape("release_agent"));
        assert_se(cg_needs_escape("tasks"));
}

TEST(cg_needs_escape_cgroup_prefix) {
        assert_se(cg_needs_escape("cgroup.clone_children"));
        assert_se(cg_needs_escape("cgroup.controllers"));
        assert_se(cg_needs_escape("cgroup.subtree_control"));
}

TEST(cg_needs_escape_controller_dot) {
        /* Controller name followed by '.' needs escaping */
        assert_se(cg_needs_escape("cpu.something"));
        assert_se(cg_needs_escape("memory.max"));
        assert_se(cg_needs_escape("pids.max"));
}

TEST(cg_needs_escape_invalid_filename) {
        assert_se(cg_needs_escape("foo/bar"));
        assert_se(cg_needs_escape("foo/../bar"));
}

TEST(cg_unescape_normal) {
        const char *p = "myapp";
        assert_se(streq(cg_unescape(p), "myapp"));
        assert_se(cg_unescape(p) == p); /* should return same pointer */
}

TEST(cg_unescape_escaped) {
        const char *p = "_myapp";
        assert_se(streq(cg_unescape(p), "myapp"));
        assert_se(cg_unescape(p) == p + 1); /* should return p+1 */
}

TEST(cg_unescape_double_underscore) {
        const char *p = "__myapp";
        assert_se(streq(cg_unescape(p), "_myapp"));
}

TEST(cg_needs_escape_c_vs_rust) {
        const char *names[] = {
                "myapp", "user.slice", "system.service",
                "_foo", ".hidden",
                "notify_on_release", "release_agent", "tasks",
                "cgroup.clone_children",
                "cpu.something", "memory.max", "pids.max",
                "cpu", "memory",
                "foo/bar", "", NULL
        };

        for (int i = 0; names[i]; i++) {
                bool cr = cg_needs_escape(names[i]);
                bool rr = rs_cg_needs_escape(names[i]);
                assert_se(cr == rr);
        }
}

TEST(cg_unescape_c_vs_rust) {
        const char *names[] = {
                "myapp", "_myapp", "__myapp", "foo", "_bar", NULL
        };

        for (int i = 0; names[i]; i++) {
                const char *cr = cg_unescape(names[i]);
                const char *rr = rs_cg_unescape(names[i]);
                assert_se(streq(cr, rr));
        }
}

DEFINE_TEST_MAIN(LOG_INFO);
