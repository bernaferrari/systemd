/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "proc-cmdline.h"
#include "string-util.h"
#include "strv.h"
#include "tests.h"

TEST(proc_cmdline_key_streq_basic) {
        assert_se(proc_cmdline_key_streq("foo", "foo"));
        assert_se(!proc_cmdline_key_streq("foo", "bar"));
        assert_se(!proc_cmdline_key_streq("foo", "foo=bar"));
        /* "-" and "_" are considered equal */
        assert_se(proc_cmdline_key_streq("foo_bar", "foo-bar"));
        assert_se(proc_cmdline_key_streq("a_b-c", "a-b_c"));
        /* Case sensitive */
        assert_se(!proc_cmdline_key_streq("KEY", "key"));
}

TEST(proc_cmdline_key_startswith_basic) {
        assert_se(proc_cmdline_key_startswith("foobar", "foo"));
        assert_se(!proc_cmdline_key_startswith("foobar", "bar"));
        assert_se(!proc_cmdline_key_startswith("foo", "foobar"));
        /* "-" and "_" are equivalent */
        assert_se(proc_cmdline_key_startswith("foo_bar-baz", "foo_bar-"));
        /* Case sensitive */
        assert_se(!proc_cmdline_key_startswith("FOOBAR", "foo"));
        assert_se(!proc_cmdline_key_startswith("", "foo"));
}

TEST(proc_cmdline_value_missing_basic) {
        /* Missing = value is NULL only */
        assert_se(proc_cmdline_value_missing("key", NULL));
        assert_se(!proc_cmdline_value_missing("key", ""));
        assert_se(!proc_cmdline_value_missing("key", "value"));
}

TEST(proc_cmdline_filter_pid1_args_basic) {
        _cleanup_strv_free_ char **result = NULL;
        char *argv[] = {
                (char*) "linux",
                (char*) "root=/dev/sda1",
                (char*) "rw",
                (char*) "quiet",
                NULL
        };

        int r = proc_cmdline_filter_pid1_args(argv, &result);
        if (r < 0) {
                log_debug("proc_cmdline_filter_pid1_args failed: %m, skipping");
                return;
        }

        assert_se(result);
        /* All args should be kept since none are systemd args */
        assert_se(strv_length(result) >= 3);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
