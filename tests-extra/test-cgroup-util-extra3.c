/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "cgroup-util.h"
#include "string-util.h"
#include "tests.h"

TEST(cg_needs_escape) {
        /* Valid names that don't need escape */
        assert_se(!cg_needs_escape("myservice"));
        assert_se(!cg_needs_escape("foo-bar"));
        assert_se(!cg_needs_escape("a"));

        /* Names starting with _ need escape */
        assert_se(cg_needs_escape("_underscore"));

        /* Names starting with . need escape */
        assert_se(cg_needs_escape(".hidden"));

        /* Empty needs escape (filename_is_valid returns false) */
        assert_se(cg_needs_escape(""));

        /* Kernel cgroup names need escape */
        assert_se(cg_needs_escape("tasks"));
        assert_se(cg_needs_escape("notify_on_release"));
        assert_se(cg_needs_escape("release_agent"));

        /* Names starting with cgroup. need escape */
        assert_se(cg_needs_escape("cgroup.procs"));
        assert_se(cg_needs_escape("cgroup.controllers"));

        /* Controller-prefixed names need escape (only when followed by .) */
        assert_se(cg_needs_escape("cpu."));
        assert_se(cg_needs_escape("memory."));
        assert_se(cg_needs_escape("cpuset.cpus"));
}

TEST(cg_escape_unescape) {
        _cleanup_free_ char *escaped = NULL;
        int r;

        /* Normal name: no escaping needed */
        r = cg_escape("myservice", &escaped);
        assert_se(r >= 0);
        assert_se(streq(escaped, "myservice"));
        assert_se(streq(cg_unescape(escaped), "myservice"));
        escaped = mfree(escaped);

        /* Name needing escape: prefixed with _ */
        r = cg_escape("_underscore", &escaped);
        assert_se(r >= 0);
        assert_se(streq(escaped, "__underscore"));
        assert_se(streq(cg_unescape(escaped), "_underscore"));
        escaped = mfree(escaped);

        /* Dot-prefixed name */
        r = cg_escape(".hidden", &escaped);
        assert_se(r >= 0);
        assert_se(streq(escaped, "_.hidden"));
        assert_se(streq(cg_unescape(escaped), ".hidden"));
        escaped = mfree(escaped);

        /* tasks → _tasks */
        r = cg_escape("tasks", &escaped);
        assert_se(r >= 0);
        assert_se(streq(escaped, "_tasks"));
        assert_se(streq(cg_unescape(escaped), "tasks"));
        escaped = mfree(escaped);

        /* Name with slash is invalid */
        r = cg_escape("has/slash", &escaped);
        assert_se(r == -EINVAL);

        /* cg_unescape: no underscore → returns as-is */
        assert_se(streq(cg_unescape("normal"), "normal"));

        /* cg_unescape: single underscore → returns empty */
        assert_se(streq(cg_unescape("_"), ""));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
