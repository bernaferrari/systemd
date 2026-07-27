/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdlib.h>

#include "env-util.h"
#include "string-util.h"
#include "tests.h"
#include "verbs.h"

static int verb_dispatch_ok(int argc, char **argv, uintptr_t data, void *userdata) {
        return 0;
}

TEST(verbs_find_verb) {
        const Verb verbs[] = {
                { .verb = "start",  .min_args = 1, .max_args = VERB_ANY, .flags = 0, .dispatch = verb_dispatch_ok },
                { .verb = "stop",   .min_args = 1, .max_args = VERB_ANY, .flags = 0, .dispatch = verb_dispatch_ok },
                { .verb = "status", .min_args = 1, .max_args = VERB_ANY, .flags = VERB_DEFAULT, .dispatch = verb_dispatch_ok },
                {},
        };
        size_t n = 3; /* 3 verbs before the sentinel */

        /* Find existing verb */
        const Verb *v = verbs_find_verb("start", verbs, verbs + n);
        assert_se(v != NULL);
        assert_se(streq(v->verb, "start"));

        v = verbs_find_verb("stop", verbs, verbs + n);
        assert_se(v != NULL);
        assert_se(streq(v->verb, "stop"));

        /* Non-existing verb returns NULL */
        v = verbs_find_verb("nonexistent", verbs, verbs + n);
        assert_se(v == NULL);

        /* NULL name returns default verb */
        v = verbs_find_verb(NULL, verbs, verbs + n);
        assert_se(v != NULL);
        assert_se(streq(v->verb, "status"));
        assert_se(FLAGS_SET(v->flags, VERB_DEFAULT));
}

TEST(verbs_find_verb_empty_table) {
        const Verb verbs[] = {
                {},
        };

        /* Empty table returns NULL for any name */
        const Verb *v = verbs_find_verb("anything", verbs, verbs);
        assert_se(v == NULL);

        /* NULL name on empty table returns NULL */
        v = verbs_find_verb(NULL, verbs, verbs);
        assert_se(v == NULL);
}

TEST(running_in_chroot_or_offline) {
        /* Test with SYSTEMD_OFFLINE=1 → true */
        assert_se(setenv("SYSTEMD_OFFLINE", "1", 1) >= 0);
        assert_se(running_in_chroot_or_offline());

        /* Test with SYSTEMD_OFFLINE=0 → false */
        assert_se(setenv("SYSTEMD_OFFLINE", "0", 1) >= 0);
        assert_se(!running_in_chroot_or_offline());

        /* Unset → falls through to running_in_chroot() */
        assert_se(unsetenv("SYSTEMD_OFFLINE") >= 0);
        /* Just verify it doesn't crash */
        (void) running_in_chroot_or_offline();
}

TEST(should_bypass) {
        /* No env var set → false */
        assert_se(unsetenv("TEST_BYPASS") >= 0);
        assert_se(!should_bypass("TEST"));

        /* Set to 1 → true */
        assert_se(setenv("TEST_BYPASS", "1", 1) >= 0);
        assert_se(should_bypass("TEST"));

        /* Set to 0 → false */
        assert_se(setenv("TEST_BYPASS", "0", 1) >= 0);
        assert_se(!should_bypass("TEST"));

        /* Clean up */
        assert_se(unsetenv("TEST_BYPASS") >= 0);
}

TEST(dispatch_verb_with_args) {
        const Verb verbs[] = {
                { .verb = "start",  .min_args = 1, .max_args = VERB_ANY, .flags = 0, .dispatch = verb_dispatch_ok },
                { .verb = "stop",   .min_args = 1, .max_args = VERB_ANY, .flags = 0, .dispatch = verb_dispatch_ok },
                { .verb = "status", .min_args = 0, .max_args = VERB_ANY, .flags = VERB_DEFAULT, .dispatch = verb_dispatch_ok },
                {},
        };

        size_t n = 3;

        /* Dispatch known verb */
        char *args_start[] = { (char*) "start", (char*) "unit.service", NULL };
        int r = _dispatch_verb_with_args(args_start, verbs, verbs + n, NULL);
        assert_se(r >= 0);

        /* Unknown verb returns -EINVAL */
        char *args_bad[] = { (char*) "nonexistent", NULL };
        r = _dispatch_verb_with_args(args_bad, verbs, verbs + n, NULL);
        assert_se(r == -EINVAL);

        /* Offline-only verb in chroot mode */
        const Verb verbs2[] = {
                { .verb = "reload", .min_args = 0, .max_args = VERB_ANY, .flags = VERB_ONLINE_ONLY, .dispatch = verb_dispatch_ok },
                {},
        };

        assert_se(setenv("SYSTEMD_OFFLINE", "1", 1) >= 0);
        char *args_reload[] = { (char*) "reload", NULL };
        r = _dispatch_verb_with_args(args_reload, verbs2, verbs2 + 1, NULL);
        assert_se(r == 0); /* returns 0 (no-op in chroot) */
        assert_se(unsetenv("SYSTEMD_OFFLINE") >= 0);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
