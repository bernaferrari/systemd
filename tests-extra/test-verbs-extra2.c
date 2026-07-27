/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "string-util.h"
#include "tests.h"
#include "verbs.h"

static int dummy_dispatch(int argc, char *argv[], uintptr_t data, void *userdata) {
        return 0;
}

TEST(verbs_find_verb) {
        const Verb verbs[] = {
                { "start", 1, 1, 0, dummy_dispatch, 0, NULL, "Start unit" },
                { "stop",  1, 1, 0, dummy_dispatch, 0, NULL, "Stop unit" },
                { "list",  1, VERB_ANY, VERB_DEFAULT, dummy_dispatch, 0, NULL, "List units" },
        };
        const Verb *verbs_end = verbs + ELEMENTSOF(verbs);

        /* Find by name */
        const Verb *v = verbs_find_verb("start", verbs, verbs_end);
        assert_se(v);
        assert_se(streq(v->verb, "start"));

        v = verbs_find_verb("stop", verbs, verbs_end);
        assert_se(v);
        assert_se(streq(v->verb, "stop"));

        v = verbs_find_verb("list", verbs, verbs_end);
        assert_se(v);
        assert_se(streq(v->verb, "list"));

        /* Find default (NULL name) */
        v = verbs_find_verb(NULL, verbs, verbs_end);
        assert_se(v);
        assert_se(streq(v->verb, "list"));
        assert_se(FLAGS_SET(v->flags, VERB_DEFAULT));

        /* Not found */
        v = verbs_find_verb("nonexistent", verbs, verbs_end);
        assert_se(v == NULL);
}

TEST(verbs_find_verb_empty) {
        const Verb verbs[] = {
                { "only", 1, 1, 0, dummy_dispatch, 0, NULL, "Only verb" },
        };

        /* Single verb, no default flag */
        assert_se(verbs_find_verb("only", verbs, verbs + 1) != NULL);
        assert_se(verbs_find_verb(NULL, verbs, verbs + 1) == NULL);
        assert_se(verbs_find_verb("missing", verbs, verbs + 1) == NULL);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
