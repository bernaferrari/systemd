/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "condition.h"
#include "string-util.h"
#include "tests.h"

DEFINE_TRIVIAL_CLEANUP_FUNC(Condition*, condition_free);

TEST(condition_new_free) {
        _cleanup_(condition_freep) Condition *c = NULL;

        c = condition_new(CONDITION_PATH_EXISTS, "/tmp", false, false);
        assert_se(c);
        assert_se(c->type == CONDITION_PATH_EXISTS);
        assert_se(streq(c->parameter, "/tmp"));
        assert_se(!c->trigger);
        assert_se(!c->negate);

        c = condition_free(c);
        assert_se(!c);
}

TEST(condition_new_with_trigger_negate) {
        _cleanup_(condition_freep) Condition *c = NULL;

        c = condition_new(CONDITION_KERNEL_COMMAND_LINE, "foo=bar", true, true);
        assert_se(c);
        assert_se(c->type == CONDITION_KERNEL_COMMAND_LINE);
        assert_se(c->trigger);
        assert_se(c->negate);
}

TEST(condition_result_roundtrip) {
        for (int i = 0; i < _CONDITION_RESULT_MAX; i++) {
                const char *s = condition_result_to_string(i);
                assert_se(s);
                ConditionResult v = condition_result_from_string(s);
                assert_se(v == i);
        }
}

TEST(condition_type_to_string) {
        /* Verify some known types produce non-NULL strings */
        assert_se(condition_type_to_string(CONDITION_PATH_EXISTS));
        assert_se(condition_type_to_string(CONDITION_VIRTUALIZATION));
        assert_se(condition_type_to_string(CONDITION_ARCHITECTURE));
        assert_se(condition_type_to_string(CONDITION_HOST));
        assert_se(condition_type_to_string(CONDITION_FIRST_BOOT));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
