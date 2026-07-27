/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sched.h>

#include "process-util.h"
#include "string-util.h"
#include "tests.h"

TEST(sched_policy_from_string) {
        assert_se(sched_policy_from_string("other") == SCHED_OTHER);
        assert_se(sched_policy_from_string("batch") == SCHED_BATCH);
        assert_se(sched_policy_from_string("idle") == SCHED_IDLE);
        assert_se(sched_policy_from_string("fifo") == SCHED_FIFO);
        assert_se(sched_policy_from_string("rr") == SCHED_RR);

        /* WITH_FALLBACK: numeric strings accepted */
        assert_se(sched_policy_from_string("0") == 0);
        assert_se(sched_policy_from_string("1") == 1);
}

TEST(sched_policy_to_string_alloc) {
        _cleanup_free_ char *s = NULL;

        assert_se(sched_policy_to_string_alloc(SCHED_OTHER, &s) == 0);
        assert_se(streq(s, "other"));

        s = mfree(s);
        assert_se(sched_policy_to_string_alloc(SCHED_BATCH, &s) == 0);
        assert_se(streq(s, "batch"));

        s = mfree(s);
        assert_se(sched_policy_to_string_alloc(SCHED_IDLE, &s) == 0);
        assert_se(streq(s, "idle"));

        s = mfree(s);
        assert_se(sched_policy_to_string_alloc(SCHED_FIFO, &s) == 0);
        assert_se(streq(s, "fifo"));

        s = mfree(s);
        assert_se(sched_policy_to_string_alloc(SCHED_RR, &s) == 0);
        assert_se(streq(s, "rr"));

        /* Fallback: numeric value not in table */
        s = mfree(s);
        assert_se(sched_policy_to_string_alloc(99, &s) == 0);
        assert_se(streq(s, "99"));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
