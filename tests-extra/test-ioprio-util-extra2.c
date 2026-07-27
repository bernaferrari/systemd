/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "ioprio-util.h"
#include "string-util.h"
#include "tests.h"

TEST(ioprio_class_from_string) {
        assert_se(ioprio_class_from_string("none") == IOPRIO_CLASS_NONE);
        assert_se(ioprio_class_from_string("realtime") == IOPRIO_CLASS_RT);
        assert_se(ioprio_class_from_string("best-effort") == IOPRIO_CLASS_BE);
        assert_se(ioprio_class_from_string("idle") == IOPRIO_CLASS_IDLE);

        /* Numeric fallback (WITH_FALLBACK) */
        assert_se(ioprio_class_from_string("5") == 5);
}

TEST(ioprio_class_to_string_alloc) {
        _cleanup_free_ char *s = NULL;
        assert_se(ioprio_class_to_string_alloc(IOPRIO_CLASS_NONE, &s) >= 0);
        assert_se(streq(s, "none"));

        s = mfree(s);
        assert_se(ioprio_class_to_string_alloc(IOPRIO_CLASS_RT, &s) >= 0);
        assert_se(streq(s, "realtime"));

        s = mfree(s);
        assert_se(ioprio_class_to_string_alloc(IOPRIO_CLASS_BE, &s) >= 0);
        assert_se(streq(s, "best-effort"));

        s = mfree(s);
        assert_se(ioprio_class_to_string_alloc(IOPRIO_CLASS_IDLE, &s) >= 0);
        assert_se(streq(s, "idle"));

        /* Out of range → -ERANGE */
        s = mfree(s);
        assert_se(ioprio_class_to_string_alloc(10, &s) == -ERANGE);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
