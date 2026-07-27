/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "ioprio-util.h"
#include "tests.h"

TEST(ioprio_class_from_string) {
        ASSERT_EQ(ioprio_class_from_string("none"), IOPRIO_CLASS_NONE);
        ASSERT_EQ(ioprio_class_from_string("realtime"), IOPRIO_CLASS_RT);
        ASSERT_EQ(ioprio_class_from_string("best-effort"), IOPRIO_CLASS_BE);
        ASSERT_EQ(ioprio_class_from_string("idle"), IOPRIO_CLASS_IDLE);
        /* WITH_FALLBACK: numeric values are accepted */
        ASSERT_EQ(ioprio_class_from_string("0"), IOPRIO_CLASS_NONE);
        ASSERT_EQ(ioprio_class_from_string("2"), IOPRIO_CLASS_BE);
        /* Non-numeric invalid returns -EINVAL */
        ASSERT_EQ(ioprio_class_from_string("invalid"), -EINVAL);
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
        s = mfree(s);

        /* Fallback for unknown but within-range values uses numeric string */
        /* Values beyond fallback max return error */
        assert_se(ioprio_class_to_string_alloc(99, &s) < 0);
}

TEST(ioprio_class_is_valid) {
        assert_se(ioprio_class_is_valid(IOPRIO_CLASS_NONE));
        assert_se(ioprio_class_is_valid(IOPRIO_CLASS_RT));
        assert_se(ioprio_class_is_valid(IOPRIO_CLASS_BE));
        assert_se(ioprio_class_is_valid(IOPRIO_CLASS_IDLE));
        assert_se(!ioprio_class_is_valid(99));
        assert_se(!ioprio_class_is_valid(-1));
}

TEST(ioprio_priority_is_valid) {
        assert_se(ioprio_priority_is_valid(0));
        assert_se(ioprio_priority_is_valid(7));
        assert_se(!ioprio_priority_is_valid(-1));
        assert_se(!ioprio_priority_is_valid(8));
}

TEST(ioprio_parse_priority) {
        int val;

        assert_se(ioprio_parse_priority("0", &val) == 0);
        assert_se(val == 0);

        assert_se(ioprio_parse_priority("7", &val) == 0);
        assert_se(val == 7);

        assert_se(ioprio_parse_priority("-1", &val) == -EINVAL);
        assert_se(ioprio_parse_priority("8", &val) == -EINVAL);
        assert_se(ioprio_parse_priority("invalid", &val) < 0);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
