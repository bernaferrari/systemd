/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "calendarspec.h"
#include "tests.h"

TEST(calendar_spec_from_string_basic) {
        _cleanup_(calendar_spec_freep) CalendarSpec *c = NULL;

        assert_se(calendar_spec_from_string("hourly", &c) >= 0);
        assert_se(calendar_spec_valid(c));
        c = calendar_spec_free(c);

        assert_se(calendar_spec_from_string("daily", &c) >= 0);
        assert_se(calendar_spec_valid(c));
        c = calendar_spec_free(c);

        assert_se(calendar_spec_from_string("weekly", &c) >= 0);
        assert_se(calendar_spec_valid(c));
        c = calendar_spec_free(c);

        assert_se(calendar_spec_from_string("monthly", &c) >= 0);
        assert_se(calendar_spec_valid(c));
        c = calendar_spec_free(c);

        assert_se(calendar_spec_from_string("yearly", &c) >= 0);
        assert_se(calendar_spec_valid(c));
        c = calendar_spec_free(c);

        /* Specific time */
        assert_se(calendar_spec_from_string("*:*:*", &c) >= 0);
        assert_se(calendar_spec_valid(c));
        c = calendar_spec_free(c);

        assert_se(calendar_spec_from_string("12:34", &c) >= 0);
        assert_se(calendar_spec_valid(c));
        c = calendar_spec_free(c);

        /* Invalid */
        assert_se(calendar_spec_from_string("invalid calendar", &c) < 0);
}

TEST(calendar_spec_to_string_roundtrip) {
        _cleanup_(calendar_spec_freep) CalendarSpec *c = NULL;
        _cleanup_free_ char *s = NULL;

        assert_se(calendar_spec_from_string("hourly", &c) >= 0);
        assert_se(calendar_spec_to_string(c, &s) >= 0);
        assert_se(s);
        c = calendar_spec_free(c);
        s = mfree(s);

        assert_se(calendar_spec_from_string("Mon *-*-* 00:00:00", &c) >= 0);
        assert_se(calendar_spec_to_string(c, &s) >= 0);
        assert_se(s);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
