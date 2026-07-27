/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "string-util.h"
#include "tests.h"
#include "volatile-util.h"

TEST(volatile_mode_roundtrip) {
        assert_se(streq(volatile_mode_to_string(VOLATILE_NO), "no"));
        assert_se(streq(volatile_mode_to_string(VOLATILE_YES), "yes"));
        assert_se(streq(volatile_mode_to_string(VOLATILE_STATE), "state"));
        assert_se(streq(volatile_mode_to_string(VOLATILE_OVERLAY), "overlay"));

        assert_se(volatile_mode_from_string("no") == VOLATILE_NO);
        assert_se(volatile_mode_from_string("yes") == VOLATILE_YES);
        assert_se(volatile_mode_from_string("state") == VOLATILE_STATE);
        assert_se(volatile_mode_from_string("overlay") == VOLATILE_OVERLAY);

        /* WITH_BOOLEAN: accepts "true"/"false" */
        assert_se(volatile_mode_from_string("true") == VOLATILE_YES);
        assert_se(volatile_mode_from_string("false") == VOLATILE_NO);

        /* Invalid */
        assert_se(volatile_mode_from_string("invalid") == _VOLATILE_MODE_INVALID);
        assert_se(volatile_mode_from_string("") == _VOLATILE_MODE_INVALID);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
