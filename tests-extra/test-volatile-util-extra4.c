/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "string-util.h"
#include "tests.h"
#include "volatile-util.h"

TEST(volatile_mode_roundtrip_all) {
        for (VolatileMode m = 0; m < _VOLATILE_MODE_MAX; m++) {
                const char *s = volatile_mode_to_string(m);
                assert_se(s != NULL);
                assert_se(volatile_mode_from_string(s) == m);
        }
}

TEST(volatile_mode_invalid_values) {
        assert_se(volatile_mode_to_string(_VOLATILE_MODE_MAX) == NULL);
        assert_se(volatile_mode_to_string(_VOLATILE_MODE_INVALID) == NULL);
        assert_se(volatile_mode_from_string("") == _VOLATILE_MODE_INVALID);
        assert_se(volatile_mode_from_string("bogus") == _VOLATILE_MODE_INVALID);
        assert_se(volatile_mode_from_string("random") == _VOLATILE_MODE_INVALID);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
