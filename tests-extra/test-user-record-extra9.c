/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "string-util.h"
#include "tests.h"
#include "user-record.h"

TEST(user_record_require) {
        /* Single mask bit */
        assert_se(USER_RECORD_REQUIRE(USER_RECORD_REGULAR) == USER_RECORD_REQUIRE_REGULAR);
        assert_se(USER_RECORD_REQUIRE(USER_RECORD_SECRET) == USER_RECORD_REQUIRE_SECRET);
        assert_se(USER_RECORD_REQUIRE(USER_RECORD_PRIVILEGED) == USER_RECORD_REQUIRE_PRIVILEGED);

        /* Multiple mask bits */
        assert_se(USER_RECORD_REQUIRE(USER_RECORD_REGULAR | USER_RECORD_SECRET) ==
                  (USER_RECORD_REQUIRE_REGULAR | USER_RECORD_REQUIRE_SECRET));
}

TEST(user_record_allow) {
        assert_se(USER_RECORD_ALLOW(USER_RECORD_REGULAR) == USER_RECORD_ALLOW_REGULAR);
        assert_se(USER_RECORD_ALLOW(USER_RECORD_SECRET) == USER_RECORD_ALLOW_SECRET);
        assert_se(USER_RECORD_ALLOW(USER_RECORD_PRIVILEGED | USER_RECORD_PER_MACHINE) ==
                  (USER_RECORD_ALLOW_PRIVILEGED | USER_RECORD_ALLOW_PER_MACHINE));
}

TEST(user_record_strip) {
        assert_se(USER_RECORD_STRIP(USER_RECORD_REGULAR) == USER_RECORD_STRIP_REGULAR);
        assert_se(USER_RECORD_STRIP(USER_RECORD_SECRET) == USER_RECORD_STRIP_SECRET);
        assert_se(USER_RECORD_STRIP(USER_RECORD_BINDING | USER_RECORD_STATUS) ==
                  (USER_RECORD_STRIP_BINDING | USER_RECORD_STRIP_STATUS));
}

TEST(user_record_require_mask) {
        UserRecordLoadFlags f = USER_RECORD_REQUIRE_REGULAR | USER_RECORD_REQUIRE_SECRET;
        assert_se(USER_RECORD_REQUIRE_MASK(f) == (USER_RECORD_REGULAR | USER_RECORD_SECRET));

        f = USER_RECORD_ALLOW_REGULAR;
        assert_se(USER_RECORD_REQUIRE_MASK(f) == 0);
}

TEST(user_record_allow_mask) {
        /* Allow mask includes require mask */
        UserRecordLoadFlags f = USER_RECORD_REQUIRE_REGULAR | USER_RECORD_ALLOW_SECRET;
        UserRecordMask m = USER_RECORD_ALLOW_MASK(f);
        assert_se(m & USER_RECORD_REGULAR);
        assert_se(m & USER_RECORD_SECRET);

        /* Only require, no extra allow */
        f = USER_RECORD_REQUIRE_REGULAR;
        m = USER_RECORD_ALLOW_MASK(f);
        assert_se(m & USER_RECORD_REGULAR);
        assert_se(!(m & USER_RECORD_SECRET));
}

TEST(user_record_strip_mask) {
        UserRecordLoadFlags f = USER_RECORD_STRIP_SECRET | USER_RECORD_STRIP_BINDING;
        assert_se(USER_RECORD_STRIP_MASK(f) == (USER_RECORD_SECRET | USER_RECORD_BINDING));

        f = USER_RECORD_REQUIRE_REGULAR;
        assert_se(USER_RECORD_STRIP_MASK(f) == 0);
}

TEST(user_record_mask_roundtrip) {
        /* Require roundtrip */
        UserRecordMask mask = USER_RECORD_REGULAR | USER_RECORD_SECRET | USER_RECORD_PRIVILEGED;
        UserRecordLoadFlags flags = USER_RECORD_REQUIRE(mask);
        assert_se(USER_RECORD_REQUIRE_MASK(flags) == mask);

        /* Strip roundtrip */
        flags = USER_RECORD_STRIP(mask);
        assert_se(USER_RECORD_STRIP_MASK(flags) == mask);

        /* Full roundtrip through all three */
        UserRecordMask req = USER_RECORD_REGULAR;
        UserRecordMask allow = USER_RECORD_SECRET | USER_RECORD_PRIVILEGED;
        UserRecordMask strip = USER_RECORD_BINDING;
        flags = USER_RECORD_REQUIRE(req) | USER_RECORD_ALLOW(allow) | USER_RECORD_STRIP(strip);

        assert_se(USER_RECORD_REQUIRE_MASK(flags) == req);
        assert_se(USER_RECORD_STRIP_MASK(flags) == strip);
}

TEST(user_record_load_full) {
        /* USER_RECORD_LOAD_FULL should require REGULAR and allow everything else */
        assert_se(USER_RECORD_REQUIRE_MASK(USER_RECORD_LOAD_FULL) == USER_RECORD_REGULAR);

        UserRecordMask allow = USER_RECORD_ALLOW_MASK(USER_RECORD_LOAD_FULL);
        assert_se(allow & USER_RECORD_SECRET);
        assert_se(allow & USER_RECORD_PRIVILEGED);
        assert_se(allow & USER_RECORD_PER_MACHINE);
        assert_se(allow & USER_RECORD_BINDING);
        assert_se(allow & USER_RECORD_STATUS);
        assert_se(allow & USER_RECORD_SIGNATURE);
        assert_se(allow & USER_RECORD_REGULAR);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
