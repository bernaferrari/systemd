/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "user-record.h"
#include "tests.h"

TEST(user_disposition) {
        ASSERT_STREQ(user_disposition_to_string(USER_INTRINSIC), "intrinsic");
        ASSERT_STREQ(user_disposition_to_string(USER_SYSTEM), "system");
        ASSERT_STREQ(user_disposition_to_string(USER_DYNAMIC), "dynamic");
        ASSERT_STREQ(user_disposition_to_string(USER_REGULAR), "regular");
        ASSERT_STREQ(user_disposition_to_string(USER_CONTAINER), "container");
        ASSERT_STREQ(user_disposition_to_string(USER_FOREIGN), "foreign");
        ASSERT_EQ(user_disposition_from_string("intrinsic"), USER_INTRINSIC);
        ASSERT_EQ(user_disposition_from_string("regular"), USER_REGULAR);
        ASSERT_EQ(user_disposition_from_string("invalid"), _USER_DISPOSITION_INVALID);
}

TEST(auto_resize_mode) {
        ASSERT_STREQ(auto_resize_mode_to_string(AUTO_RESIZE_OFF), "off");
        ASSERT_STREQ(auto_resize_mode_to_string(AUTO_RESIZE_GROW), "grow");
        ASSERT_STREQ(auto_resize_mode_to_string(AUTO_RESIZE_SHRINK_AND_GROW), "shrink-and-grow");
        ASSERT_EQ(auto_resize_mode_from_string("off"), AUTO_RESIZE_OFF);
        ASSERT_EQ(auto_resize_mode_from_string("grow"), AUTO_RESIZE_GROW);
        ASSERT_EQ(auto_resize_mode_from_string("invalid"), _AUTO_RESIZE_MODE_INVALID);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
