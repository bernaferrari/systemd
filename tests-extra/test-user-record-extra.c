/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "user-record.h"
#include "tests.h"

TEST(user_disposition_to_string) {
        ASSERT_STREQ(user_disposition_to_string(USER_INTRINSIC), "intrinsic");
        ASSERT_STREQ(user_disposition_to_string(USER_SYSTEM), "system");
        ASSERT_STREQ(user_disposition_to_string(USER_DYNAMIC), "dynamic");
        ASSERT_STREQ(user_disposition_to_string(USER_REGULAR), "regular");
        ASSERT_STREQ(user_disposition_to_string(USER_CONTAINER), "container");
        ASSERT_STREQ(user_disposition_to_string(USER_FOREIGN), "foreign");
        ASSERT_STREQ(user_disposition_to_string(USER_RESERVED), "reserved");
}

TEST(user_disposition_from_string) {
        ASSERT_EQ(user_disposition_from_string("intrinsic"), USER_INTRINSIC);
        ASSERT_EQ(user_disposition_from_string("system"), USER_SYSTEM);
        ASSERT_EQ(user_disposition_from_string("dynamic"), USER_DYNAMIC);
        ASSERT_EQ(user_disposition_from_string("regular"), USER_REGULAR);
        ASSERT_EQ(user_disposition_from_string("container"), USER_CONTAINER);
        ASSERT_EQ(user_disposition_from_string("foreign"), USER_FOREIGN);
        ASSERT_EQ(user_disposition_from_string("reserved"), USER_RESERVED);
        ASSERT_EQ(user_disposition_from_string("invalid"), _USER_DISPOSITION_INVALID);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
