/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "user-record.h"
#include "tests.h"

TEST(user_storage_to_from_string) {
        ASSERT_STREQ(user_storage_to_string(USER_CLASSIC), "classic");
        ASSERT_STREQ(user_storage_to_string(USER_LUKS), "luks");
        ASSERT_STREQ(user_storage_to_string(USER_DIRECTORY), "directory");
        ASSERT_STREQ(user_storage_to_string(USER_SUBVOLUME), "subvolume");
        ASSERT_STREQ(user_storage_to_string(USER_FSCRYPT), "fscrypt");
        ASSERT_STREQ(user_storage_to_string(USER_CIFS), "cifs");

        ASSERT_EQ(user_storage_from_string("classic"), USER_CLASSIC);
        ASSERT_EQ(user_storage_from_string("luks"), USER_LUKS);
        ASSERT_EQ(user_storage_from_string("directory"), USER_DIRECTORY);
        ASSERT_EQ(user_storage_from_string("subvolume"), USER_SUBVOLUME);
        ASSERT_EQ(user_storage_from_string("fscrypt"), USER_FSCRYPT);
        ASSERT_EQ(user_storage_from_string("cifs"), USER_CIFS);
        ASSERT_EQ(user_storage_from_string("invalid"), _USER_STORAGE_INVALID);
}

TEST(user_disposition_to_from_string) {
        ASSERT_STREQ(user_disposition_to_string(USER_INTRINSIC), "intrinsic");
        ASSERT_STREQ(user_disposition_to_string(USER_SYSTEM), "system");
        ASSERT_STREQ(user_disposition_to_string(USER_DYNAMIC), "dynamic");
        ASSERT_STREQ(user_disposition_to_string(USER_REGULAR), "regular");
        ASSERT_STREQ(user_disposition_to_string(USER_CONTAINER), "container");

        ASSERT_EQ(user_disposition_from_string("intrinsic"), USER_INTRINSIC);
        ASSERT_EQ(user_disposition_from_string("system"), USER_SYSTEM);
        ASSERT_EQ(user_disposition_from_string("dynamic"), USER_DYNAMIC);
        ASSERT_EQ(user_disposition_from_string("regular"), USER_REGULAR);
        ASSERT_EQ(user_disposition_from_string("container"), USER_CONTAINER);
        ASSERT_EQ(user_disposition_from_string("invalid"), _USER_DISPOSITION_INVALID);
}

TEST(auto_resize_mode_to_from_string) {
        ASSERT_STREQ(auto_resize_mode_to_string(AUTO_RESIZE_OFF), "off");
        ASSERT_STREQ(auto_resize_mode_to_string(AUTO_RESIZE_GROW), "grow");
        ASSERT_STREQ(auto_resize_mode_to_string(AUTO_RESIZE_SHRINK_AND_GROW), "shrink-and-grow");

        ASSERT_EQ(auto_resize_mode_from_string("off"), AUTO_RESIZE_OFF);
        ASSERT_EQ(auto_resize_mode_from_string("grow"), AUTO_RESIZE_GROW);
        ASSERT_EQ(auto_resize_mode_from_string("shrink-and-grow"), AUTO_RESIZE_SHRINK_AND_GROW);
        ASSERT_EQ(auto_resize_mode_from_string("invalid"), _AUTO_RESIZE_MODE_INVALID);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
