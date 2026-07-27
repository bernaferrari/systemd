/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "user-record.h"
#include "tests.h"

TEST(user_storage_to_string) {
        ASSERT_STREQ(user_storage_to_string(USER_CLASSIC), "classic");
        ASSERT_STREQ(user_storage_to_string(USER_LUKS), "luks");
        ASSERT_STREQ(user_storage_to_string(USER_DIRECTORY), "directory");
        ASSERT_STREQ(user_storage_to_string(USER_SUBVOLUME), "subvolume");
        ASSERT_STREQ(user_storage_to_string(USER_FSCRYPT), "fscrypt");
        ASSERT_STREQ(user_storage_to_string(USER_CIFS), "cifs");
}

TEST(user_storage_from_string) {
        ASSERT_EQ(user_storage_from_string("classic"), USER_CLASSIC);
        ASSERT_EQ(user_storage_from_string("luks"), USER_LUKS);
        ASSERT_EQ(user_storage_from_string("directory"), USER_DIRECTORY);
        ASSERT_EQ(user_storage_from_string("subvolume"), USER_SUBVOLUME);
        ASSERT_EQ(user_storage_from_string("fscrypt"), USER_FSCRYPT);
        ASSERT_EQ(user_storage_from_string("cifs"), USER_CIFS);
        ASSERT_EQ(user_storage_from_string("invalid"), _USER_STORAGE_INVALID);
}

TEST(auto_resize_mode_to_string) {
        ASSERT_STREQ(auto_resize_mode_to_string(AUTO_RESIZE_OFF), "off");
        ASSERT_STREQ(auto_resize_mode_to_string(AUTO_RESIZE_GROW), "grow");
        ASSERT_STREQ(auto_resize_mode_to_string(AUTO_RESIZE_SHRINK_AND_GROW), "shrink-and-grow");
}

TEST(auto_resize_mode_from_string) {
        ASSERT_EQ(auto_resize_mode_from_string("off"), AUTO_RESIZE_OFF);
        ASSERT_EQ(auto_resize_mode_from_string("grow"), AUTO_RESIZE_GROW);
        ASSERT_EQ(auto_resize_mode_from_string("shrink-and-grow"), AUTO_RESIZE_SHRINK_AND_GROW);
        ASSERT_EQ(auto_resize_mode_from_string("invalid"), _AUTO_RESIZE_MODE_INVALID);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
