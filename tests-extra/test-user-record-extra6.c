/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "string-util.h"
#include "tests.h"
#include "user-record.h"

TEST(user_storage_to_from_string) {
        assert_se(streq(user_storage_to_string(USER_CLASSIC), "classic"));
        assert_se(streq(user_storage_to_string(USER_LUKS), "luks"));
        assert_se(streq(user_storage_to_string(USER_DIRECTORY), "directory"));
        assert_se(streq(user_storage_to_string(USER_SUBVOLUME), "subvolume"));
        assert_se(streq(user_storage_to_string(USER_FSCRYPT), "fscrypt"));
        assert_se(streq(user_storage_to_string(USER_CIFS), "cifs"));

        assert_se(user_storage_from_string("classic") == USER_CLASSIC);
        assert_se(user_storage_from_string("luks") == USER_LUKS);
        assert_se(user_storage_from_string("directory") == USER_DIRECTORY);
        assert_se(user_storage_from_string("subvolume") == USER_SUBVOLUME);
        assert_se(user_storage_from_string("fscrypt") == USER_FSCRYPT);
        assert_se(user_storage_from_string("cifs") == USER_CIFS);
        assert_se(user_storage_from_string("invalid") < 0);
}

TEST(user_disposition_to_from_string) {
        assert_se(streq(user_disposition_to_string(USER_INTRINSIC), "intrinsic"));
        assert_se(streq(user_disposition_to_string(USER_SYSTEM), "system"));
        assert_se(streq(user_disposition_to_string(USER_DYNAMIC), "dynamic"));
        assert_se(streq(user_disposition_to_string(USER_CONTAINER), "container"));
        assert_se(streq(user_disposition_to_string(USER_RESERVED), "reserved"));

        assert_se(user_disposition_from_string("intrinsic") == USER_INTRINSIC);
        assert_se(user_disposition_from_string("system") == USER_SYSTEM);
        assert_se(user_disposition_from_string("dynamic") == USER_DYNAMIC);
        assert_se(user_disposition_from_string("container") == USER_CONTAINER);
        assert_se(user_disposition_from_string("reserved") == USER_RESERVED);
        assert_se(user_disposition_from_string("invalid") < 0);
}

TEST(auto_resize_mode_to_from_string) {
        assert_se(streq(auto_resize_mode_to_string(AUTO_RESIZE_OFF), "off"));
        assert_se(streq(auto_resize_mode_to_string(AUTO_RESIZE_GROW), "grow"));
        assert_se(streq(auto_resize_mode_to_string(AUTO_RESIZE_SHRINK_AND_GROW), "shrink-and-grow"));

        assert_se(auto_resize_mode_from_string("off") == AUTO_RESIZE_OFF);
        assert_se(auto_resize_mode_from_string("grow") == AUTO_RESIZE_GROW);
        assert_se(auto_resize_mode_from_string("shrink-and-grow") == AUTO_RESIZE_SHRINK_AND_GROW);
        assert_se(auto_resize_mode_from_string("invalid") < 0);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
