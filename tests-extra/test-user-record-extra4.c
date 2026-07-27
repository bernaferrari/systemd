/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "tests.h"
#include "user-record.h"

TEST(user_storage_roundtrip) {
        for (int i = 0; i < _USER_STORAGE_MAX; i++) {
                const char *s = user_storage_to_string(i);
                assert_se(s);
                UserStorage v = user_storage_from_string(s);
                assert_se(v == i);
        }
}

TEST(user_disposition_roundtrip) {
        for (int i = 0; i < _USER_DISPOSITION_MAX; i++) {
                const char *s = user_disposition_to_string(i);
                assert_se(s);
                UserDisposition v = user_disposition_from_string(s);
                assert_se(v == i);
        }
}

TEST(auto_resize_mode_roundtrip) {
        for (int i = 0; i < _AUTO_RESIZE_MODE_MAX; i++) {
                const char *s = auto_resize_mode_to_string(i);
                assert_se(s);
                AutoResizeMode v = auto_resize_mode_from_string(s);
                assert_se(v == i);
        }
}

TEST(user_storage_from_string_invalid) {
        assert_se(user_storage_from_string("nonsense") == _USER_STORAGE_INVALID);
        assert_se(user_storage_from_string("") == _USER_STORAGE_INVALID);
}

TEST(user_disposition_from_string_invalid) {
        assert_se(user_disposition_from_string("nonsense") == _USER_DISPOSITION_INVALID);
        assert_se(user_disposition_from_string("") == _USER_DISPOSITION_INVALID);
}

TEST(auto_resize_mode_from_string_invalid) {
        assert_se(auto_resize_mode_from_string("nonsense") == _AUTO_RESIZE_MODE_INVALID);
        assert_se(auto_resize_mode_from_string("") == _AUTO_RESIZE_MODE_INVALID);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
