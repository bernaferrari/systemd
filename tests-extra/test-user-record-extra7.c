/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "string-util.h"
#include "tests.h"
#include "user-record.h"

TEST(user_record_build_image_path_luks) {
        _cleanup_free_ char *path = NULL;
        int r;

        r = user_record_build_image_path(USER_LUKS, "testuser", &path);
        assert_se(r > 0);
        assert_se(endswith(path, "/testuser.home"));
        assert_se(startswith(path, "/home/"));
}

TEST(user_record_build_image_path_directory) {
        _cleanup_free_ char *path = NULL;
        int r;

        r = user_record_build_image_path(USER_DIRECTORY, "testuser", &path);
        assert_se(r > 0);
        assert_se(endswith(path, "/testuser.homedir"));
}

TEST(user_record_build_image_path_subvolume) {
        _cleanup_free_ char *path = NULL;
        int r;

        r = user_record_build_image_path(USER_SUBVOLUME, "testuser", &path);
        assert_se(r > 0);
        assert_se(endswith(path, "/testuser.homedir"));
}

TEST(user_record_build_image_path_fscrypt) {
        _cleanup_free_ char *path = NULL;
        int r;

        r = user_record_build_image_path(USER_FSCRYPT, "testuser", &path);
        assert_se(r > 0);
        assert_se(endswith(path, "/testuser.homedir"));
}

TEST(user_record_build_image_path_classic) {
        _cleanup_free_ char *path = NULL;
        int r;

        /* Classic storage → returns 0 with NULL */
        r = user_record_build_image_path(USER_CLASSIC, "testuser", &path);
        assert_se(r == 0);
        assert_se(path == NULL);
}

TEST(user_record_build_image_path_with_realm) {
        _cleanup_free_ char *path = NULL;
        int r;

        r = user_record_build_image_path(USER_LUKS, "user@realm", &path);
        assert_se(r > 0);
        assert_se(endswith(path, "/user@realm.home"));
}

TEST(user_record_new_unref) {
        _cleanup_(user_record_unrefp) UserRecord *u = NULL;

        u = user_record_new();
        assert_se(u);
        assert_se(u->n_ref == 1);
}

TEST(user_record_ref_unref) {
        UserRecord *u = user_record_new();
        assert_se(u);

        UserRecord *u2 = user_record_ref(u);
        assert_se(u2 == u);
        assert_se(u->n_ref == 2);

        user_record_unref(u);
        assert_se(u->n_ref == 1);
        user_record_unref(u);
}

TEST(user_record_unref_null) {
        user_record_unref(NULL);
}

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

DEFINE_TEST_MAIN(LOG_DEBUG);
