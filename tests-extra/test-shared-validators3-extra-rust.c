/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Shadow test: string table lookups from user-record.c */

#include <assert.h>
#include <errno.h>
#include "tests.h"
#include "user-record.h"

/* Rust FFI declarations */
const char* rs_user_storage_to_string(int d);
int rs_user_storage_from_string(const char *s);
const char* rs_user_disposition_to_string(int d);
int rs_user_disposition_from_string(const char *s);

static void test_user_storage(void) {
        assert_se(streq_ptr(rs_user_storage_to_string(USER_CLASSIC), user_storage_to_string(USER_CLASSIC)));
        assert_se(streq_ptr(rs_user_storage_to_string(USER_LUKS), user_storage_to_string(USER_LUKS)));
        assert_se(streq_ptr(rs_user_storage_to_string(USER_DIRECTORY), user_storage_to_string(USER_DIRECTORY)));
        assert_se(streq_ptr(rs_user_storage_to_string(USER_SUBVOLUME), user_storage_to_string(USER_SUBVOLUME)));
        assert_se(streq_ptr(rs_user_storage_to_string(USER_FSCRYPT), user_storage_to_string(USER_FSCRYPT)));
        assert_se(streq_ptr(rs_user_storage_to_string(USER_CIFS), user_storage_to_string(USER_CIFS)));
        assert_se(streq_ptr(rs_user_storage_to_string(_USER_STORAGE_MAX), user_storage_to_string(_USER_STORAGE_MAX)));
        assert_se(streq_ptr(rs_user_storage_to_string(-1), user_storage_to_string(-1)));

        assert_se(rs_user_storage_from_string("classic") == user_storage_from_string("classic"));
        assert_se(rs_user_storage_from_string("luks") == user_storage_from_string("luks"));
        assert_se(rs_user_storage_from_string("directory") == user_storage_from_string("directory"));
        assert_se(rs_user_storage_from_string("subvolume") == user_storage_from_string("subvolume"));
        assert_se(rs_user_storage_from_string("fscrypt") == user_storage_from_string("fscrypt"));
        assert_se(rs_user_storage_from_string("cifs") == user_storage_from_string("cifs"));
        assert_se(rs_user_storage_from_string("bogus") == user_storage_from_string("bogus"));
        assert_se(rs_user_storage_from_string(NULL) == user_storage_from_string(NULL));
}

static void test_user_disposition(void) {
        assert_se(streq_ptr(rs_user_disposition_to_string(USER_INTRINSIC), user_disposition_to_string(USER_INTRINSIC)));
        assert_se(streq_ptr(rs_user_disposition_to_string(USER_SYSTEM), user_disposition_to_string(USER_SYSTEM)));
        assert_se(streq_ptr(rs_user_disposition_to_string(USER_DYNAMIC), user_disposition_to_string(USER_DYNAMIC)));
        assert_se(streq_ptr(rs_user_disposition_to_string(USER_REGULAR), user_disposition_to_string(USER_REGULAR)));
        assert_se(streq_ptr(rs_user_disposition_to_string(USER_CONTAINER), user_disposition_to_string(USER_CONTAINER)));
        assert_se(streq_ptr(rs_user_disposition_to_string(USER_FOREIGN), user_disposition_to_string(USER_FOREIGN)));
        assert_se(streq_ptr(rs_user_disposition_to_string(USER_RESERVED), user_disposition_to_string(USER_RESERVED)));
        assert_se(streq_ptr(rs_user_disposition_to_string(-1), user_disposition_to_string(-1)));

        assert_se(rs_user_disposition_from_string("intrinsic") == user_disposition_from_string("intrinsic"));
        assert_se(rs_user_disposition_from_string("system") == user_disposition_from_string("system"));
        assert_se(rs_user_disposition_from_string("dynamic") == user_disposition_from_string("dynamic"));
        assert_se(rs_user_disposition_from_string("regular") == user_disposition_from_string("regular"));
        assert_se(rs_user_disposition_from_string("container") == user_disposition_from_string("container"));
        assert_se(rs_user_disposition_from_string("foreign") == user_disposition_from_string("foreign"));
        assert_se(rs_user_disposition_from_string("reserved") == user_disposition_from_string("reserved"));
        assert_se(rs_user_disposition_from_string("bogus") == user_disposition_from_string("bogus"));
        assert_se(rs_user_disposition_from_string(NULL) == user_disposition_from_string(NULL));
}

int main(int argc, char **argv) {
        test_user_storage();
        test_user_disposition();
        return 0;
}
