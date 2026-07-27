/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdint.h>

#include "uid-classification.h"
#include "user-util.h"
#include "tests.h"

TEST(uid_is_valid_basic) {
        assert_se(uid_is_valid(0));
        assert_se(uid_is_valid(1000));
        assert_se(uid_is_valid(65534));
        assert_se(!uid_is_valid(UINT32_C(0xFFFFFFFF)));
        assert_se(!uid_is_valid(UINT32_C(0xFFFF)));
}

TEST(gid_is_valid_basic) {
        assert_se(gid_is_valid(0));
        assert_se(gid_is_valid(100));
        assert_se(!gid_is_valid(UINT32_C(0xFFFFFFFF)));
}

TEST(parse_uid_basic) {
        uid_t uid;

        assert_se(parse_uid("0", &uid) == 0);
        assert_se(uid == 0);

        assert_se(parse_uid("1000", &uid) == 0);
        assert_se(uid == 1000);

        assert_se(parse_uid("65534", &uid) == 0);
        assert_se(uid == 65534);
}

TEST(parse_uid_invalid) {
        uid_t uid;

        assert_se(parse_uid("", &uid) < 0);
        assert_se(parse_uid("-1", &uid) < 0);
        assert_se(parse_uid("+1", &uid) < 0);
        assert_se(parse_uid("abc", &uid) < 0);
        assert_se(parse_uid("4294967295", &uid) < 0);  /* 0xFFFFFFFF */
}

TEST(parse_uid_range_basic) {
        uid_t lower, upper;

        assert_se(parse_uid_range("1000", &lower, &upper) == 0);
        assert_se(lower == 1000);
        assert_se(upper == 1000);

        assert_se(parse_uid_range("1000-2000", &lower, &upper) == 0);
        assert_se(lower == 1000);
        assert_se(upper == 2000);
}

TEST(parse_uid_range_invalid) {
        uid_t lower, upper;

        assert_se(parse_uid_range("abc", &lower, &upper) < 0);
        assert_se(parse_uid_range("1000-abc", &lower, &upper) < 0);
        assert_se(parse_uid_range("", &lower, &upper) < 0);
}

TEST(parse_gid_basic) {
        gid_t gid;

        assert_se(parse_gid("100", &gid) == 0);
        assert_se(gid == 100);
}

TEST(uid_is_system_basic) {
        /* UID 0 (root) is system */
        assert_se(uid_is_system(0));
        assert_se(uid_is_system(100));
        /* High UIDs are not system */
        assert_se(!uid_is_system(UINT32_C(0xFFFF0000)));
}

TEST(gid_is_system_basic) {
        assert_se(gid_is_system(0));
        assert_se(gid_is_system(100));
        assert_se(!gid_is_system(UINT32_C(0xFFFF0000)));
}

TEST(uid_is_dynamic_basic) {
        /* Dynamic UIDs: range DYNAMIC_UID_MIN..DYNAMIC_UID_MAX (61184..65519) */
        assert_se(!uid_is_dynamic(0));
        assert_se(!uid_is_dynamic(1000));
        assert_se(uid_is_dynamic(61184));
        assert_se(uid_is_dynamic(65519));
        assert_se(!uid_is_dynamic(65520));
}

TEST(uid_is_container_basic) {
        assert_se(!uid_is_container(0));
        assert_se(!uid_is_container(1000));
        /* Container UIDs start from CONTAINER_UID_BASE_MIN */
        assert_se(uid_is_container(524288));
}

TEST(uid_is_foreign_basic) {
        assert_se(!uid_is_foreign(0));
        assert_se(!uid_is_foreign(1000));
        /* Foreign UIDs start from FOREIGN_UID_BASE */
        assert_se(uid_is_foreign(2147352576U));
}

TEST(is_nologin_shell_basic) {
        assert_se(is_nologin_shell("/bin/nologin"));
        assert_se(is_nologin_shell("/sbin/nologin"));
        assert_se(is_nologin_shell("/usr/bin/nologin"));
        assert_se(is_nologin_shell("/bin/false"));
        assert_se(is_nologin_shell("/bin/true"));
        assert_se(!is_nologin_shell("/bin/bash"));
        assert_se(!is_nologin_shell("/bin/zsh"));
}

TEST(shell_is_placeholder_basic) {
        assert_se(shell_is_placeholder(NULL));
        assert_se(shell_is_placeholder(""));
        assert_se(shell_is_placeholder("/bin/nologin"));
        assert_se(!shell_is_placeholder("/bin/bash"));
}

TEST(valid_user_group_name_basic) {
        assert_se(valid_user_group_name("root", 0));
        assert_se(valid_user_group_name("nobody", 0));
        assert_se(valid_user_group_name("test-user", 0));
        assert_se(valid_user_group_name("user123", 0));
        assert_se(!valid_user_group_name("", 0));
        assert_se(!valid_user_group_name("-bad", 0));
        assert_se(!valid_user_group_name("a$b", 0));
}

TEST(valid_gecos_basic) {
        assert_se(valid_gecos("Test User"));
        assert_se(valid_gecos("John Doe"));
        assert_se(valid_gecos(""));           /* empty is valid */
        assert_se(!valid_gecos("bad:value")); /* colon not allowed */
}

DEFINE_TEST_MAIN(LOG_DEBUG);
