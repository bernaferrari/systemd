/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "xattr-util.h"
#include "tests.h"

TEST(xattr_is_acl) {
        ASSERT_TRUE(xattr_is_acl("system.posix_acl_access"));
        ASSERT_TRUE(xattr_is_acl("system.posix_acl_default"));
        ASSERT_FALSE(xattr_is_acl("user.data"));
        ASSERT_FALSE(xattr_is_acl("security.capability"));
        ASSERT_FALSE(xattr_is_acl(""));
}

TEST(xattr_is_selinux) {
        ASSERT_TRUE(xattr_is_selinux("security.selinux"));
        ASSERT_FALSE(xattr_is_selinux("user.data"));
        ASSERT_FALSE(xattr_is_selinux("system.posix_acl_access"));
        ASSERT_FALSE(xattr_is_selinux(""));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
