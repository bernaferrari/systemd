/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "xattr-util.h"
#include "tests.h"

TEST(xattr_is_acl_basic) {
        assert_se(xattr_is_acl("system.posix_acl_access"));
        assert_se(xattr_is_acl("system.posix_acl_default"));
        assert_se(!xattr_is_acl("user.foo"));
        assert_se(!xattr_is_acl("security.selinux"));
}

TEST(xattr_is_selinux_basic) {
        assert_se(xattr_is_selinux("security.selinux"));
        assert_se(!xattr_is_selinux("security.capability"));
        assert_se(!xattr_is_selinux("user.foo"));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
